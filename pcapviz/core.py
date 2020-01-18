
"""
ross lazarus december 2019 
forked from mateuszk87/PcapViz
changed geoIP lookup to use maxminddb
added reverse DNS lookup and cache with host names added to node labels
added CL parameters to adjust image layout and shapes
"""


from collections import OrderedDict

import networkx
import itertools
from networkx import DiGraph

from scapy.layers.inet import TCP, IP, UDP
from scapy.all import *
from scapy.layers.http import *
import logging

import os
import socket
import maxminddb


class GraphManager(object):
	""" Generates and processes the graph based on packets
	"""

	def __init__(self, packets, layer=3, args=None):
		self.graph = DiGraph()
		self.layer = layer
		self.geo_ip = None
		self.args = args
		self.data = {}
		self.deeNS = {} # cache for reverse lookups
		self.title = 'Title goes here'
		try:
			self.geo_ip = maxminddb.open_database(self.args.geopath) # command line -G
		except:
			logging.warning("could not load GeoIP data from supplied parameter geopath %s" % self.args.geopath)
		if self.args.DEBUG:
			macs = {}
			macips = {}
			for packet in packets:
				macs.setdefault(packet[0].src,[0,''])
				macs[packet[0].src][0] += 1
				macs.setdefault(packet[0].dst,[0,''])
				macs[packet[0].dst][0] += 1
				if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
					ip = packet[1].src
					macs[packet[0].src][1] = ip
			print('# mac\tip\tpackets\n%s' % '\n'.join(['%s\t%s\t%d\n' % (x,macs[x][1],macs[x][0]) for x in macs.keys()]))
		if self.args.restrict:
			packetsr = [x for x in packets if ((x[0].src in self.args.restrict) or (x[0].dst in self.args.restrict))]
			if len(packetsr) == 0:
				print('### warning - no packets left after filtering on %s - nothing to plot' % self.args.restrict)
				return
			else:
				if self.args.DEBUG:
					print('%d packets filtered with restrict = ' % (len(packets) - len(packetsr)),self.args.restrict)
				packets = packetsr
		if self.layer == 2:
			edges = map(self._layer_2_edge, packets)
		elif self.layer == 3:
			edges = map(self._layer_3_edge, packets)
		elif self.layer == 4:
			edges = map(self._layer_4_edge, packets)
		else:
			raise ValueError("Other layers than 2,3 and 4 are not supported yet!")

		for src, dst, packet in filter(lambda x: not (x is None), edges):
			if src in self.graph and dst in self.graph[src]:
				self.graph[src][dst]['packets'].append(packet)
			else:
				self.graph.add_edge(src, dst)
				self.graph[src][dst]['packets'] = [packet]

		for node in self.graph.nodes():
			self._retrieve_node_info(node)

		for src, dst in self.graph.edges():
			self._retrieve_edge_info(src, dst)

	def lookup(self,ip):
		"""deeNS caches all slow! fqdn reverse dns lookups from ip"""
		kname = self.deeNS.get(ip,None)
		if kname == None:
			kname = socket.getfqdn(ip) 
			self.deeNS[ip] = kname
		return (kname)


	def get_in_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.in_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def get_out_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.out_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def _sorted_results(self,unsorted_degrees, print_stdout):
		sorted_degrees = OrderedDict(sorted(list(unsorted_degrees), key=lambda t: t[1], reverse=True))
		for i in sorted_degrees:
			if print_stdout:
				nn = self.lookup(i)
				if (nn == i):
					print(sorted_degrees[i], i)
				else:
					print(sorted_degrees[i],i,nn)
		return sorted_degrees

	def _retrieve_node_info(self, node):
		self.data[node] = {}
		city = None
		country = None
		if self.layer >= 3 and self.geo_ip:
			if self.layer == 3:
				self.data[node]['ip'] = node
			elif self.layer == 4:
				self.data[node]['ip'] = node.split(':')[0]
			node_ip = self.data[node]['ip']
			try:
				mmdbrec = self.geo_ip.get(node_ip)
				if mmdbrec != None:
					countryrec = mmdbrec.get('city',None)
					cityrec = mmdbrec.get('country',None)
					if countryrec: # some records have one but not the other....
						country = countryrec['names'].get(self.args.geolang,None)
					if cityrec:
						city =  cityrec['names'].get(self.args.geolang,None)
				self.data[node]['country'] = country if country else 'private'
				self.data[node]['city'] = city if city else 'private'
			except:
				logging.debug("could not load GeoIP data for node %s" % node_ip)
				# no lookup so not much data available
				#del self.data[node]
				
		#TODO layer 2 info?


	def _retrieve_edge_info(self, src, dst):
		edge = self.graph[src][dst]
		if edge:
			packets = edge['packets']
			edge['layers'] = set(list(itertools.chain(*[set(GraphManager.get_layers(p)) for p in packets])))
			edge['transmitted'] = sum(len(p) for p in packets)
			edge['connections'] = len(packets)

	@staticmethod
	def get_layers(packet):
		return list(GraphManager.expand(packet))

	@staticmethod
	def expand(x):
		yield x.name
		while x.payload:
			x = x.payload
			yield x.name

	@staticmethod
	def _layer_2_edge(packet):
		return packet[0].src, packet[0].dst, packet

	@staticmethod
	def _layer_3_edge(packet):
		if packet.haslayer(IP):
			return packet[1].src, packet[1].dst, packet

	@staticmethod
	def _layer_4_edge(packet):
		if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
			src = packet[1].src
			dst = packet[1].dst
			_ = packet[2]
			return "%s:%i" % (src, _.sport), "%s:%i" % (dst, _.dport), packet

	def draw(self, filename=None):
		graph = self.get_graphviz_format()
		graph.graph_attr['label'] = self.title
		graph.graph_attr['labelloc'] = 't'
		graph.graph_attr['fontsize'] = 20
		graph.graph_attr['fontcolor'] = 'blue'
		for node in graph.nodes():
			if node not in self.data:
				# node might be deleted, because it's not legit etc.
				continue
			snode = str(node)
			nnode = snode
			ssnode = snode.split(':') # look for mac or a port on the ip
			if len(ssnode) <= 2:
				nnode = self.lookup(ssnode[0])
			
			node.attr['shape'] = self.args.shape
			node.attr['fontsize'] = '10'
			node.attr['width'] = '0.5'
			node.attr['color'] = 'linen'
			node.attr['style'] = 'filled,rounded'
			if 'country' in self.data[snode]:
				country_label = self.data[snode]['country']
				city_label = self.data[snode]['city']
				if nnode != snode:
					nodelab = '%s\n%s' % (nnode,snode)
				else:
					nodelab = snode
				if country_label != 'private':
					if city_label == 'private':
						nodelab += "\n(%s)" % (country_label)
					else:
						nodelab += "\n(%s, %s)" % (city_label, country_label)
				node.attr['label'] = nodelab
				if not (country_label == 'private'):
					node.attr['color'] = 'lightyellow'
					#TODO add color based on country or scan?
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]
			edge.attr['label'] = 'transmitted: %i bytes\n%s ' % (connection['transmitted'], ' | '.join(connection['layers']))
			edge.attr['fontsize'] = '8'
			edge.attr['minlen'] = '2'
			edge.attr['penwidth'] = min(max(0.05,connection['connections'] * 1.0 / len(self.graph.nodes())), 2.0)
		graph.layout(prog=self.args.layoutengine)
		graph.draw(filename)

	def get_graphviz_format(self, filename=None):
		agraph = networkx.drawing.nx_agraph.to_agraph(self.graph)
		# remove packet information (blows up file size)
		for edge in agraph.edges():
			del edge.attr['packets']
		if filename:
			agraph.write(filename)
		return agraph
