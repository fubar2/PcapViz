from argparse import ArgumentParser

from pcapviz.core import GraphManager
from pcapviz.sources import ScapySource
from scapy.all import *
from scapy.layers.http import HTTP


# make this global so we can use it for tests

parser = ArgumentParser(description='Network packet capture (standard .pcap file) topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-i', '--pcaps', nargs='*',help='Mandatory space delimited list of capture files to be analyzed - wildcards work too - e.g. -i Y*.pcap',required=True)
parser.add_argument('-o', '--out', help='Each topology will be drawn and saved using this filename stub. Use a .pdf or .png filename extension to specify image type')
parser.add_argument('-g', '--graphviz', help='Graph will be exported for downstream applications to the specified file (dot format)')
parser.add_argument('--layer2', action='store_true', help='Device (mac address) topology network graph')
parser.add_argument('--layer3', action='store_true', help='IP layer message graph. Default')
parser.add_argument('--layer4', action='store_true', help='TCP/UDP message graph')
parser.add_argument('-d','--DEBUG', action='store_true', help='Show debug messages and other (sometimes) very useful data')
parser.add_argument('-w', '--whitelist', nargs='*', help='Whitelist of protocols - only packets matching these layers shown - eg IP Raw HTTP')
parser.add_argument('-b', '--blacklist', nargs='*', help='Blacklist of protocols - NONE of the packets having these layers shown eg DNS NTP ARP RTP RIP')
parser.add_argument('-r', '--restrict', nargs='*', help='Whitelist of device mac addresses - restrict all graphs to traffic to or device(s). Specify mac address(es) as "xx:xx:xx:xx:xx:xx"')
parser.add_argument('-fi', '--frequent-in', action='store_true', help='Print frequently contacted nodes to stdout')
parser.add_argument('-fo', '--frequent-out', action='store_true', help='Print frequent source nodes to stdout')
parser.add_argument('-G', '--geopath', default='/usr/share/GeoIP/GeoLite2-City.mmdb', help='Path to maxmind geodb data')
parser.add_argument('-l', '--geolang', default='en', help='Language to use for geoIP names')
parser.add_argument('-E', '--layoutengine', default='sfdp', help='Graph layout method - dot, sfdp etc.')
parser.add_argument('-s', '--shape', default='diamond', help='Graphviz node shape - circle, diamond, box etc.')
parser.add_argument('-n', '--nmax', default=100, help='Automagically draw individual protocols if more than --nmax nodes. 100 seems too many for any one graph.')
parser.add_argument('-a', '--append', action='store_true',default=False, help='Append multiple input files before processing - old behaviour. New default is to batch process each input pcap file.')

args = parser.parse_args()

llook = {'DNS':DNS,'UDP':UDP,'ARP':ARP,'NTP':NTP,'IP':IP,'TCP':TCP,'Raw':Raw,'HTTP':HTTP,'RIP':RIP,'RTP':RTP}

def doLayer(layer, packets,fname,args):
	"""
	run a single layer analysis
	"""
	args.nmax = int(args.nmax)
	g = GraphManager(packets, layer=layer, args=args)
	nn = len(g.graph.nodes())
	if args.out:
		if nn > args.nmax:
			print('Asked to draw %d nodes with --nmax set to %d. Will also do useful protocols separately' % (nn,args.nmax))
			for kind in llook.keys():
				subset = [x for x in packets if x.haslayer(kind) and x != None]  
				if len(subset) > 2:
					sg = GraphManager(subset,layer=layer, args=args)
					nn = len(sg.graph.nodes())
					if nn > 2:
						ofn = '%s_%d_%s_%s' % (kind,nn,fname,args.out)
						sg.draw(filename = ofn)
						print('drew %s %d nodes' % (ofn,nn))
		g.draw(filename='%s_layer%d_%s' % (fname,layer,args.out))
	if args.frequent_in:
		g.get_in_degree()

	if args.frequent_out:
		g.get_out_degree()

	if args.graphviz:
		g.get_graphviz_format(args.graphviz)

def doPcap(pin,args):
	"""
	filtering and control for analysis - amalgamated input or not 
	runs all layers if no layer specified
	"""
	bl=[]
	wl=[]
	if args.whitelist != None and args.blacklist != None:
		print('### Parameter error: Specify --blacklist or specify --whitelist but not both together please.')
		sys.exit(1)
	packets = pin
	if args.whitelist: # packets are returned from ScapySource.load as a list so cannot use pcap.filter(lambda...)
		wl = [llook[x] for x in args.whitelist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in wl]) > 0 and x != None]  
	elif args.blacklist:
		bl = [llook[x] for x in args.blacklist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in bl]) == 0 and x != None]  
	if args.DEBUG and (args.blacklist or args.whitelist):
		print('### Read', len(pin), 'packets. After applying supplied filters,',len(packets),'are left. wl=',wl,'bl=',bl)			
	if not (args.layer2 or args.layer3 or args.layer4): # none requested - do all
		for layer in [2,3,4]:
			doLayer(layer, packets,args.out,args)
	else:
		layer = 3
		if args.layer2:
			layer = 2
		elif args.layer4:
			layer = 4
		doLayer(layer,packets,args.out,args)	


if __name__ == '__main__':
	if args.pcaps:
		if args.append: # old style amalgamated input
			pin = ScapySource.load(args.pcaps)
			doPcap(pin,args)
		else:
			for fname in args.pcaps:
				pin = rdpcap(fname) # ScapySource.load(args.pcaps)
				doPcap(pin,args)
