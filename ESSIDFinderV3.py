#!/bin/python

import sys
import os
import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11
import pcapy
from threading import Thread
from tabulate import tabulate
from prettytable import PrettyTable
from netifaces import interfaces

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

clients = set()
ESSIDsList = []
APList = []
debug = 0
t = PrettyTable(['No','ESSID', 'BSSID'])
wlanInterfaces = set()
sniffersThreads = []

def hopper(iface):
	n = 1
	stop_hopper = False
	while not stop_hopper:
		time.sleep(0.5)
		os.system('iwconfig %s channel %d' % (iface, n))
		if debug >= 2:
			print "Current Channel %d" % (n)
		dig = int(random.random() * 14)
		if dig != 0 and dig != n:
			n = dig

def hopperRange(iface, rangeStart, rangeEnd):
	n = rangeStart
	stop_hopper = False
	while not stop_hopper:
		for x in xrange(rangeStart,rangeEnd):
			time.sleep(0.5)
			os.system('iwconfig %s channel %d' % (iface, x))
			if debug >= 2:
				print "Wireless Interface: {} Current Channel: {}".format(iface,n)
			dig = int(random.randint(rangeStart,rangeEnd))
			if dig != 0 and dig != n:
				n = dig

def PacketHandeler(pkt):
	pass


def PacketHandeler1(pkt):
	#print "\t\t\tHandling the packets by Handler1"
	if pkt.haslayer(Dot11Beacon):
		if debug == 3:
			print pkt.summary()
		if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
			temp = pkt
			pkt.getlayer(Dot11).payload.name
			if "Resp" in pkt:
				print "Analyzing {} packet".format()
			while temp:
				temp = temp.getlayer(Dot11Elt)
				AP = [temp.info,pkt.addr3]
				if temp and temp.ID == 0:
					essid = temp.info
					bssid = pkt.addr3
					#print str(temp.info)
					if str(essid).startswith("\x00") :
						if debug >= 2:
							print "Hidden Network"
						essid = "**Hidden ESSID**"

					AP = [essid,bssid]
					
					ESSIDsList.append(temp.info)
					if AP not in APList:
						APList.append(AP)
						if debug == 1:
							pktName = pkt.getlayer(Dot11).payload.name
							if str(temp.info).startswith("\x00"):
								print bcolors.FAIL +"New ESSID '{}' and BSSID: {} Detected, Total number of Discovered ESSID = {}  via {} ---> Hidden ESSID".format(essid,bssid,len(APList),pktName) + bcolors.ENDC
							else:
								print "New ESSID '{}' and BSSID: {} Detected, Total number of Discovered ESSID = {}  via {}".format(essid,bssid,len(APList),pktName)
						if debug >= 2:
							print "ESSID: %s\t\t\tBSSID %s " %(essid,bssid)
						t.add_row([len(APList),essid,bssid])
					break
				temp = temp.payload

	else :
		if debug >= 2:
			print "Not a Dot11 Packet"
		pass
	return


def sniffer(iface, count , prn ):
	print "Trying to set monitor mode for device " + iface + "..."
	os.system("ifconfig " + iface + " down")
	os.system("iwconfig " + iface + " mode monitor")
	os.system("ifconfig " + iface + " up")
	#print "Done. If you don't see any data, the monitor mode setup may have failed.\n\n"
	print "Wireless Interface : {} Start Sniffing .....".format(iface)
	sniff(iface = iface, count = count, prn = prn)

def main():
	global debug
	os.system('figlet -c -t -k The WiFiSnifferV2')
	print len(sys.argv)
	if len(sys.argv) >= 2:
		print "Available devices:"
		print
		#devices = pcapy.findalldevs()
		devices = interfaces()
		for device in devices:
			if device.startswith("wlan"):
				wlanInterfaces.add(device)
				print device
	else:
		print "Usage: ./wirelessSniffer.py %s deviceName", sys.argv[1]
		exit()

	dev = sys.argv[1]
	debug = 1
	packetCount = int(sys.argv[2])
	chPerInterface = int(14 / len(wlanInterfaces))
	extraCh = 14 % len(wlanInterfaces) 
	print "chPerInterface = {}".format(chPerInterface)
	counter = 1
	iterationCounter = 1
	for device in wlanInterfaces:
		rangeStart = counter
		rangeEnd = counter + chPerInterface -1
		if rangeEnd > 14:
			rangeEnd = 14
		if (iterationCounter == len(wlanInterfaces)) and (extraCh > 0):
			rangeEnd += extraCh
		threadHopper = threading.Thread(target=hopperRange, args=(device, rangeStart, rangeEnd), name="hopperRange")
		threadHopper.daemon = True
		threadHopper.start()
		

		print "Started Thread for device {} with channels range Start = {} , End = {}".format(device,rangeStart, rangeEnd)

		counter = rangeEnd + 1

		threadSniffer = threading.Thread(target=sniffer, args=(device, packetCount, PacketHandeler1), name="sniffer")
		threadSniffer.daemon = True
		threadSniffer.start()


		sniffersThreads.append([threadSniffer,threadHopper])
		iterationCounter += 1

	
	#sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandeler)

	for thread in sniffersThreads:
		thread[0].join()


	print(t)

if __name__ == '__main__':
	main()