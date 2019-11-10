#!/bin/python

import pcapy
from prettytable import PrettyTable
from scapy.all import *
from scapy.layers.dot11 import Dot11

ESSIDsList = []
APList = []
t = PrettyTable(['No', 'ESSID', 'BSSID'])
debug = 0


def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(1)
        os.system('iwconfig %s channel %d' % (iface, n))
        if debug >= 2:
            print "Current Channel %d" % (n)
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


def PacketHandeler1(pkt):
    # print "\t\t\tHandling the packets by Handler1"
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
                AP = [temp.info, pkt.addr3]
                if temp and temp.ID == 0:
                    essid = temp.info
                    bssid = pkt.addr3
                    # print str(temp.info)
                    if str(essid).startswith("\x00"):
                        if debug >= 2:
                            print "Hidden Network"
                        essid = "**Hidden ESSID**"

                    AP = [essid, bssid]

                    ESSIDsList.append(temp.info)
                    if AP not in APList:
                        APList.append(AP)
                        if debug == 1:
                            pktName = pkt.getlayer(Dot11).payload.name
                            if str(essid).startswith("\x00"):
                                print "New ESSID '{}' and BSSID: {} Detected, Total number of Discovered ESSID = {}  via {} ---> Hidden ESSID".format(
                                    essid, bssid, len(APList), pktName)
                            else:
                                print "New ESSID '{}' and BSSID: {} Detected, Total number of Discovered ESSID = {}  via {}".format(
                                    essid, bssid, len(APList), pktName)
                        if debug >= 2:
                            print "ESSID: %s\t\t\tBSSID %s " % (essid, bssid)
                        t.add_row([len(APList), essid, bssid])
                    break
                temp = temp.payload

    else:
        if debug >= 2:
            print "Not a Dot11 Packet"
        pass
    return


def PacketHandeler(pkt):
    # print "\t\t\tHandling the packets by Handler0"
    if pkt.haslayer(Dot11FCS):
        print pkt.summary()
    else:
        print "Not a Dot11 Packet"
    return


def main():
    global debug
    os.system('figlet -c -t -k The WiFiSnifferV2')
    print len(sys.argv)
    if len(sys.argv) < 2:
        print "Available devices:"
        print
        devices = pcapy.findalldevs()

        for device in devices:
            if device.startswith("wlan"):
                print device

        print "Usage: ./wirelessSniffer.py %s deviceName", sys.argv[1]
        exit()

    dev = sys.argv[1]
    debug = 1

    thread = threading.Thread(target=hopper, args=(sys.argv[1],), name="hopper")
    thread.daemon = True
    thread.start()

    print "Trying to set monitor mode for device " + dev + "..."
    os.system("ifconfig " + dev + " down")
    os.system("iwconfig " + dev + " mode monitor")
    os.system("ifconfig " + dev + " up")
    print "Done. If you don't see any data, the monitor mode setup may have failed.\n\n"
    print "Sniffing ....."
    sniff(iface=sys.argv[1], prn=PacketHandeler1, timeout=60000)
    # print(tabulate(APList,headers=['ESSID', 'BSSID']))
    print(t)


if __name__ == "__main__":
    main()
