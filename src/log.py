#!/usr/bin/env python

from scapy.all import *

### see the following link for package types
# https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces

ap_list = []
subtype_list = []
type_list = []

accepted_subtypes = [0, 2, 4]

interface = "wlp1s0mon"
load_module("p0f")

f_dump = open("sample5.dat", "w+")
f_dump.writelines("MAC RSSI\n")

def PacketHandler (pkt):#
    if pkt.haslayer (Dot11):		#print (str(pkt.subtype))
        if pkt.type == 0 and pkt.subtype in accepted_subtypes:
            if pkt.addr2 not in ap_list:
                extra = pkt.notdecoded 
                rssi = -(256-ord(extra[-4:-3]))
                ap_list.append(pkt.addr2)
                print 'MAC adress %s strength (dBm) %s' %(pkt.addr2, rssi)
                f_dump.writelines('%s %s \n' %(pkt.addr2, rssi))
                f_dump.flush()

sniff(iface = interface , prn = PacketHandler, store = 0)

