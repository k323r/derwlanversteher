#!/usr/bin/env python

import os.path
import sys

from scapy.all import load_module, sniff, Dot11

USAGE = """\
usage: sudo python log.py [-f] <monitoring-interface> <logfile-name>
example: sudo python log.py wlp1s0mon macs.dat"""

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
DIR_DATA = os.path.join(ROOT, 'data')

### see the following link for package types
# https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces

ap_list = [] # set()
subtype_list = []
type_list = []

accepted_subtypes = [0, 2, 4]

# read command line parameters and maybe overwrite option
args = sys.argv
options = [arg for arg in args if arg.startswith('-')]
parameters = [arg for arg in args if not arg in options]
use_the_force = ('-f' in options)
try:
    interface, fname_log = parameters[1:3]
except:
    print USAGE
    sys.exit()

# init log file
path_log = os.path.join(DIR_DATA, fname_log)
if (not use_the_force) and os.path.exists(path_log):
    print 'Log file exists already: %s. Exiting.' % path_log
    sys.exit()
f_dump = open(path_log, "w+")
f_dump.writelines("MAC RSSI\n")

# What is p0f ?
load_module("p0f")

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype in accepted_subtypes:
            if pkt.addr2 not in ap_list:
                extra = pkt.notdecoded 
                rssi = -(256-ord(extra[-4:-3]))
                ap_list.append(pkt.addr2) # set --> add
                print 'MAC adress %s strength (dBm) %s' %(pkt.addr2, rssi)
                f_dump.writelines('%s %s \n' %(pkt.addr2, rssi))
                f_dump.flush()


sniff(iface = interface , prn = PacketHandler, store = 0)

