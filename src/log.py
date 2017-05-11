#!/usr/bin/env python

import os.path
import sys

from scapy.all import load_module, sniff, Dot11

USAGE = """
Usage: sudo python log.py [-c] [-i] <monitoring-interface>

Example: echo 'mac_address,rssi,time_stamp,packet_type,packet_subtype' > ../data/test.dat && sudo python log.py -c wlp1s0mon >> ../data/test.dat

Options:

    -c  Continuous logging, i.e. log every acceptable packet. If this option is
        absent, only the first acceptable packet per mac address is logged.

    -i  Inspect packets that are logged, i.e. print their contents (currently:
        packet.__dict__ and packet.command()) to stdout."""

DIR_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
DIR_DATA = os.path.join(DIR_ROOT, 'data')

# Package types and subtypes.
# More information:
# https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
# TODO: Complete this list (see ./insert_packet_types.sql).
T_MANAGEMENT = 0
ST_ASSOCIATION_REQUEST = 0
ST_REASSOCIATION_REQUEST = 2
ST_PROBE_REQUEST = 4
ACCEPTED_SUBTYPES = [
    ST_ASSOCIATION_REQUEST,
    ST_REASSOCIATION_REQUEST,
    ST_PROBE_REQUEST
]

def get_command_line_parameters():
    """
    If the user supplies proper parameters, parse and return them. Otherwise
    print USAGE information to stdout and exit.
    TODO: I couldn't be bothered setting up argparse for two simple flags.
    Maybe for three...
    """
    args = sys.argv
    options = [arg for arg in args if arg.startswith('-')]
    parameters = [arg for arg in args if not arg in options]
    shall_inspect_packets = any(('i' in o) for o in options)
    shall_log_continuously = any(('c' in o) for o in options)
    try:
        monitoring_interface = parameters[1]
    except:
        print USAGE
        sys.exit()
    return (
        monitoring_interface, shall_inspect_packets, shall_log_continuously)

def is_acceptable(packet):
    """
    TODO: "is_acceptable" is OK for first tests, but too generic. Define a
    series of specific boolean functions with appropriate names to reflect
    different packet semantics. Then apply these inside make_packet_handler.
    """
    return (
        packet.haslayer(Dot11)
        and packet.type == T_MANAGEMENT
        and packet.subtype in ACCEPTED_SUBTYPES)

def show_inspection(packet):
    """
    Development tool: Print as much packet information as you can to stdout.
    The __dict__ attribute and command method can be found in the Packet help:
    >>> from scapy.all import Packet
    >>> help(Packet)
    The scapy documentation may also be useful:
    http://www.secdev.org/projects/scapy/doc/usage.html
    """
    print '#### packet dict ####'
    print packet.__dict__
    print ''
    print '#### packet command ####'
    print packet.command()
    print ''

def shall_be_logged(mac_address, mac_addresses, shall_log_continuously):
    return (shall_log_continuously or (not mac_address in mac_addresses))

def make_packet_handler(shall_inspect_packets, shall_log_continuously):
    """
    Return a callback as 'prn' parameter in scapy.all.sniff.
    """
    mac_addresses = set()

    def handle_packet(packet):
        """
        TODO:
            * Expand is_acceptable (see there).
              (==> What else (besides .addr2) is interesting in a packet?)
            * Explain rssi parsing magic.
        """
        if is_acceptable(packet):
            # https://en.wikipedia.org/wiki/MAC_address
            mac_address = packet.addr2
            if shall_be_logged(mac_address, mac_addresses, shall_log_continuously):
                mac_addresses.add(mac_address)
                if shall_inspect_packets:
                    show_inspection(packet)
                # https://en.wikipedia.org/wiki/Received_signal_strength_indication
                rssi = -(256-ord(packet.notdecoded[-4:-3]))
                sys.stdout.write(
                    '%s,%s,%s,%s,%s\n' % (
                        mac_address,
                        rssi,
                        packet.time,
                        packet.type,
                        packet.subtype))
                sys.stdout.flush()
    return handle_packet

if __name__ == '__main__':
    load_module("p0f")
    monitoring_interface, shall_inspect_packets, shall_log_continuously = get_command_line_parameters()
    handle_packet = make_packet_handler(shall_inspect_packets, shall_log_continuously)
    sniff(
        iface=monitoring_interface, 
        prn=handle_packet,
        store=0)
