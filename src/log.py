#!/usr/bin/env python

import os
import os.path
import sys

from scapy.all import load_module, sniff, Dot11

USAGE = """
Usage: sudo python log.py [-c] [-f] [-i] <monitoring-interface> <logfile-name>

Example: sudo python log.py -fi wlp1s0mon test.dat

Options:

    -c  Continuous logging, i.e. log every acceptable packet. If this option is
        absent, only the first acceptable packet per mac address is logged.

    -f  Force overwrite of an already existing logfile.

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

def mkdir_p(path):
    """
    Wrapper around os.makedirs, except that it keeps silent if the path points
    to an existing directory.
    """
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise OSError("Could not create directory: %s." % path)

def get_command_line_parameters():
    """
    If the user supplies proper parameters, parse and return them in a format
    compatible with Logger.__init__. Otherwise print USAGE information to
    stdout and exit.
    TODO: The command line options started as a simple development convenience
    flag (-f) for which I couldn't be bothered setting up argparse. Now that
    the options have multiplied, this decision is up for reconsideration.
    """
    args = sys.argv
    options = [arg for arg in args if arg.startswith('-')]
    parameters = [arg for arg in args if not arg in options]
    shall_overwrite_log = any(('f' in o) for o in options)
    shall_inspect_packets = any(('i' in o) for o in options)
    shall_log_continuously = any(('c' in o) for o in options)
    try:
        monitoring_interface, logfile_name = parameters[1:3]
    except:
        print USAGE
        sys.exit()
    return (
        monitoring_interface, logfile_name, shall_overwrite_log,
        shall_inspect_packets, shall_log_continuously)

def is_acceptable(packet):
    """
    TODO: "is_acceptable" is OK for first tests, but too generic. Define a
    series of specific boolean functions with appropriate names to reflect
    different packet semantics. Then apply these inside Logger.handle_packet.
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

class Logger(object):
    """
    Basically a wrapper around handle_packet to avoid a global logfile_handle.
    Unfortunately, scapy.all.sniff seems to insist on managing the main loop
    internally, instead of beeing managed by one.
    """
    def __init__(self, monitoring_interface, logfile_name, shall_overwrite_log,
                    shall_inspect_packets, shall_log_continuously):
        self.monitoring_interface = monitoring_interface
        self.logfile_path = os.path.join(DIR_DATA, logfile_name)
        self.shall_overwrite_log = shall_overwrite_log
        self.shall_inspect_packets = shall_inspect_packets
        self.shall_log_continuously = shall_log_continuously
        self._init_log_file()
        self._setup_sniffing()

    def _init_log_file(self):
        """
        Create the DIR_DATA if necessary, then start a fresh log at
        self.logfile_path -- unless it exists already and shall not be
        overwritten, in which case we exit. In case of success, keep the
        logfile open for further additions.
        TODO: Refactor into database connect and update routine.
        """
        try:
            mkdir_p(DIR_DATA)
        except OSError as e:
            print e
            sys.exit()
        if os.path.exists(self.logfile_path) and not self.shall_overwrite_log:
            print 'Log file exists already: %s. Exiting.' % self.logfile_path
            sys.exit()
        self.logfile_handle = open(self.logfile_path, "w+")
        self.logfile_handle.write(
            "mac_address,rssi,time_stamp,packet_type,packet_subtype\n")

    def _setup_sniffing(self):
        """
        Requisites for handle_packet.
        """
        load_module("p0f")
        self.mac_addresses = set()

    def _shall_be_logged(self, mac_address):
        return (
            self.shall_log_continuously 
            or (not mac_address in self.mac_addresses))

    def handle_packet(self, packet):
        """
        TODO:
            * Refactor using a database.
            * Expand is_acceptable (see there).
              (==> What else (besides .addr2) is interesting in a packet?)
            * Explain rssi parsing magic.
        """
        if is_acceptable(packet):
            # https://en.wikipedia.org/wiki/MAC_address
            mac_address = packet.addr2
            if self._shall_be_logged(mac_address):
                self.mac_addresses.add(mac_address)
                if self.shall_inspect_packets:
                    show_inspection(packet)
                # https://en.wikipedia.org/wiki/Received_signal_strength_indication
                rssi = -(256-ord(packet.notdecoded[-4:-3]))
                self.logfile_handle.write(
                    '%s,%s,%s,%s,%s\n' % (
                        mac_address,
                        rssi,
                        packet.time,
                        packet.type,
                        packet.subtype))
                self.logfile_handle.flush()

if __name__ == '__main__':
    lgr = Logger(*get_command_line_parameters())
    sniff(
        iface=lgr.monitoring_interface, 
        prn=lgr.handle_packet,
        store=0)
