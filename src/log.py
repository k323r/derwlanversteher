#!/usr/bin/env python

import os
import os.path
import sys

from scapy.all import load_module, sniff, Dot11

USAGE = """\
usage: sudo python log.py [-f] <monitoring-interface> <logfile-name>
example: sudo python log.py wlp1s0mon test.dat"""

DIR_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
DIR_DATA = os.path.join(DIR_ROOT, 'data')

# Package types and subtypes.
# More information:
# https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
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
    Note: I couldn't be bothered setting up argparse for one simple development
    convenience flag. If more command line options should be desired in the
    future, this decision might be reconsidered.
    """
    args = sys.argv
    options = [arg for arg in args if arg.startswith('-')]
    parameters = [arg for arg in args if not arg in options]
    overwrite_logfile = ('-f' in options)
    try:
        monitoring_interface, logfile_name = parameters[1:3]
    except:
        print USAGE
        sys.exit()
    return monitoring_interface, logfile_name, overwrite_logfile

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

class Logger(object):
    """
    Basically a wrapper around handle_packet to avoid a global logfile_handle.
    Unfortunately, scapy.all.sniff seems to insist on managing the main loop
    internally, instead of beeing managed by one.
    """
    def __init__(self, monitoring_interface, logfile_name, overwrite_logfile):
        self.monitoring_interface = monitoring_interface
        self.logfile_path = os.path.join(DIR_DATA, logfile_name)
        self.overwrite_logfile = overwrite_logfile
        self._init_log_file()
        self._setup_sniffing()

    def _init_log_file(self):
        """
        Create the DIR_DATA if necessary, then start a fresh log at
        self.logfile_path -- unless it exists already and shall not be
        overwritten, in which case we exit. Keep the logfile open for further
        additions.
        TODO: Refactor into database connect and update routine.
        """
        try:
            mkdir_p(DIR_DATA)
        except OSError as e:
            print e
            sys.exit()
        if os.path.exists(self.logfile_path) and not self.overwrite_logfile:
            print 'Log file exists already: %s. Exiting.' % self.logfile_path
            sys.exit()
        self.logfile_handle = open(self.logfile_path, "w+")
        self.logfile_handle.write("mac rssi\n")

    def _setup_sniffing(self):
        """
        Requisites for handle_packet.
        """
        load_module("p0f")
        self.mac_addresses = set()

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
            if not mac_address in self.mac_addresses:
                # https://en.wikipedia.org/wiki/Received_signal_strength_indication
                rssi = -(256-ord(packet.notdecoded[-4:-3]))
                print 'MAC adress %s strength (dBm) %s' %(mac_address, rssi)
                self.mac_addresses.add(mac_address)
                self.logfile_handle.write('%s %s\n' %(mac_address, rssi))
                self.logfile_handle.flush()

if __name__ == '__main__':
    lgr = Logger(*get_command_line_parameters())
    sniff(
        iface=lgr.monitoring_interface, 
        prn=lgr.handle_packet,
        store=0)
