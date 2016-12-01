#!/usr/bin/python

import os
import sys
import datetime
import time
import socket
import argparse
from tabulate import tabulate

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', help='Print help', action='store_true')
    parser.add_argument('-d', '--domain', help='Domain name (example: test.com)', default="test.com")
    parser.add_argument('-s', '--nsservers', help='NS servers (example: "ns1,ns2")', default="ns1,ns2")
    parser.add_argument('-q', '--query', help='DNS query (example: query.test.com)', default=None)
    parser.add_argument('-t', '--timeout', help='Set nslookup timeout (default: 2)', default=2)
    args = parser.parse_args()

    if len(sys.argv) <= 2:
        parser.print_help()
        sys.exit(1)

    if args.help:
        parser.print_help()
        sys.exit(1)

    DOMAIN = args.domain
    if not DOMAIN.startswith("."):
        DOMAIN = "." + DOMAIN

    if args.query == None:
        QUERY = DOMAIN[1:]
    else:
        QUERY = args.query

    NAME_ns_str = str(args.nsservers).replace(" ", "")  # remove all spaces
    NAME_ns_list = NAME_ns_str.split(",")               # make list for ns server names
    NS_list = {}

    for NAME in NAME_ns_list:
        NAME += DOMAIN
        NS_list[NAME] = {}
        NS_list[NAME]["NAME"] = NAME
        try:
            NS_list[NAME]["IP"] = str(socket.gethostbyname(NAME))
        except:
            print "Fail to resolving DNS Servers: " + NAME
            sys.exit(1)

    print ""
    print tabulate([["Domain", DOMAIN], ["Query", QUERY]], tablefmt='grid')
    for NS in NS_list.keys():
        print tabulate([[NS_list[NS]["NAME"], NS_list[NS]["IP"]]], tablefmt='grid')
    print ""

    print "\r\nStart check: " + str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S") + "\r\n")
    try:
        while True:
            for NS in NS_list.keys():
                now = str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
                start = datetime.datetime.now()
                os.system("nslookup -timeout=" + str(int(args.timeout)) + " " + QUERY + " "
                          + NS_list[NS]["IP"] + " >/dev/null 2>/dev/null")
                speed = str((datetime.datetime.now() - start).total_seconds())[:4]
                print str(tabulate([[now, NS_list[NS]["NAME"], speed]], tablefmt='grid'))
                time.sleep(1)
    except:
        print "\r\nStop check: " + str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S") + "\r\n")
        sys.exit(1)
