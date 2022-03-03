#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--t", dest="target", help="Target MAC address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please provide a target, use --help for more info.")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n------------------------------------------")

    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


# get the command line options
options = get_arguments()
# call the scan function and save result as variable
scan_result = scan(options.target)
#print results
print_result(scan_result)