#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="specify the target ip / range of ip")
    options = parser.parse_args()
    return options

def scanner(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_brodcast = broadcast/arp_request
    answer = scapy.srp(arp_request_brodcast,timeout=1,verbose=False)[0]
    big_list = []
    for element in answer:
        element_dict = {"ip":element[1].psrc,"MAC":element[1].hwsrc}
        big_list.append(element_dict)
    return big_list

def print_scan(result_list):
    print("IP\t\t\tMAC Address\n...........................................")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["MAC"])

option_result = get_argument()
scan_list = scanner(option_result.target)
print_scan(scan_list)