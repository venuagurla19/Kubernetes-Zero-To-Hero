#!/usr/bin/python
# -*- coding: utf-8 -*-
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License.
#
# Author: Mohamed BEN ALI

import os
import sys
import platform
import argparse
import logging
import time
import socket
import pygeoip
from scapy.all import *
from libs.colorama import *
from libs import FileUtils

if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.1.1'
__description__ = '''\
  ___________________________________________

  CyberScan | v.''' + __version__ + '''
  Author: BEN ALI Mohamed
  ___________________________________________
'''

# Helper functions
def header():
    program_banner = open(FileUtils.buildPath('banner.txt')).read().format(version=__version__)
    message = Style.BRIGHT + Fore.RED + program_banner + Style.RESET_ALL
    write(message)

def write(string):
    sys.stdout.write(string + '\n')
    sys.stdout.flush()

def geo_ip(host):
    try:
        geo_data = pygeoip.GeoIP('GeoLiteCity.dat')
        data = geo_data.record_by_name(host)
        print(f"[*] GeoIP Information for {host}:")
        for key, value in data.items():
            print(f"[*] {key}: {value}")
    except Exception as e:
        print(f"[*] Error fetching GeoIP data: {e}")

def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        if check_port(host, port):
            open_ports.append(port)
    return open_ports

def display_open_ports(open_ports):
    if open_ports:
        print("[*] Open Ports:")
        for port in open_ports:
            print(f"  [*] Port {port} is open")
    else:
        print("[*] No open ports found.")

def arp_ping(host):
    print(f"[*] Performing ARP ping for {host}")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=2)
    ans.summary(lambda s, r: r.sprintf("%Ether.src% %ARP.psrc%"))

def icmp_ping(host):
    print(f"[*] Performing ICMP ping for {host}")
    ans, unans = srp(IP(dst=host) / ICMP())
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

def superscan(host, start_port, end_port):
    print(f"[*] Scanning {host} from port {start_port} to {end_port}...")
    open_ports = scan_ports(host, start_port, end_port)
    display_open_ports(open_ports)

# Packet Analysis Functions
def pcap_analyser(file, layer_type):
    pkts = rdpcap(file)
    i = 0
    for pkt in pkts:
        i += 1
        print(f"\n[*] Packet {i}")
        if layer_type == "eth" and pkt.haslayer(Ether):
            print(f"[*] Ethernet - Src: {pkt.src}, Dst: {pkt.dst}")
        elif layer_type == "ip" and pkt.haslayer(IP):
            print(f"[*] IP - Src: {pkt[IP].src}, Dst: {pkt[IP].dst}")
        elif layer_type == "tcp" and pkt.haslayer(TCP):
            print(f"[*] TCP - Src Port: {pkt[TCP].sport}, Dst Port: {pkt[TCP].dport}")
        elif layer_type == "udp" and pkt.haslayer(UDP):
            print(f"[*] UDP - Src Port: {pkt[UDP].sport}, Dst Port: {pkt[UDP].dport}")
        elif layer_type == "icmp" and pkt.haslayer(ICMP):
            print(f"[*] ICMP - Type: {pkt[ICMP].type}, Code: {pkt[ICMP].code}")

# Main function for argument parsing
def main():
    try:
        parser = argparse.ArgumentParser(description=__description__, formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("-s", "--serveur", dest="serveur", help="Target server IP address")
        parser.add_argument("-p", "--level", dest="level", help="Action level (scan, arp, icmp, etc.)")
        parser.add_argument("-d", "--sport", dest="sport", help="Start port for scanning")
        parser.add_argument("-t", "--eport", dest="eport", help="End port for scanning")
        parser.add_argument("-f", "--file", dest="file", help="Pcap file for analysis")
        args = parser.parse_args()

        if args.serveur or args.file:
            header()
            if args.file and args.level:
                pcap_analyser(args.file, args.level)
            elif args.serveur and args.level:
                if args.level == "arp":
                    arp_ping(args.serveur)
                elif args.level == "icmp":
                    icmp_ping(args.serveur)
                elif args.level == "scan" and args.sport and args.eport:
                    start_port = int(args.sport)
                    end_port = int(args.eport)
                    superscan(args.serveur, start_port, end_port)
                elif args.level == "geoip":
                    geo_ip(args.serveur)
        else:
            print("Usage: CyberScan.py [-h] [-s SERVEUR] [-p LEVEL] [-d SPORT] [-t EPORT] [-f FILE]")
    except KeyboardInterrupt:
        print("\n[*] You pressed Ctrl+C. Exiting.")
        sys.exit(1)

if __name__ == '__main__':
    main()
