from scapy.all import *

ports = [25,80,53,443,445,8080,8443]

def SynScan(host):
    pkt = IP(dst=host)/TCP(sport=5555, dport=ports,flags='S')
    answered, unanswered = sr(pkt, timeout=2, verbose=False)
    for(s,r, ) in answered:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

def DNSScan(host):
    pkt = IP(dst=host)/UDP(sport=5555, dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com"))
    answered, unanswered = sr(pkt, timeout=2, verbose=False)
    if answered:
        print("DNS Server at %s" %host)

host = '8.8.8.8'

SynScan(host)
DNSScan(host)