from scapy.all import *

def handler(packet):
    print(packet.summary())

#sniff(iface="wlp1s0", prn=handler, store=0)
sniff(iface="wlo1", prn=handler, store=0)
# Run with following command
# sudo python3 sniffer.py
# You can change last network id -> wlp1s0
