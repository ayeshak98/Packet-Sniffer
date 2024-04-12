# Import the necessary libraries
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet import ICMP
from scapy.layers.dhcp import BOOTP
from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
import time

# Define the packet sniffer function
def packet_sniffer(packet):
    if packet.haslayer(ARP):
        try:
            # handle arp packets
            arp_pkt = packet[ARP]
            print("ARP Packet Detected:")
            print("Source MAC:", arp_pkt.hwsrc)
            print("Source IP:", arp_pkt.psrc)
            print("Destination MAC", arp_pkt.hwdst)
            print("Destination IP:", arp_pkt.pdst)
            
        except IndexError as e:
            print("Error while handling ARP packet:", e)

    elif packet.haslayer(ICMP):
        try:
            # handle icmp packets
            icmp_pkt = packet[ICMP]
            print("ICMP Packet Detected:")
            print("Type:", icmp_pkt.type)
            print("Code:", icmp_pkt.code)
           
        except IndexError as e:
            print("Error while handling ICMP packet:", e)

    elif packet.haslayer(TCP):
        try:
            # handle TCP packets
            tcp_pkt = packet[TCP]
            print("TCP packet detected:")
            print("Source IP:", packet[IP].src)
            print("Source Port:", tcp_pkt.sport)
            print("Destination IP:", packet[IP].dst)
            print("Destination Port:", tcp_pkt.dport)
            
        except IndexError as e:
            print("Error while handling TCP packet:", e)

    elif packet.haslayer(UDP):
        try:
            # handle udp packets
            udp_pkt = packet[UDP]
            print("UDP Packet Detected:")
            print("Source IP:", packet[IP].src)
            print("Source Port:", udp_pkt.sport)
            print("Destination IP:", packet[IP].dst)
            print("Destination Port:", udp_pkt.dport)
           
        except IndexError as e:
            print("Error while handling UDP packet:", e)

    elif packet.haslayer(BOOTP):
        try:
            # handle bootp packets
            bootp_pkt = packet[BOOTP]
            print("BOOTP Packet Detected:")
            print("Source MAC:", bootp_pkt.chaddr)
            print("SOURCE IP:", bootp_pkt.ciaddr)
           
        except IndexError as e:
            print("Error while handling BOOTP packet:", e)



# Define the duration to run the packet sniffer (in seconds)
duration = 120

# Start time
start_time = time.time()

# Sniff packets for the specified duration
while time.time() - start_time <= duration:

 sniff(prn=packet_sniffer, filter="arp or icmp or tcp or udp or bootp", store=0, timeout=duration)
 print("Packet sniffing complete.")
