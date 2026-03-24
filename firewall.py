from scapy.all import sniff, IP, TCP, UDP
from rules import is_blocked
from logger import log_packet

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        port = None

        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport

        if is_blocked(src_ip, dst_ip, port, protocol):
            print(f"[BLOCKED] {src_ip} -> {dst_ip} | {protocol}:{port}")
            log_packet(src_ip, dst_ip, port, protocol, "BLOCKED")
        else:
            print(f"[ALLOWED] {src_ip} -> {dst_ip} | {protocol}:{port}")
            log_packet(src_ip, dst_ip, port, protocol, "ALLOWED")

def start_firewall():
    print("🚀 Firewall Started... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)
