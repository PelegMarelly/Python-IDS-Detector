from scapy.all import *
from collections import defaultdict
import tkinter as tk
from tkinter import messagebox
import threading

print("Detecting: SYN Scans, ARP Scans, NULL/XMAS Scans")

syn_scanners = defaultdict(set)
arp_scanners = defaultdict(set)
reported_threats = set()

def show_alert(title, message):
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    messagebox.showwarning(title=title, message=message)
    root.destroy()


def analyze_packet(packet):
    try:
        if packet.haslayer(ARP) and packet[ARP].op == 1:
            src_ip = packet[ARP].psrc
            target_ip = packet[ARP].pdst
            arp_scanners[src_ip].add(target_ip)

            if len(arp_scanners[src_ip]) > 10:
                threat_id = f"{src_ip}_ARP"
                if threat_id not in reported_threats:
                    print(f"\nARP SCAN DETECTED from {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert, args=("NETWORK SCAN DETECTED",
                                                              f"Source IP: {src_ip}\nis scanning the network via ARP")).start()
        elif packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            if flags == 0 or str(flags) == "":
                threat_id = f"{src_ip}_NULL"
                if threat_id not in reported_threats:
                    print(f"\nNULL SCAN DETECTED from {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert,
                                     args=("MALICIOUS PACKET", f"NULL Scan detected from:\n{src_ip}")).start()

            elif 'F' in str(flags) and 'P' in str(flags) and 'U' in str(flags):
                threat_id = f"{src_ip}_XMAS"
                if threat_id not in reported_threats:
                    print(f"\nXMAS SCAN DETECTED from {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert,
                                     args=("MALICIOUS PACKET", f"XMAS Scan detected from:\n{src_ip}")).start()

            elif flags == 'S':
                syn_scanners[src_ip].add(dst_port)
                if len(syn_scanners[src_ip]) > 15:
                    threat_id = f"{src_ip}_SYN"
                    if threat_id not in reported_threats:
                        print(f"\nPORT SCAN DETECTED from {src_ip}")
                        reported_threats.add(threat_id)
                        threading.Thread(target=show_alert, args=("PORT SCAN DETECTED",
                                                                  f"Source IP: {src_ip}\nScanning multiple ports")).start()

    except Exception as e:
        pass

sniff(prn=analyze_packet, store=0)