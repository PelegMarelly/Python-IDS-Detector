from scapy.all import *
from collections import defaultdict
import tkinter as tk
from tkinter import messagebox
import threading

print("Starting GUI Scan Detector...")
print("Threshold: 10 ports")


scanners = defaultdict(set)
reported_ips = set()



def show_alert(ip, port_count):
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)

    messagebox.showwarning(
        title="SECURITY ALERT",
        message=f"PORT SCAN DETECTED!\n\nSource IP: {ip}\nUnique Ports Scanned: {port_count}\n\nBlocking recommended!"
    )
    root.destroy()


def analyze_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        scanners[src_ip].add(dst_port)
        ports_scanned_count = len(scanners[src_ip])

        if ports_scanned_count > 10 and src_ip not in reported_ips:
            print(f"\nALERT: PORT SCAN DETECTED from {src_ip}")
            reported_ips.add(src_ip)
            alert_thread = threading.Thread(target=show_alert, args=(src_ip, ports_scanned_count))
            alert_thread.start()

sniff(filter="tcp", prn=analyze_packet, store=0, iface="Software Loopback Interface 1")