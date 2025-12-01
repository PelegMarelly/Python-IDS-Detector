from scapy.all import *
import time
import random

target_ip = "1.2.3.4"

print(f"Targeting: {target_ip}")
print("1. SYN Scan (Port Scan)")
print("2. XMAS Scan")
print("3. NULL Scan")
print("4. ARP Scan (Network Discovery)")

choice = input("Choose attack type (1-4): ")

if choice == "1":
    print("Sending SYN Scan...")
    for port in range(20, 45):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.01)

elif choice == "2":
    print("Sending XMAS Scan (FIN+PSH+URG)...")
    send(IP(dst=target_ip)/TCP(dport=80, flags="FPU"), verbose=0)

elif choice == "3":
    print("Sending NULL Scan (No Flags)...")
    send(IP(dst=target_ip)/TCP(dport=80, flags=""), verbose=0)

elif choice == "4":
    print("Sending ARP Scan...")
    target_prefix = target_ip.rsplit('.', 1)[0]
    for i in range(1, 20):
        fake_target = f"{target_prefix}.{random.randint(100,200)}"
        send(ARP(op=1, pdst=fake_target), verbose=0)
        time.sleep(0.01)

print("Attack sent")
