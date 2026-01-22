from scapy.all import sniff, IP
from collections import defaultdict
import time

ip_counter = defaultdict(int)

BLACKLIST_FILE = "blacklist.txt"

TIME_WINDOW = 10
PACKET_THRESHOLD = 100

start_time = time.time()

def packet_handler(packet):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1

    current_time = time.time()

    if current_time - start_time >= TIME_WINDOW:
        print("\n--- Traffic Analysis ---")
        for ip, count in ip_counter.items():
            print(f"IP: {ip} | Packets: {count}")

            if count > PACKET_THRESHOLD:
                print(f"[ALERT] Possible DDoS detected from {ip}")
                blacklist_ip(ip)

        ip_counter.clear()
        start_time = current_time


def blacklist_ip(ip):
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")
    print(f"[BLACKLISTED] {ip} added to blacklist")


print("🔍 DDoS Detection Tool Started")
print("Monitoring network traffic.\n")

sniff(prn=packet_handler, store=False)