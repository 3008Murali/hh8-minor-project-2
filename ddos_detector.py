from scapy.all import sniff, IP
from collections import defaultdict
import time

ip_counter = defaultdict(int)
ip_start_time = {}
BLACKLIST_FILE = "blacklist.txt"
TIME_WINDOW = 10       
PACKET_THRESHOLD = 100 


def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        return set()


def add_to_blacklist(ip):
    with open(BLACKLIST_FILE, "a") as file:
        file.write(ip + "\n")


blacklisted_ips = load_blacklist()


def detect_ddos(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()

        # Ignore already blacklisted IPs
        if src_ip in blacklisted_ips:
            return

        # First packet from IP
        if src_ip not in ip_start_time:
            ip_start_time[src_ip] = current_time
            ip_counter[src_ip] = 1
        else:
            ip_counter[src_ip] += 1

            # Check time window
            if current_time - ip_start_time[src_ip] <= TIME_WINDOW:
                if ip_counter[src_ip] > PACKET_THRESHOLD:
                    print(f"[ALERT] DDoS detected from IP: {src_ip}")
                    add_to_blacklist(src_ip)
                    blacklisted_ips.add(src_ip)
            else:
                # Reset counter after time window
                ip_start_time[src_ip] = current_time
                ip_counter[src_ip] = 1


print("🚨 DDoS Detection Tool Started...")
sniff(prn=detect_ddos, store=False)
