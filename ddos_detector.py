import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP
from collections import defaultdict
import time



logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

PACKET_THRESHOLD = 20   
TIME_WINDOW = 2         

def simulate_ddos():
    print("DDoS Detection Tool Started (Simulation Mode)...")

    ip_counter = defaultdict(int)
    start_time = time.time()

    
    packets = (
        [IP(src="192.168.1.2")/TCP()] * 25 +
        [IP(src="192.168.1.3")/TCP()] * 30
    )

    for pkt in packets:
        src_ip = pkt[IP].src
        ip_counter[src_ip] += 1
        time.sleep(0.05)

        if time.time() - start_time >= TIME_WINDOW:
            for ip, count in ip_counter.items():
                if count >= PACKET_THRESHOLD:
                    print(f"[ALERT] DDoS detected from IP: {ip}")
            break

    print("✅ Monitoring stopped. Demo completed.")


if __name__ == "__main__":
    simulate_ddos()
