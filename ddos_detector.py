from scapy.all import sniff, IP
from collections import defaultdict
import time

ip_counter = defaultdict(int)

BLACKLIST_FILE = "blacklist.txt"

TIME_WINDOW = 10
PACKET_THRESHOLD = 100

start_time = time.time()