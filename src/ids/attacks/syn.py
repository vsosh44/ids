import time
from collections import defaultdict, deque

from scapy.all import IP, TCP

from src.ids.cmds import block_ip
from src.database import get_blocked_ips
from src.logs import logger
from src.ids.check_ip import check_ip
import src.ids.base as ids_base

syn_packets = defaultdict(deque)
blocked_ips: set = get_blocked_ips()
last_reset = time.time()
learning_phase = True

threshold_pps = 20.0
min_pps = 8.0
max_pps = 50.0
learning_k = 3
adaptive_k = 3.2
WINDOW = 2.0


def attack(pkt):
    global last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        learning_phase, threshold_pps = ids_base.update_thresholds(
            syn_packets,
            now,
            learning_phase,
            min_pps, max_pps,
            learning_k, adaptive_k
        )

        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        pkt[IP].src not in blocked_ips and
        TCP in pkt and
        pkt[TCP].flags == 2):

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        syn_packets[src_ip].append(now)

        current_pps, avg_pps = ids_base.get_pps(syn_packets, src_ip, now, WINDOW)

        logger.info(f"[SYN] {src_ip=}, port={dst_port}, rate={current_pps:.1f} pps")

        if current_pps > threshold_pps and current_pps > avg_pps * 3:
            status, asn = check_ip(src_ip)
            if not status:
                logger.info(f"[ATTACK] SYN-SCAN/FLOOD from {src_ip} | "
                            f"Rate: {current_pps:.1f} pps | Threshold: {threshold_pps:.1f} pps")

                block_ip(src_ip)
                blocked_ips.add(src_ip)
                syn_packets[src_ip].clear()
