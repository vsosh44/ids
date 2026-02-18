import time
from collections import defaultdict, deque

from scapy.all import IP, ICMP

from src.ids.cmds import block_ip
from src.database import get_blocked_ips
from src.logs import logger
from src.ids.check_ip import check_ip
import src.ids.base as ids_base

icmp_packets = defaultdict(deque)
blocked_ips: set = get_blocked_ips()
last_reset = time.time()
learning_phase = True

threshold_pps = 8.0
min_pps = 4.0
max_pps = 25.0
learning_k = 2.5
adaptive_k = 2.8
WINDOW = 5.0


def attack(pkt):
    global last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        learning_phase, threshold_pps = ids_base.update_thresholds(
            icmp_packets,
            now,
            learning_phase,
            min_pps, max_pps,
            learning_k, adaptive_k
        )

        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        pkt[IP].src not in blocked_ips and
        ICMP in pkt and
        pkt[ICMP].type == 8):

        src_ip = pkt[IP].src

        icmp_packets[src_ip].append(now)

        current_pps, avg_pps = ids_base.get_pps(icmp_packets, src_ip, now, WINDOW)

        logger.info(f"[ICMP] {src_ip=}, rate={current_pps:.1f} pps")

        if current_pps > threshold_pps and current_pps > avg_pps * 3:
            status, asn = check_ip(src_ip)
            if not status:
                logger.info(f"[ATTACK] ICMP-FLOOD from {src_ip} | "
                            f"Rate: {current_pps:.1f} pps | Threshold: {threshold_pps:.1f} pps")

                block_ip(src_ip)
                blocked_ips.add(src_ip)
                icmp_packets[src_ip].clear()
