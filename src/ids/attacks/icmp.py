import time
from collections import defaultdict, deque

from scapy.all import IP, ICMP

from src.ids.cmds import block_ip
from src.logs import logger
from ids.check_ip import check_ip
import src.ids.base as ids_base

icmp_packets = defaultdict(deque)
last_reset = time.time()
learning_phase = True

threshold_pps = 8.0
min_pps = 4.0
max_pps = 25.0
learning_k = 2.5
adaptive_k = 2.8
WINDOW = 5.0


def prune_queue(q: deque, now: float, window: float) -> None:
    while q and now - q[0] > window:
        q.popleft()


def attack(pkt):
    global last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        for q in icmp_packets.values():
            prune_queue(q, now, WINDOW)

        total = sum(len(q) for q in icmp_packets.values())
        avg_pps = total / WINDOW if WINDOW > 0 else 0.0

        if learning_phase and icmp_packets:
            threshold_pps = max(min_pps, min(max_pps, avg_pps * learning_k))
            logger.info(f"[ADAPTATION] Training completed. New threshold: {threshold_pps:.1f} packets/sec")
            learning_phase = False
        else:
            threshold_pps = max(min_pps, min(max_pps, avg_pps * adaptive_k))
            logger.info(f"[ADAPTATION] New threshold: {threshold_pps:.1f} packets/sec")

        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        ICMP in pkt and
        pkt[ICMP].type == 8):

        src_ip = pkt[IP].src

        icmp_packets[src_ip].append(now)

        prune_queue(icmp_packets[src_ip], now, WINDOW)

        current_pps = len(icmp_packets[src_ip]) / WINDOW

        logger.info(f"[PING] {src_ip=}, rate={current_pps:.1f} pps")

        if current_pps > threshold_pps:
            status, asn = check_ip(src_ip)
            if not status:
                logger.info(f"[ATTACK] ICMP-FLOOD from {src_ip} | "
                            f"Rate: {current_pps:.1f} pps | Threshold: {threshold_pps:.1f} pps")

                block_ip(src_ip)
                icmp_packets[src_ip].clear()
