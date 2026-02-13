import time
from collections import defaultdict, deque

from scapy.all import IP, TCP

from src.ids.cmds import block_ip
from src.logs import logger
from src.ids.check_ip import check_ip
import src.ids.base as ids_base

syn_packets = defaultdict(deque)
last_reset = time.time()
learning_phase = True
threshold_pps = 12.0
WINDOW = 5.0


def prune_queue(q: deque, now: float, window: float) -> None:
    while q and now - q[0] > window:
        q.popleft()


def attack(pkt):
    global last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        for q in syn_packets.values():
            prune_queue(q, now, WINDOW)

        total = sum(len(q) for q in syn_packets.values())
        avg_pps = total / WINDOW if WINDOW > 0 else 0.0

        if learning_phase and syn_packets:
            threshold_pps = max(8.0, min(50.0, avg_pps * 3.0))
            logger.info(f"[ADAPTATION] Training completed. New threshold: {threshold_pps:.1f} packets/sec")
            learning_phase = False
        else:
            threshold_pps = max(8.0, min(50.0, avg_pps * 3.2))
            logger.info(f"[ADAPTATION] New threshold: {threshold_pps:.1f} packets/sec")

        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        TCP in pkt and
        pkt[TCP].flags == 2):

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        syn_packets[src_ip].append(now)

        prune_queue(syn_packets[src_ip], now, WINDOW)

        current_pps = len(syn_packets[src_ip]) / WINDOW

        logger.info(f"[SYN] {src_ip=}, port={dst_port}, rate={current_pps:.1f} pps")

        if current_pps > threshold_pps:
            status, asn = check_ip(src_ip)
            if not status:
                logger.info(f"[ATTACK] SYN-SCAN/FLOOD from {src_ip} | "
                            f"Rate: {current_pps:.1f} pps | Threshold: {threshold_pps:.1f} pps")

                block_ip(src_ip)
                syn_packets[src_ip].clear()
