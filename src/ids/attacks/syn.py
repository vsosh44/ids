import time
from collections import defaultdict, deque

from scapy.all import IP, TCP

from src.ids.cmds import block_ip
from src.database import get_blocked_ips
from src.logs import logger
from src.ids.check_ip import check_ip
import src.ids.base as ids_base
from src.config import settings

packets = defaultdict(deque)
blocked_ips: set = get_blocked_ips()
last_reset = time.time()
learning_phase = True

threshold_pps = settings.syn_min_m


def attack(pkt):
    global packets, last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        learning_phase, threshold_pps = ids_base.update_thresholds(
            packets,
            now,
            learning_phase,
            settings.syn_min_m, settings.syn_max_m,
            settings.syn_k
        )

        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        pkt[IP].src not in blocked_ips and
        TCP in pkt and
        pkt[TCP].flags == 2):

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        packets[src_ip].append(now)

        packets, current_pps, avg_pps = ids_base.get_pps(packets, src_ip, now, settings.window)

        if settings.log_all:
            logger.info(f"[SYN] IP: {src_ip}, Port: {dst_port}, Rate: {current_pps:.1f} pps")

        if pkt[IP].src not in settings.ignored_ips and not learning_phase and current_pps > threshold_pps:
            status, asn = check_ip(src_ip)
            if not status:
                logger.info(
                    f"[ATTACK] SYN-SCAN from {src_ip} to port {dst_port} | "
                    f"Rate: {current_pps:.1f} pps | Threshold: {threshold_pps:.1f} pps"
                )

                block_ip(src_ip)
                blocked_ips.add(src_ip)
                packets[src_ip].clear()
