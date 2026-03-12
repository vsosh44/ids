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

threshold_pps = settings.tcp_min_m


def attack(pkt):
    global packets, last_reset, threshold_pps, learning_phase

    now = time.time()

    if now - last_reset > 30:
        learning_phase, threshold_pps = ids_base.update_thresholds(
            packets,
            now,
            learning_phase,
            settings.tcp_min_m, settings.tcp_max_m,
            settings.tcp_k
        )
        last_reset = now

    if (IP in pkt and
        pkt[IP].dst == ids_base.HOST_IP and
        pkt[IP].src not in blocked_ips and
        len(bytes(pkt[TCP].payload)) > 0 and
        TCP in pkt and (
            pkt[TCP].type == 0x10 or
            pkt[TCP].type == 0x18
        )):

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        packets[src_ip].append(now)
        packets, current_pps, avg_pps = ids_base.get_pps(packets, src_ip, now, settings.window)

        logger.debug(
            f"[TCP] src={src_ip}, dport={dst_port}, flags={"ACK" if pkt[TCP].flags == 0x10 else "PSH+ACK"}, "
            f"rate={current_pps:.1f} pps, avg={avg_pps:.1f} pps, thr={threshold_pps:.1f} pps"
        )

        if not learning_phase and current_pps > threshold_pps and current_pps > avg_pps * 3:
            status, asn = check_ip(src_ip)
            if not status:
                logger.warning(
                    f"[ATTACK] TCP-FLOOD from {src_ip} to port {dst_port} | "
                    f"rate={current_pps:.1f} pps | threshold={threshold_pps:.1f} pps | asn={asn}"
                )

                block_ip(src_ip)
                blocked_ips.add(src_ip)
                packets[src_ip].clear()
