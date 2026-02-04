from time import time
from collections import defaultdict

from scapy.all import IP, UDP

from src.config import settings
from src.ids.cmds import block_ip
from src.logs import logger
import src.ids.base as ids_base

last_reset = time()
counter = defaultdict(int)

def attack(pkt):
    global last_reset
    now = time()

    t_delta = now - last_reset
    if t_delta > settings.window:
        for src_ip, packets_cnt in counter.items():
            if packets_cnt > settings.m_udp * t_delta:
                logger.info(f"[ATTACK] UDP-FLOOD: {src_ip=}, {packets_cnt=}")
                block_ip(src_ip)
                ids_base.blocked_ips.add(src_ip)
        
        counter.clear()
        last_reset = now
    

    if UDP in pkt and IP in pkt and pkt[IP].dst == ids_base.HOST_IP:
        src_ip = pkt[IP].src
        dst_port = pkt[UDP].dport
        counter[src_ip] += 1
        logger.info(f"[UDP] {src_ip=}, {dst_port=}")
