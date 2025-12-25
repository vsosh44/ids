import asyncio
import signal
from scapy.all import sniff, IP, TCP, ICMP, UDP, AsyncSniffer
from collections import defaultdict
import time

from src.config import settings, check_config
from src.database import init_db, get_blocked_ips
from src.ids.cmds import get_host_ip, block_ip
from src.logs import logger

stop_event = asyncio.Event()
HOST_IP = get_host_ip()
init_db()

counters = {
    'syn' : defaultdict(int),
    'icmp': defaultdict(int),
    'udp' : defaultdict(int)
}
last_reset = time.time()
blocked_ips: set = get_blocked_ips()


def pkt_handler(pkt):
    global last_reset
    now = time.time()

    if IP in pkt and pkt[IP].src in blocked_ips: return

    t_delta = now - last_reset
    if t_delta > settings.window:
        for src_ip, packets_cnt in counters['syn'].items():
            if packets_cnt > settings.m_syn * t_delta:
                logger.info(f"[ATTACK] SYN-SCAN: {src_ip=}, {packets_cnt=}")
                block_ip(src_ip)
                blocked_ips.add(src_ip)

        for src_ip, packets_cnt in counters['icmp'].items():
            if packets_cnt > settings.m_icmp * t_delta:
                logger.info(f"[ATTACK] ICMP-FLOOD: {src_ip=}, {packets_cnt=}")
                block_ip(src_ip)
                blocked_ips.add(src_ip)

        for src_ip, packets_cnt in counters['udp'].items():
            if packets_cnt > settings.m_udp * t_delta:
                logger.info(f"[ATTACK] UDP-FLOOD: {src_ip=}, {packets_cnt=}")
                block_ip(src_ip)
                blocked_ips.add(src_ip)

        counters['syn'].clear()
        counters['icmp'].clear()
        counters['udp'].clear()
        last_reset = now


    if (IP in pkt and pkt[IP].dst == HOST_IP and TCP in pkt and pkt[TCP].flags == 2):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        counters['syn'][src_ip] += 1
        logger.info(f"[SYN] {src_ip=}, {dst_port=}")

    if (IP in pkt and pkt[IP].dst == HOST_IP and ICMP in pkt and pkt[ICMP].type == 8):
        src_ip = pkt[IP].src
        counters['icmp'][src_ip] += 1
        logger.info(f"[PING] {src_ip=}")

    if UDP in pkt and IP in pkt and pkt[IP].dst == HOST_IP:
        src_ip = pkt[IP].src
        dst_port = pkt[UDP].dport
        counters['udp'][src_ip] += 1
        logger.info(f"[UDP] {src_ip=}, {dst_port=}")


async def main():
    try:
        sniffer = AsyncSniffer(iface=settings.interface, prn=pkt_handler, store=False)
    except ValueError as exc:
        if "Interface" in str(exc):
            logger.error(f"[ERROR] Interface {settings.interface} not found")
            exit(-1)
        raise

    sniffer.start()
    logger.info(f"IDS started on interface {settings.interface}")

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    loop.add_signal_handler(signal.SIGTERM, stop_event.set)

    task = asyncio.create_task(check_config())

    await stop_event.wait()

    try:
        sniffer.stop()
    except Exception:
        pass

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    asyncio.run(main())
