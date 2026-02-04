import asyncio
import signal
from scapy.all import IP, AsyncSniffer

from src.config import settings, check_config
from src.database import init_db
from src.logs import logger
from src.ids.attacks import icmp, syn, udp

import src.ids.base as ids_base

stop_event = asyncio.Event()
init_db()


def pkt_handler(pkt):
    if IP in pkt and pkt[IP].src in ids_base.blocked_ips: return

    syn.attack(pkt)
    icmp.attack(pkt)
    udp.attack(pkt)


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
