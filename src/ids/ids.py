import asyncio
import signal
from scapy.all import IP, AsyncSniffer

from src.database import init_db
init_db()

from src.config import check_config
from src.logs import logger
from src.ids.attacks import icmp, syn, udp, tcp
from src.ids.cmds import blocked_ips

stop_event = asyncio.Event()


def pkt_handler(pkt):
    if IP in pkt and pkt[IP].src in blocked_ips:
        return

    tcp.attack(pkt)
    syn.attack(pkt)
    icmp.attack(pkt)
    udp.attack(pkt)


async def main():
    sniffer = AsyncSniffer(prn=pkt_handler, store=False)

    sniffer.start()
    logger.info(f"IDS started")

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, stop_event.set)
    except NotImplementedError:
        pass

    task = asyncio.create_task(check_config())

    try:
        await stop_event.wait()
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("IDS stopped")
        exit(0)
