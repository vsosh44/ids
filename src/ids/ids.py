import asyncio
import signal
import os
from scapy.all import IP, AsyncSniffer

from src.database import init_db
init_db()

from src.config import check_config
from src.logs import logger
from src.ids.attacks import icmp, syn, udp
from src.ids.cmds import blocked_ips

stop_event = asyncio.Event()


def pkt_handler(pkt):
    if IP in pkt and pkt[IP].src in blocked_ips:
        return

    syn.attack(pkt)
    icmp.attack(pkt)
    udp.attack(pkt)


def draw_threshold_pps_graph() -> None:
    if not udp.threshold_pps_history:
        logger.info("No UDP threshold history to plot")
        return

    import matplotlib.pyplot as plt

    times, values = zip(*udp.threshold_pps_history)
    start_time = times[0]
    x_values = [t - start_time for t in times]

    os.makedirs("images", exist_ok=True)
    output_path = os.path.join("images", "udp_threshold_pps.png")

    plt.figure(figsize=(10, 5))
    plt.plot(x_values, values, marker="o")
    plt.title("threshold_pps over time")
    plt.xlabel("Seconds")
    plt.ylabel("threshold_pps")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

    logger.info(f"Saved threshold graph to {output_path}")


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
        draw_threshold_pps_graph()
        exit(0)
