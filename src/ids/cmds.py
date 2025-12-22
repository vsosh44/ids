from subprocess import Popen, PIPE

from src.database import add_ip, remove_ip
from src.config import settings
from src.cmd_utils import run_cmd


def block_ip(ip: str) -> bool:
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    run_cmd(cmd)
    
    if settings.block_output:
        cmd = f"iptables -A OUTPUT -s {ip} -j DROP"
        run_cmd(cmd)

    add_ip(ip)
    return True


def unblock_ip(ip: str) -> bool:
    cmd = f"iptables -D INPUT -s {ip} -j DROP"
    run_cmd(cmd)

    cmd = f"iptables -D OUTPUT -s {ip} -j DROP"
    run_cmd(cmd)

    remove_ip(ip)
    return True


def get_host_ip() -> str:
    cmd = "hostname -I"
    _, out, _ = run_cmd(cmd)
    return out.strip()
