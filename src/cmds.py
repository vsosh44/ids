from subprocess import Popen, PIPE
from database import add_ip, remove_ip
from config import settings

def run_cmd(cmd: str) -> tuple[int, str, str]:
    list_cmd = cmd.split()
    p = Popen(list_cmd, stdout=PIPE, stderr=PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err


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
