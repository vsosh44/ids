import socket
import platform
import subprocess
import re

from src.database import get_blocked_ips
from src.database import add_ip, remove_ip
from src.config import settings
from src.logs import logger

blocked_ips: set = get_blocked_ips()

IPV4_REGEX = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"


def block_ip_linux(ip: str) -> bool:
    blocked_ips.add(ip)

    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True, capture_output=True, check=True)
    
    if settings.block_output:
        cmd = f"iptables -A OUTPUT -s {ip} -j DROP"
        subprocess.run(cmd, shell=True, capture_output=True, check=True)
    return True


def block_ip_windows(ip: str) -> bool:
    try:
        rule_name = f"Block_{ip.replace('.', '_')}"
        cmd1 = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes'
        cmd2 = f'netsh advfirewall firewall add rule name="{rule_name}_out" dir=out action=block remoteip={ip} enable=yes'

        subprocess.run(cmd1, shell=True, capture_output=True, check=True)
        subprocess.run(cmd2, shell=True, capture_output=True, check=True)

        logger.info(f"[BLOCK] {ip} → Windows Firewall")
        return True
    except subprocess.CalledProcessError:
        pass

    try:
        cmd_route = f'route add {ip} mask 255.255.255.255 0.0.0.0 -p'
        subprocess.run(cmd_route, shell=True, capture_output=True, check=True)

        logger.info(f"[BLOCK] {ip} → Null Route (blackhole)")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip}: {e}")
        return False


def unblock_ip_linux(ip: str) -> bool:
    try:
        cmd = f"iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(cmd, shell=True, capture_output=True, check=True)

        cmd = f"iptables -D OUTPUT -s {ip} -j DROP"
        subprocess.run(cmd, shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError:
        return False
    return True


def unblock_ip_windows(ip: str) -> bool:
    try:
        subprocess.run(f'netsh advfirewall firewall delete rule name="Block_{ip.replace(".", "_")}"',
                       shell=True,
                       capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="Block_{ip.replace(".", "_")}_out"',
                       shell=True,
                       capture_output=True)

        subprocess.run(f'route delete {ip}', shell=True, capture_output=True)

        logger.info(f"[UNBLOCK] {ip}")
        return True
    except subprocess.CalledProcessError:
        return False


def block_ip(ip: str) -> bool:
    if not re.fullmatch(IPV4_REGEX, ip):
        logger.error(f"Invalid IP address: {ip}")
        return False

    remove_ip(ip)
    if platform.system() == "Linux":
        return block_ip_linux(ip)
    elif platform.system() == "Windows":
        return block_ip_windows(ip)
    return False


def unblock_ip(ip: str) -> bool:
    if not re.fullmatch(IPV4_REGEX, ip):
        logger.error(f"Invalid IP address: {ip}")
        return False

    add_ip(ip)
    if platform.system() == "Linux":
        return unblock_ip_linux(ip)
    elif platform.system() == "Windows":
        return unblock_ip_windows(ip)
    return False


def get_host_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
