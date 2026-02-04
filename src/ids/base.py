from src.database import get_blocked_ips
from src.ids.cmds import get_host_ip

blocked_ips: set = get_blocked_ips()
HOST_IP = get_host_ip()
