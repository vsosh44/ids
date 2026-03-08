import requests
from functools import lru_cache
import ipaddress

TRUSTED_ASNS = {
    "AS15169",
    "AS13335",
    "AS16509",
    "AS24940",
    "AS54113",
    "AS20940",
    "AS16276",
    "AS8075",
    "AS47764",
    "AS31898"
}


@lru_cache(maxsize=1000)
def get_ip_reputation(ip: str):
    try:
        response = requests.get(f"https://api.ipapi.is/?q={ip}", timeout=6)

        if response.status_code != 200:
            return "neutral", "unknown", "unknown"

        data = response.json()

        asn_str = str(data.get("asn", {}).get("asn", ""))
        abuser_score_str = data.get("company", {}).get("abuser_score", "0")

        try:
            abuser_score = float(abuser_score_str.split()[0])
        except ValueError:
            abuser_score = 0.0

        is_abuser = data.get("is_abuser", False)
        is_proxy = data.get("is_proxy", False)
        is_vpn = data.get("is_vpn", False)
        is_tor = data.get("is_tor", False)

        if asn_str in TRUSTED_ASNS:
            return "trusted", data.get("company", {}).get("name", "unknown"), asn_str

        if is_tor or is_proxy or is_vpn:
            return "suspicious", data.get("company", {}).get("name", "unknown"), asn_str

        if is_abuser and abuser_score > 60:
            return "suspicious", data.get("company", {}).get("name", "unknown"), asn_str

        return "neutral", data.get("company", {}).get("name", "unknown"), asn_str

    except requests.exceptions.RequestException:
        return "neutral", "unknown", "unknown"


def check_ip(ip: str) -> tuple[bool, str]:
    try:
        if ipaddress.ip_address(ip).is_private:
            return False, "local"
    except ValueError:
        return False, "invalid"

    status, name, asn = get_ip_reputation(ip)
    if status == "suspicious":
        return False, asn
    return True, asn
