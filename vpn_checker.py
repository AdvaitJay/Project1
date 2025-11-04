import os, json, ipaddress, requests
from functools import lru_cache

VPNAPI_KEY = os.getenv("VPNAPI_IO_KEY", "").strip()
IPSET_PATH = os.getenv("IPSET_DATA_PATH", "").strip()

def _load_ipset(path):
    nets = []
    if not path or not os.path.exists(path):
        return nets
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            items = []
            for v in data.values():
                if isinstance(v, list): items += v
            items = [x for x in items if isinstance(x, str)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, str)]
        else:
            items = []
    except Exception:
        with open(path, "r") as f:
            items = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    for s in items:
        try:
            if "/" in s:
                nets.append(ipaddress.ip_network(s, strict=False))
            else:
                ip = ipaddress.ip_address(s)
                nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
        except Exception:
            continue
    return nets

_NETS = _load_ipset(IPSET_PATH)

@lru_cache(maxsize=2048)
def _vpnapi_lookup(ip):
    if not VPNAPI_KEY:
        return None
    try:
        r = requests.get(f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}", timeout=5)
        if r.status_code != 200:
            return None
        sec = r.json().get("security", {})
        return bool(sec.get("vpn") or sec.get("proxy") or sec.get("tor"))
    except Exception:
        return None

def is_vpn(ip: str) -> bool:
    # offline first
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in _NETS:
            if ip_obj in net:
                return True
    except Exception:
        pass
    # online fallback
    v = _vpnapi_lookup(ip)
    return bool(v)