import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Alt"
}

def check_port(target, port, timeout=1.0):
    """Attempt a TCP connection to a given port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown Service")
                return {"port": port, "status": "OPEN", "service": service}
    except Exception:
        pass
    return None

def scan_target_ports(target, ports=None, max_threads=20):
    """Scan a target IP or hostname across specified ports concurrently."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    print(f"[*] Scanning {target} across {len(ports)} ports...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_port, target, port) for port in ports]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)

    return open_ports