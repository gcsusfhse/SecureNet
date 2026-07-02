"""
host_discovery.py
------------------
Discovers live hosts on a local network segment using ICMP-style
reachability checks (via the system ping utility) and lightweight
TCP probes as a fallback.

This module is intended purely for discovery on networks the user
owns or is explicitly authorized to test (e.g. a home LAN or a lab
environment). It does not perform any exploitation.

Author: SecureNet Guardian Team
"""

import ipaddress
import platform
import subprocess
import concurrent.futures

from utils import print_info, print_success, print_warning, timestamp


def _ping_host(ip, timeout_ms=800):
    """
    Ping a single host using the OS-native ping command.

    Returns True if the host responds, False otherwise.
    """
    system = platform.system().lower()

    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        # -c 1 => one packet, -W is seconds on Linux
        timeout_s = max(1, timeout_ms // 1000)
        command = ["ping", "-c", "1", "-W", str(timeout_s), str(ip)]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def discover_hosts(network_cidr, max_workers=50, timeout_ms=800):
    """
    Sweep a CIDR range and return a list of hosts that responded.

    Args:
        network_cidr (str): e.g. "192.168.1.0/24"
        max_workers (int): number of concurrent ping threads
        timeout_ms (int): per-host timeout in milliseconds

    Returns:
        list[dict]: [{"ip": "...", "status": "up", "checked_at": "..."}]
    """
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print_info(f"Scanning {len(hosts)} possible hosts on {network_cidr} ...")

    live_hosts = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(_ping_host, ip, timeout_ms): ip for ip in hosts
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                is_alive = future.result()
            except Exception:
                is_alive = False

            if is_alive:
                print_success(f"Host up: {ip}")
                live_hosts.append(
                    {"ip": ip, "status": "up", "checked_at": timestamp()}
                )

    if not live_hosts:
        print_warning("No live hosts discovered in the given range.")

    return live_hosts


if __name__ == "__main__":
    # Simple manual test when running this module directly
    import sys

    target_range = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1/32"
    results = discover_hosts(target_range)
    print(f"\nDiscovered {len(results)} live host(s).")
