"""
scanner.py
----------
TCP port scanner with basic, non-intrusive vulnerability checks.

The scanner only opens TCP connections to determine whether a port
is open (a standard "connect scan"). It never sends exploit payloads.
Basic vulnerability checks are limited to flagging commonly
mis-configured or legacy services (e.g. Telnet, FTP-anonymous-prone
ports) so students learn to recognize risky configurations.

Author: SecureNet Guardian Team
"""

import socket
import concurrent.futures

from utils import print_info, print_success, print_warning, timestamp

# Common ports and their typical service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}

# Services that are commonly flagged as risky in a basic security review
RISKY_SERVICES = {
    21: "FTP transmits credentials in plaintext. Prefer SFTP/FTPS.",
    23: "Telnet transmits data in plaintext. Prefer SSH.",
    445: "SMB has historically been targeted by worms (e.g. EternalBlue). "
         "Ensure it is patched and not exposed to the internet.",
    3389: "RDP exposed to the internet is a common brute-force target. "
          "Restrict access via VPN or firewall rules.",
}


def scan_port(host, port, timeout=0.5):
    """
    Attempt a TCP connection to a single port.

    Returns True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            return result == 0
        except (socket.gaierror, socket.timeout, OSError):
            return False


def scan_ports(host, ports=None, max_workers=100, timeout=0.5):
    """
    Scan a list (or range) of TCP ports on a target host.

    Args:
        host (str): Target hostname or IP address.
        ports (iterable[int], optional): Ports to scan.
            Defaults to COMMON_PORTS keys.
        max_workers (int): Concurrent scanning threads.
        timeout (float): Per-connection timeout in seconds.

    Returns:
        list[dict]: Open ports with service name and risk notes.
    """
    ports = list(ports) if ports else list(COMMON_PORTS.keys())
    print_info(f"Scanning {len(ports)} port(s) on {host} ...")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False

            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                risk_note = RISKY_SERVICES.get(port, "No common issues flagged.")
                print_success(f"Port {port}/tcp open  ({service})")
                open_ports.append(
                    {
                        "host": host,
                        "port": port,
                        "service": service,
                        "risk_note": risk_note,
                        "checked_at": timestamp(),
                    }
                )

    open_ports.sort(key=lambda item: item["port"])

    if not open_ports:
        print_warning(f"No open ports found on {host} for the scanned range.")

    return open_ports


def basic_vulnerability_check(open_ports_result):
    """
    Given the output of scan_ports(), return a filtered list of
    findings that correspond to commonly risky services.

    This is intentionally limited to educational, well-known
    configuration risks -- not an exploit database lookup.
    """
    findings = [
        entry for entry in open_ports_result if entry["port"] in RISKY_SERVICES
    ]

    if findings:
        print_warning(f"{len(findings)} potentially risky service(s) detected.")
    else:
        print_success("No commonly risky services detected among open ports.")

    return findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    results = scan_ports(target)
    basic_vulnerability_check(results)
