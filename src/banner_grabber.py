"""
banner_grabber.py
------------------
Connects to open TCP ports and reads the service banner (if any) that
the remote service voluntarily sends. This is a passive, read-only
technique widely used in legitimate security assessments to identify
running software and versions.

No packets are crafted to trigger unintended behavior; the module
simply opens a socket and reads whatever the service sends back.

Author: SecureNet Guardian Team
"""

import socket

from utils import print_info, print_success, print_warning, timestamp


def grab_banner(host, port, timeout=1.5, read_bytes=1024):
    """
    Attempt to read a service banner from an open port.

    Args:
        host (str): Target hostname or IP.
        port (int): Target TCP port.
        timeout (float): Socket timeout in seconds.
        read_bytes (int): Maximum bytes to read from the socket.

    Returns:
        str | None: The decoded banner text, or None if unavailable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Some services (like HTTP) require a request before they reply
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())

            banner = sock.recv(read_bytes)
            return banner.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def grab_banners_for_ports(host, open_ports):
    """
    Grab banners for a list of open ports (as produced by scanner.scan_ports).

    Args:
        host (str): Target hostname or IP.
        open_ports (list[dict]): Entries containing at least a "port" key.

    Returns:
        list[dict]: Each entry enriched with a "banner" field.
    """
    print_info(f"Attempting banner grab on {len(open_ports)} open port(s)...")
    results = []

    for entry in open_ports:
        port = entry["port"]
        banner = grab_banner(host, port)

        if banner:
            print_success(f"Port {port}: banner captured ({len(banner)} chars)")
        else:
            print_warning(f"Port {port}: no banner received")

        results.append(
            {
                **entry,
                "banner": banner or "No banner received",
                "grabbed_at": timestamp(),
            }
        )

    return results


if __name__ == "__main__":
    import sys

    host_arg = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    result = grab_banner(host_arg, port_arg)
    print(result or "No banner received.")
