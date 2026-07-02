"""
Unit tests for scanner.py

Run with:
    python -m pytest tests/
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner import scan_port, scan_ports, basic_vulnerability_check, RISKY_SERVICES


def _start_dummy_server():
    """Start a temporary TCP server on an ephemeral port for testing."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_loop():
        try:
            server.settimeout(3)
            conn, _ = server.accept()
            conn.close()
        except socket.timeout:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    time.sleep(0.1)
    return port


def test_open_port_detected():
    port = _start_dummy_server()
    assert scan_port("127.0.0.1", port) is True


def test_closed_port_not_detected():
    # Port 1 is virtually never open on a test machine without root services
    assert scan_port("127.0.0.1", 1, timeout=0.3) is False


def test_scan_ports_returns_list_of_dicts():
    port = _start_dummy_server()
    results = scan_ports("127.0.0.1", ports=[port], timeout=0.5)
    assert isinstance(results, list)
    assert results[0]["port"] == port


def test_basic_vulnerability_check_flags_risky_ports():
    fake_results = [
        {"host": "127.0.0.1", "port": 23, "service": "Telnet", "risk_note": RISKY_SERVICES[23]},
        {"host": "127.0.0.1", "port": 22, "service": "SSH", "risk_note": "No common issues flagged."},
    ]
    findings = basic_vulnerability_check(fake_results)
    assert len(findings) == 1
    assert findings[0]["port"] == 23
