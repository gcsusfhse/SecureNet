"""
Unit tests for log_analyzer.py

Run with:
    python -m pytest tests/
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from log_analyzer import analyze_auth_log, BRUTE_FORCE_THRESHOLD


SAMPLE_LOG = """\
Jun 28 09:12:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.55 port 51422 ssh2
Jun 28 09:12:03 host sshd[2]: Failed password for invalid user admin from 203.0.113.55 port 51423 ssh2
Jun 28 09:12:05 host sshd[3]: Failed password for invalid user root from 203.0.113.55 port 51424 ssh2
Jun 28 09:12:07 host sshd[4]: Failed password for invalid user root from 203.0.113.55 port 51425 ssh2
Jun 28 09:12:09 host sshd[5]: Failed password for invalid user test from 203.0.113.55 port 51426 ssh2
Jun 28 09:14:20 host sshd[6]: Accepted password for rishi from 192.168.1.20 port 52311 ssh2
"""


def _write_temp_log(content):
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".log")
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_failed_attempts_counted():
    path = _write_temp_log(SAMPLE_LOG)
    try:
        result = analyze_auth_log(path)
        assert result["failed_attempts_by_ip"]["203.0.113.55"] == 5
    finally:
        os.remove(path)


def test_successful_login_captured():
    path = _write_temp_log(SAMPLE_LOG)
    try:
        result = analyze_auth_log(path)
        assert {"user": "rishi", "ip": "192.168.1.20"} in result["successful_logins"]
    finally:
        os.remove(path)


def test_brute_force_threshold_flagging():
    path = _write_temp_log(SAMPLE_LOG)
    try:
        result = analyze_auth_log(path)
        suspicious_ips = [entry["ip"] for entry in result["suspicious_ips"]]
        if 5 >= BRUTE_FORCE_THRESHOLD:
            assert "203.0.113.55" in suspicious_ips
        else:
            assert "203.0.113.55" not in suspicious_ips
    finally:
        os.remove(path)
