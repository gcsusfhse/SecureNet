"""
log_analyzer.py
----------------
Parses common log file formats (auth logs, web server access logs)
and flags patterns commonly associated with security events, such as
repeated failed login attempts (possible brute force) or unusual
request bursts from a single IP address.

This is a defensive, pattern-matching analyzer intended for learning
log-analysis fundamentals -- it does not modify or delete any log
data.

Author: SecureNet Guardian Team
"""

import re
from collections import Counter, defaultdict

from utils import print_info, print_success, print_warning, timestamp

# Regex patterns for common log lines
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"(?P<method>GET|POST|PUT|DELETE|HEAD) '
    r'(?P<path>\S+).*?" (?P<status>\d{3})'
)

BRUTE_FORCE_THRESHOLD = 5  # failed attempts from same IP to flag as suspicious


def analyze_auth_log(filepath):
    """
    Analyze an SSH/auth-style log file for failed and successful logins.

    Returns:
        dict: {
            "failed_attempts_by_ip": {...},
            "successful_logins": [...],
            "suspicious_ips": [...],
            "total_lines_scanned": int,
        }
    """
    failed_by_ip = defaultdict(int)
    successful_logins = []
    total_lines = 0

    print_info(f"Analyzing auth log: {filepath}")

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1

            failed_match = FAILED_LOGIN_PATTERN.search(line)
            if failed_match:
                failed_by_ip[failed_match.group("ip")] += 1
                continue

            success_match = ACCEPTED_LOGIN_PATTERN.search(line)
            if success_match:
                successful_logins.append(
                    {
                        "user": success_match.group("user"),
                        "ip": success_match.group("ip"),
                    }
                )

    suspicious_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in failed_by_ip.items()
        if count >= BRUTE_FORCE_THRESHOLD
    ]

    if suspicious_ips:
        print_warning(f"{len(suspicious_ips)} IP(s) exceeded the brute-force threshold.")
    else:
        print_success("No brute-force patterns detected.")

    return {
        "failed_attempts_by_ip": dict(failed_by_ip),
        "successful_logins": successful_logins,
        "suspicious_ips": suspicious_ips,
        "total_lines_scanned": total_lines,
        "analyzed_at": timestamp(),
    }


def analyze_access_log(filepath, top_n=10):
    """
    Analyze a web server access log (Common/Combined Log Format style)
    and summarize request volume, status codes, and the most active
    client IP addresses.

    Returns:
        dict summary of the access log.
    """
    ip_counter = Counter()
    status_counter = Counter()
    total_lines = 0

    print_info(f"Analyzing access log: {filepath}")

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1
            match = ACCESS_LOG_PATTERN.search(line)
            if match:
                ip_counter[match.group("ip")] += 1
                status_counter[match.group("status")] += 1

    top_ips = ip_counter.most_common(top_n)
    error_rate = sum(
        count for status, count in status_counter.items() if status.startswith("4") or status.startswith("5")
    )

    if error_rate:
        print_warning(f"{error_rate} request(s) returned 4xx/5xx status codes.")

    return {
        "total_lines_scanned": total_lines,
        "top_requesting_ips": top_ips,
        "status_code_breakdown": dict(status_counter),
        "error_response_count": error_rate,
        "analyzed_at": timestamp(),
    }


if __name__ == "__main__":
    import sys
    import json

    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_outputs/sample_auth.log"
    print(json.dumps(analyze_auth_log(log_path), indent=2))
