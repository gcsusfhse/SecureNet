"""
main.py
-------
Command-line entry point for SecureNet Guardian.

Provides a unified CLI that ties together host discovery, port
scanning, banner grabbing, password analysis, file integrity
checking, log analysis, and report generation.

Usage:
    python main.py discover --network 192.168.1.0/24
    python main.py scan --host 192.168.1.10 --ports 1-1024
    python main.py banner --host 192.168.1.10 --port 22
    python main.py password
    python main.py integrity --path ./sample_outputs --baseline baseline.json
    python main.py logs --file /var/log/auth.log --type auth
    python main.py full-scan --host 192.168.1.10 --export html,csv

Author: SecureNet Guardian Team
"""

import argparse
import getpass
import sys

import host_discovery
import scanner
import banner_grabber
import password_checker
import integrity_checker
import log_analyzer
import report_generator
from utils import (
    print_banner, print_info, print_error, print_success,
    export_to_csv, export_to_json,
)


def parse_port_range(port_str):
    """Convert '1-1024' or '22,80,443' into a list of integers."""
    ports = set()
    for chunk in port_str.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(ports)


def handle_discover(args):
    results = host_discovery.discover_hosts(args.network)
    if args.export:
        export_to_csv(results, "sample_outputs/host_discovery_results.csv")
    return results


def handle_scan(args):
    ports = parse_port_range(args.ports) if args.ports else None
    results = scanner.scan_ports(args.host, ports=ports)
    scanner.basic_vulnerability_check(results)
    if args.export:
        export_to_csv(results, "sample_outputs/port_scan_results.csv")
    return results


def handle_banner(args):
    banner = banner_grabber.grab_banner(args.host, args.port)
    print_info(f"Banner: {banner or 'No banner received'}")
    return banner


def handle_password(_args):
    pwd = getpass.getpass("Enter a password to analyze (input hidden): ")
    report = password_checker.analyze_password(pwd)
    password_checker.print_report(report)
    return report


def handle_integrity(args):
    if args.verify:
        from utils import load_json
        baseline = load_json(args.baseline)
        result = integrity_checker.verify_baseline(baseline)
        export_to_json(result, "sample_outputs/integrity_verification.json")
    else:
        baseline = integrity_checker.generate_baseline(args.path)
        export_to_json(baseline, args.baseline)
        print_success(f"Baseline saved to {args.baseline}")
    return None


def handle_logs(args):
    if args.type == "access":
        result = log_analyzer.analyze_access_log(args.file)
    else:
        result = log_analyzer.analyze_auth_log(args.file)
    export_to_json(result, "sample_outputs/log_analysis_results.json")
    return result


def handle_full_scan(args):
    print_info(f"Running full assessment against {args.host} ...")
    open_ports = scanner.scan_ports(args.host)
    risky = scanner.basic_vulnerability_check(open_ports)
    enriched = banner_grabber.grab_banners_for_ports(args.host, open_ports)

    exports = (args.export or "").split(",") if args.export else []

    if "csv" in exports:
        export_to_csv(enriched, "sample_outputs/full_scan_results.csv")

    if "html" in exports or not exports:
        report_generator.generate_html_report(
            target=args.host, open_ports=enriched, risky_findings=risky
        )

    if "pdf" in exports:
        report_generator.generate_pdf_report(
            target=args.host, open_ports=enriched, risky_findings=risky
        )

    return enriched


def build_parser():
    parser = argparse.ArgumentParser(
        prog="securenet-guardian",
        description="SecureNet Guardian -- Network Security Assessment Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_p = subparsers.add_parser("discover", help="Discover live hosts on a network")
    discover_p.add_argument("--network", required=True, help="CIDR range, e.g. 192.168.1.0/24")
    discover_p.add_argument("--export", action="store_true", help="Export results to CSV")
    discover_p.set_defaults(func=handle_discover)

    scan_p = subparsers.add_parser("scan", help="Scan TCP ports on a host")
    scan_p.add_argument("--host", required=True, help="Target hostname or IP")
    scan_p.add_argument("--ports", help="Port range, e.g. 1-1024 or 22,80,443")
    scan_p.add_argument("--export", action="store_true", help="Export results to CSV")
    scan_p.set_defaults(func=handle_scan)

    banner_p = subparsers.add_parser("banner", help="Grab a service banner")
    banner_p.add_argument("--host", required=True)
    banner_p.add_argument("--port", required=True, type=int)
    banner_p.set_defaults(func=handle_banner)

    password_p = subparsers.add_parser("password", help="Analyze password strength")
    password_p.set_defaults(func=handle_password)

    integrity_p = subparsers.add_parser("integrity", help="Generate or verify a file integrity baseline")
    integrity_p.add_argument("--path", default=".", help="File or directory to baseline")
    integrity_p.add_argument("--baseline", default="baseline.json", help="Baseline JSON file path")
    integrity_p.add_argument("--verify", action="store_true", help="Verify against an existing baseline")
    integrity_p.set_defaults(func=handle_integrity)

    logs_p = subparsers.add_parser("logs", help="Analyze a log file")
    logs_p.add_argument("--file", required=True, help="Path to the log file")
    logs_p.add_argument("--type", choices=["auth", "access"], default="auth")
    logs_p.set_defaults(func=handle_logs)

    full_p = subparsers.add_parser("full-scan", help="Run a full assessment and generate a report")
    full_p.add_argument("--host", required=True)
    full_p.add_argument("--export", help="Comma-separated export formats: html,pdf,csv")
    full_p.set_defaults(func=handle_full_scan)

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print_error("Interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - top-level CLI safety net
        print_error(f"An unexpected error occurred: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
