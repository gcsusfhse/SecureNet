"""
utils.py
--------
Shared utility functions used across the SecureNet Guardian toolkit.

This module centralizes common helpers such as console styling,
timestamp generation, IP/CIDR validation, and file path helpers so
that individual modules stay focused on their core responsibility.

Author: SecureNet Guardian Team
"""

import ipaddress
import os
import sys
import json
import csv
from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:  # pragma: no cover - colorama is a listed dependency
    COLOR_ENABLED = False


# ---------------------------------------------------------------------------
# Console output helpers
# ---------------------------------------------------------------------------

def print_banner():
    """Print the SecureNet Guardian ASCII banner to the console."""
    banner = r"""
  ____                       _   _      _    ____                     _ _
 / ___|  ___  ___ _   _ _ __| \ | | ___| |_ / ___|_   _  __ _ _ __ __| (_) __ _ _ __
 \___ \ / _ \/ __| | | | '__|  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` | |/ _` | '_ \
  ___) |  __/ (__| |_| | |  | |\  |  __/ |_| |_| | |_| | (_| | | | (_| | | (_| | | | |
 |____/ \___|\___|\__,_|_|  |_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|

            Network Security Assessment Toolkit  |  v1.0.0
    """
    print(_color(banner, "cyan"))


def _color(text, color):
    """Return colorized text if colorama is available, else plain text."""
    if not COLOR_ENABLED:
        return text
    colors = {
        "cyan": Fore.CYAN,
        "green": Fore.GREEN,
        "red": Fore.RED,
        "yellow": Fore.YELLOW,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def print_success(message):
    print(_color(f"[+] {message}", "green"))


def print_error(message):
    print(_color(f"[-] {message}", "red"))


def print_info(message):
    print(_color(f"[*] {message}", "blue"))


def print_warning(message):
    print(_color(f"[!] {message}", "yellow"))


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def is_valid_ip(ip_str):
    """Return True if ip_str is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_network(cidr_str):
    """Return True if cidr_str is a valid IPv4/IPv6 network in CIDR form."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def is_private_target(target):
    """
    Best-effort check that a target IP belongs to a private / loopback
    range. Used to nudge users toward scanning only networks they own
    or are authorized to test.
    """
    try:
        ip_obj = ipaddress.ip_address(target)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        # Hostnames can't be range-checked here; resolution happens
        # elsewhere. Default to True so hostnames are not blocked.
        return True


# ---------------------------------------------------------------------------
# Timestamp / file helpers
# ---------------------------------------------------------------------------

def timestamp():
    """Return the current time formatted for logs and reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_timestamp():
    """Return a filesystem-safe timestamp for output filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path):
    """Create a directory if it does not already exist."""
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def export_to_csv(data, filepath, fieldnames=None):
    """
    Export a list of dictionaries to a CSV file.

    Args:
        data (list[dict]): Rows to export.
        filepath (str): Destination CSV path.
        fieldnames (list[str], optional): Column order. Inferred from
            the first row if not supplied.
    """
    if not data:
        print_warning("No data available to export to CSV.")
        return False

    fieldnames = fieldnames or list(data[0].keys())
    ensure_dir(os.path.dirname(filepath) or ".")

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print_success(f"Results exported to CSV: {filepath}")
    return True


def export_to_json(data, filepath):
    """Export a Python object to a formatted JSON file."""
    ensure_dir(os.path.dirname(filepath) or ".")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=str)
    print_success(f"Results exported to JSON: {filepath}")
    return True


def load_json(filepath):
    """Load and return JSON data from a file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)
