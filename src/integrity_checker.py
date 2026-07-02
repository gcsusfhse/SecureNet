"""
integrity_checker.py
---------------------
File Integrity Checker using SHA-256 hashing.

Generates and verifies checksums for files or entire directories so
users can detect unauthorized modification -- a core concept in File
Integrity Monitoring (FIM), used by tools like Tripwire and OSSEC.

Author: SecureNet Guardian Team
"""

import hashlib
import os

from utils import print_info, print_success, print_warning, print_error, timestamp

CHUNK_SIZE = 65536  # 64 KB, read in chunks to handle large files safely


def calculate_sha256(filepath):
    """Calculate the SHA-256 checksum of a single file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        print_error(f"Could not hash {filepath}: {exc}")
        return None


def generate_baseline(target_path):
    """
    Generate a baseline dictionary of {filepath: sha256_hash} for a
    single file or every file within a directory (recursively).

    Returns:
        dict[str, str]
    """
    baseline = {}

    if os.path.isfile(target_path):
        file_hash = calculate_sha256(target_path)
        if file_hash:
            baseline[target_path] = file_hash
        return baseline

    print_info(f"Building integrity baseline for directory: {target_path}")
    for root, _dirs, files in os.walk(target_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            file_hash = calculate_sha256(full_path)
            if file_hash:
                baseline[full_path] = file_hash

    print_success(f"Baseline created for {len(baseline)} file(s).")
    return baseline


def verify_baseline(baseline):
    """
    Re-hash every file recorded in a baseline and compare it against
    the stored hash.

    Returns:
        dict: {
            "unchanged": [...],
            "modified": [...],
            "missing": [...],
            "checked_at": str,
        }
    """
    unchanged, modified, missing = [], [], []

    for filepath, original_hash in baseline.items():
        if not os.path.exists(filepath):
            missing.append(filepath)
            print_error(f"MISSING: {filepath}")
            continue

        current_hash = calculate_sha256(filepath)
        if current_hash == original_hash:
            unchanged.append(filepath)
        else:
            modified.append(filepath)
            print_warning(f"MODIFIED: {filepath}")

    if not modified and not missing:
        print_success("Integrity check passed -- no changes detected.")

    return {
        "unchanged": unchanged,
        "modified": modified,
        "missing": missing,
        "checked_at": timestamp(),
    }


if __name__ == "__main__":
    import sys
    import json

    path_arg = sys.argv[1] if len(sys.argv) > 1 else "."
    result_baseline = generate_baseline(path_arg)
    print(json.dumps(result_baseline, indent=2))
