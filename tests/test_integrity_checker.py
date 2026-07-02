"""
Unit tests for integrity_checker.py

Run with:
    python -m pytest tests/
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from integrity_checker import calculate_sha256, generate_baseline, verify_baseline


def test_hash_is_deterministic():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        tmp.write("hello world")
        path = tmp.name

    try:
        hash1 = calculate_sha256(path)
        hash2 = calculate_sha256(path)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest length
    finally:
        os.remove(path)


def test_modified_file_detected():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        tmp.write("original content")
        path = tmp.name

    try:
        baseline = generate_baseline(path)

        with open(path, "w") as f:
            f.write("tampered content")

        result = verify_baseline(baseline)
        assert path in result["modified"]
        assert result["unchanged"] == []
    finally:
        os.remove(path)


def test_missing_file_detected():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        tmp.write("temp data")
        path = tmp.name

    baseline = generate_baseline(path)
    os.remove(path)

    result = verify_baseline(baseline)
    assert path in result["missing"]


def test_unchanged_file_passes():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        tmp.write("stable content")
        path = tmp.name

    try:
        baseline = generate_baseline(path)
        result = verify_baseline(baseline)
        assert path in result["unchanged"]
        assert result["modified"] == []
        assert result["missing"] == []
    finally:
        os.remove(path)
