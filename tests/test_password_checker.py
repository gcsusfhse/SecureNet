"""
Unit tests for password_checker.py

Run with:
    python -m pytest tests/
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from password_checker import analyze_password, _calculate_entropy, _has_sequential_chars, _has_repeated_chars


def test_weak_password_is_flagged():
    report = analyze_password("123456")
    assert report["strength_label"] == "Very Weak"
    assert report["score"] == 0
    assert len(report["issues"]) > 0


def test_common_password_detected():
    report = analyze_password("password")
    assert any("commonly used" in issue for issue in report["issues"])


def test_strong_password_scores_high():
    report = analyze_password("Tr0ub4dor&3xample!")
    assert report["score"] >= 3
    assert report["strength_label"] in ("Strong", "Very Strong")


def test_entropy_increases_with_length():
    short_entropy = _calculate_entropy("Ab1!")
    long_entropy = _calculate_entropy("Ab1!Ab1!Ab1!")
    assert long_entropy > short_entropy


def test_sequential_detection():
    assert _has_sequential_chars("abc123") is True
    assert _has_sequential_chars("xk9$mQ") is False


def test_repeated_char_detection():
    assert _has_repeated_chars("aaa123") is True
    assert _has_repeated_chars("abc123") is False


def test_no_issues_for_strong_password():
    report = analyze_password("Zq7#vLp9$kR2!wXe")
    assert report["issues"] == []
