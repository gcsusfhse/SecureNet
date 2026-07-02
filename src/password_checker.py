"""
password_checker.py
--------------------
Analyzes password strength using entropy estimation and common
best-practice heuristics (length, character variety, sequences,
repeated characters, and membership in a small common-password list).

This module does NOT store, transmit, or log the passwords it
analyzes anywhere other than in-memory during the current run.

Author: SecureNet Guardian Team
"""

import math
import re

from utils import print_info

# A small illustrative sample of frequently-breached passwords.
# In a production tool this would reference a much larger, external
# breach-corpus (e.g. Have I Been Pwned's k-anonymity API) rather
# than a hardcoded list.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "admin", "letmein",
    "welcome", "monkey", "iloveyou", "111111", "123123",
}

STRENGTH_LABELS = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]


def _character_pool_size(password):
    """Estimate the character pool size based on which classes are used."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approximate size of common symbol set
    return pool or 1


def _calculate_entropy(password):
    """
    Estimate password entropy in bits using:
        entropy = length * log2(pool_size)
    This is a widely used approximation for keyspace-based strength.
    """
    pool_size = _character_pool_size(password)
    return len(password) * math.log2(pool_size)


def _has_sequential_chars(password, run_length=3):
    """Detect simple ascending/descending sequences like 'abc' or '321'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def _has_repeated_chars(password, run_length=3):
    """Detect repeated-character runs like 'aaa' or '111'."""
    pattern = r"(.)\1{" + str(run_length - 1) + r",}"
    return re.search(pattern, password) is not None


def analyze_password(password):
    """
    Analyze a password and return a structured report.

    Returns:
        dict: {
            "length": int,
            "entropy_bits": float,
            "score": int (0-4),
            "strength_label": str,
            "issues": list[str],
            "suggestions": list[str],
        }
    """
    issues = []
    suggestions = []

    length = len(password)
    entropy = round(_calculate_entropy(password), 2)

    if length < 8:
        issues.append("Password is shorter than the recommended 8 characters.")
        suggestions.append("Use at least 12 characters for stronger protection.")

    if not re.search(r"[a-z]", password):
        issues.append("No lowercase letters used.")
        suggestions.append("Add lowercase letters.")

    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters used.")
        suggestions.append("Add uppercase letters.")

    if not re.search(r"[0-9]", password):
        issues.append("No digits used.")
        suggestions.append("Add at least one number.")

    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters used.")
        suggestions.append("Add symbols such as !, @, #, or $.")

    if _has_sequential_chars(password):
        issues.append("Contains a sequential character pattern (e.g. 'abc', '321').")
        suggestions.append("Avoid predictable sequences.")

    if _has_repeated_chars(password):
        issues.append("Contains repeated character runs (e.g. 'aaa').")
        suggestions.append("Avoid repeating the same character multiple times.")

    if password.lower() in COMMON_PASSWORDS:
        issues.append("Password appears in a list of commonly used/breached passwords.")
        suggestions.append("Choose a unique password not found in public breach lists.")

    # Derive a 0-4 score from entropy bits, penalized for each issue found
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    # Cap the score based on the number of concrete issues detected
    score = max(0, score - min(len(issues), score))

    return {
        "length": length,
        "entropy_bits": entropy,
        "score": score,
        "strength_label": STRENGTH_LABELS[score],
        "issues": issues,
        "suggestions": suggestions or ["Great job -- no major issues detected!"],
    }


def print_report(report):
    """Pretty-print an analyze_password() report to the console."""
    print_info(f"Length: {report['length']} characters")
    print_info(f"Estimated entropy: {report['entropy_bits']} bits")
    print_info(f"Strength: {report['strength_label']} ({report['score']}/4)")

    if report["issues"]:
        print_info("Issues found:")
        for issue in report["issues"]:
            print(f"    - {issue}")

    print_info("Suggestions:")
    for suggestion in report["suggestions"]:
        print(f"    - {suggestion}")


if __name__ == "__main__":
    import getpass

    pwd = getpass.getpass("Enter a password to analyze (input hidden): ")
    result = analyze_password(pwd)
    print_report(result)
