"""
analyzer.py — Password Strength Analyzer

Combines zxcvbn scoring with custom pattern-detection heuristics to produce
a detailed strength report for a given password.
"""

import math
import re
import string
from typing import Any

try:
    from zxcvbn import zxcvbn
    _ZXCVBN_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ZXCVBN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEET_MAP: dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "6": "g",
}

COMMON_SUBSTITUTIONS: dict[str, list[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "b": ["8"],
    "g": ["6"],
}

YEAR_PATTERN = re.compile(r"(19[0-9]{2}|20[0-9]{2})")
SEQUENTIAL_THRESHOLD = 4   # run length to flag sequential chars
REPEATED_THRESHOLD = 3     # run length to flag repeated chars


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy_bits(password: str) -> float:
    """Shannon entropy of the password character set × length."""
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def _has_sequential_chars(password: str, threshold: int = SEQUENTIAL_THRESHOLD) -> bool:
    """Return True if the password contains a sequential char run >= threshold."""
    lower = password.lower()
    run = 1
    for i in range(1, len(lower)):
        diff = ord(lower[i]) - ord(lower[i - 1])
        if diff == 1:
            run += 1
            if run >= threshold:
                return True
        else:
            run = 1
    return False


def _has_sequential_keyboard(password: str, threshold: int = SEQUENTIAL_THRESHOLD) -> bool:
    """Return True if password contains a keyboard-row sequential run >= threshold."""
    rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
    ]
    lower = password.lower()
    for row in rows:
        run = 1
        for i in range(1, len(lower)):
            if lower[i] in row and lower[i - 1] in row:
                ri_curr = row.index(lower[i])
                ri_prev = row.index(lower[i - 1])
                if abs(ri_curr - ri_prev) == 1:
                    run += 1
                    if run >= threshold:
                        return True
                else:
                    run = 1
            else:
                run = 1
    return False


def _has_repeated_chars(password: str, threshold: int = REPEATED_THRESHOLD) -> bool:
    """Return True if the password contains a repeated char run >= threshold."""
    run = 1
    for i in range(1, len(password)):
        if password[i].lower() == password[i - 1].lower():
            run += 1
            if run >= threshold:
                return True
        else:
            run = 1
    return False


def _has_leet_pattern(password: str) -> bool:
    """Return True if the password contains common leet substitutions."""
    return any(ch in LEET_MAP for ch in password)


def _has_year_pattern(password: str) -> bool:
    """Return True if the password contains a 4-digit year (1900–2029)."""
    return bool(YEAR_PATTERN.search(password))


def _common_password_structures(password: str) -> list[str]:
    """Identify common structural patterns in the password."""
    found: list[str] = []
    lower = password.lower()

    if re.fullmatch(r"[a-zA-Z]+[0-9]+", password):
        found.append("word+digits")
    if re.fullmatch(r"[0-9]+[a-zA-Z]+", password):
        found.append("digits+word")
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}]$", password):
        found.append("special_char_suffix")
    if re.match(r"^[A-Z][a-z]+", password):
        found.append("capitalized_word")
    if _has_year_pattern(password):
        found.append("contains_year")
    if lower.startswith(lower[0] * len(lower)):
        found.append("all_same_char")

    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_password(password: str, user_inputs: list[str] | None = None) -> dict[str, Any]:
    """
    Analyze a password and return a comprehensive report dictionary.

    Parameters
    ----------
    password    : The password string to analyze.
    user_inputs : Optional list of user-specific strings (name, city …) passed
                  to zxcvbn to improve dictionary matching.

    Returns
    -------
    dict with keys:
        password, length, entropy_bits, score (0-4), strength_label,
        crack_time_display, patterns_detected, suggestions, zxcvbn_result
    """
    if user_inputs is None:
        user_inputs = []

    # --- zxcvbn ---
    zxcvbn_result: dict[str, Any] = {}
    score = 0
    crack_time_display = "unknown"
    suggestions: list[str] = []

    if _ZXCVBN_AVAILABLE:
        zxcvbn_result = zxcvbn(password, user_inputs=user_inputs)
        score = zxcvbn_result.get("score", 0)
        crack_time_display = (
            zxcvbn_result.get("crack_times_display", {})
            .get("offline_slow_hashing_1e4_per_second", "unknown")
        )
        suggestions = zxcvbn_result.get("feedback", {}).get("suggestions", [])

    # --- custom heuristics ---
    patterns: list[str] = []
    if _has_sequential_chars(password):
        patterns.append("sequential_alphabetic_chars")
    if _has_sequential_keyboard(password):
        patterns.append("sequential_keyboard_chars")
    if _has_repeated_chars(password):
        patterns.append("repeated_chars")
    if _has_leet_pattern(password):
        patterns.append("leet_substitutions")
    if _has_year_pattern(password):
        patterns.append("year_pattern")
    patterns.extend(_common_password_structures(password))

    # --- custom suggestions ---
    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add special characters (!@#$%…).")
    if "repeated_chars" in patterns:
        suggestions.append("Avoid repeated characters (e.g. 'aaa').")
    if "sequential_alphabetic_chars" in patterns or "sequential_keyboard_chars" in patterns:
        suggestions.append("Avoid sequential character runs (e.g. 'abcd', 'qwer').")
    if "year_pattern" in patterns:
        suggestions.append("Avoid embedding years in your password.")

    strength_labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    strength_label = strength_labels[score]

    return {
        "password": password,
        "length": len(password),
        "entropy_bits": round(_entropy_bits(password), 2),
        "score": score,
        "strength_label": strength_label,
        "crack_time_display": crack_time_display,
        "patterns_detected": list(dict.fromkeys(patterns)),  # deduplicate, preserve order
        "suggestions": list(dict.fromkeys(suggestions)),
        "zxcvbn_result": zxcvbn_result,
    }


def print_analysis(result: dict[str, Any]) -> None:
    """Pretty-print an analysis result to stdout."""
    sep = "=" * 60
    print(sep)
    print(f"  Password Analysis Report")
    print(sep)
    print(f"  Password         : {'*' * len(result['password'])}")
    print(f"  Length           : {result['length']}")
    print(f"  Entropy (bits)   : {result['entropy_bits']}")
    print(f"  Strength Score   : {result['score']} / 4  ({result['strength_label']})")
    print(f"  Est. Crack Time  : {result['crack_time_display']}")

    if result["patterns_detected"]:
        print("\n  Patterns Detected:")
        for p in result["patterns_detected"]:
            print(f"    • {p}")

    if result["suggestions"]:
        print("\n  Suggestions:")
        for s in result["suggestions"]:
            print(f"    → {s}")

    print(sep)
