"""
wordlist_generator.py — Custom Targeted Wordlist Generator

Accepts user-specific personal information and generates a targeted wordlist
using permutations, leet-speak transformations, and common password patterns.
"""

from __future__ import annotations

import itertools
import os
import re
from typing import Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEET_TABLE: dict[str, list[str]] = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "b": ["b", "8"],
    "g": ["g", "6"],
    "l": ["l", "1"],
    "z": ["z", "2"],
}

COMMON_SUFFIXES: list[str] = [
    "", "1", "12", "123", "1234", "12345",
    "!", "!!", "123!", "@",
]

COMMON_YEARS: list[str] = [str(y) for y in range(1970, 2026)]

COMMON_PATTERNS: list[str] = [
    "{word}",
    "{word}{word}",
    "{word}123",
    "{word}1234",
    "{word}!",
    "{word}@{year}",
    "{word}{year}",
    "{word}#{year}",
    "{Word}",
    "{WORD}",
    "{Word}123",
    "{Word}!",
    "{Word}@{year}",
    "{Word}{year}",
]

# Maximum total entries to avoid runaway generation
MAX_WORDLIST_SIZE = 100_000


# ---------------------------------------------------------------------------
# Leet transformations
# ---------------------------------------------------------------------------

def _leet_variants(word: str, max_variants: int = 64) -> list[str]:
    """
    Return a list of leet-speak variants of *word*.

    Only the first character of each leet-able character is transformed at
    each step to keep the variant count manageable.
    """
    word = word.lower()
    replaceable_positions = [
        (i, LEET_TABLE[ch])
        for i, ch in enumerate(word)
        if ch in LEET_TABLE
    ]

    if not replaceable_positions:
        return [word]

    # Limit to first 5 positions to keep combinations reasonable
    replaceable_positions = replaceable_positions[:5]

    # Build cartesian product of choices for each position
    choices = [choices for _, choices in replaceable_positions]
    variants: set[str] = set()
    for combo in itertools.islice(itertools.product(*choices), max_variants):
        chars = list(word)
        for (pos, _), replacement in zip(replaceable_positions, combo):
            chars[pos] = replacement
        variants.add("".join(chars))

    return list(variants)


# ---------------------------------------------------------------------------
# Combination helpers
# ---------------------------------------------------------------------------

def _apply_pattern(pattern: str, word: str, year: str) -> str:
    return (
        pattern
        .replace("{word}", word.lower())
        .replace("{Word}", word.capitalize())
        .replace("{WORD}", word.upper())
        .replace("{year}", year)
    )


def _generate_from_tokens(tokens: list[str]) -> Iterable[str]:
    """Yield raw password candidates from a list of base tokens."""
    seen: set[str] = set()

    def emit(candidate: str) -> Iterable[str]:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

    for token in tokens:
        # --- plain forms ---
        yield from emit(token.lower())
        yield from emit(token.upper())
        yield from emit(token.capitalize())

        # --- with common suffixes ---
        for suffix in COMMON_SUFFIXES:
            yield from emit(token.lower() + suffix)
            yield from emit(token.capitalize() + suffix)

        # --- with years ---
        for year in COMMON_YEARS:
            yield from emit(token.lower() + year)
            yield from emit(token.capitalize() + year)

        # --- pattern-based ---
        for pattern in COMMON_PATTERNS:
            for year in ["2020", "2021", "2022", "2023", "2024", "2025"]:
                yield from emit(_apply_pattern(pattern, token, year))

        # --- leet variants ---
        for leet in _leet_variants(token.lower()):
            yield from emit(leet)
            for suffix in ["", "1", "123", "!"]:
                yield from emit(leet + suffix)

    # --- two-token combinations (first 4 tokens × first 4 tokens) ---
    short_tokens = tokens[:4]
    for t1, t2 in itertools.permutations(short_tokens, 2):
        if t1 != t2:
            yield from emit(t1.lower() + t2.lower())
            yield from emit(t1.capitalize() + t2.capitalize())
            yield from emit(t1.lower() + t2.lower() + "123")
            yield from emit(t1.capitalize() + t2.lower() + "!")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_wordlist(
    name: str | None = None,
    surname: str | None = None,
    date_of_birth: str | None = None,
    pet_name: str | None = None,
    city: str | None = None,
    keywords: list[str] | None = None,
    extra_tokens: list[str] | None = None,
) -> list[str]:
    """
    Generate a targeted wordlist from user-specific personal information.

    Parameters
    ----------
    name          : First name of the target user.
    surname       : Last / family name.
    date_of_birth : DOB string (e.g. "01011990", "1990", "19900101").
    pet_name      : Name of a pet.
    city          : City or place name.
    keywords      : Additional keywords (company name, favourite team…).
    extra_tokens  : Any other tokens to include.

    Returns
    -------
    A deduplicated list of password candidates (up to MAX_WORDLIST_SIZE).
    """
    tokens: list[str] = []

    for value in [name, surname, pet_name, city]:
        if value:
            tokens.append(value.strip())

    # Extract numeric components from DOB
    if date_of_birth:
        dob_clean = re.sub(r"[^0-9]", "", date_of_birth)
        if dob_clean:
            tokens.append(dob_clean)
            # year portion (last 4 or first 4 digits if looks like a year)
            if len(dob_clean) >= 4:
                tokens.append(dob_clean[-4:])  # year at end e.g. DDMMYYYY
                tokens.append(dob_clean[:4])   # year at start e.g. YYYYMMDD

    if keywords:
        for kw in keywords:
            if kw:
                tokens.append(kw.strip())

    if extra_tokens:
        for t in extra_tokens:
            if t:
                tokens.append(t.strip())

    if not tokens:
        raise ValueError("At least one personal-information field must be provided.")

    # Deduplicate while preserving order
    seen_tokens: set[str] = set()
    unique_tokens: list[str] = []
    for t in tokens:
        if t.lower() not in seen_tokens:
            seen_tokens.add(t.lower())
            unique_tokens.append(t)

    wordlist: list[str] = []
    for candidate in _generate_from_tokens(unique_tokens):
        wordlist.append(candidate)
        if len(wordlist) >= MAX_WORDLIST_SIZE:
            break

    return wordlist


def export_wordlist(wordlist: list[str], output_path: str) -> int:
    """
    Write *wordlist* to a plain-text file at *output_path* (one entry per line).

    Returns the number of entries written.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        for entry in wordlist:
            fh.write(entry + "\n")
    return len(wordlist)


def print_wordlist_summary(wordlist: list[str], output_path: str | None = None) -> None:
    """Print a brief summary of the generated wordlist."""
    print("=" * 60)
    print("  Wordlist Generation Summary")
    print("=" * 60)
    print(f"  Total candidates : {len(wordlist):,}")
    if output_path:
        print(f"  Saved to         : {output_path}")
    if wordlist:
        print(f"  First 10 entries :")
        for entry in wordlist[:10]:
            print(f"    {entry}")
    print("=" * 60)
