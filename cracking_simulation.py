"""
cracking_simulation.py — Password Cracking Simulation & Tool Integration

Provides:
  1. A pure-Python brute-force simulation for offline evaluation.
  2. Wrapper helpers to invoke Hashcat or John the Ripper when they are
     available on the host machine.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
from typing import Any

# ---------------------------------------------------------------------------
# Hash utilities
# ---------------------------------------------------------------------------

SUPPORTED_HASH_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of *password* using *algorithm*."""
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(SUPPORTED_HASH_ALGORITHMS)}"
        )
    return SUPPORTED_HASH_ALGORITHMS[algorithm](password.encode()).hexdigest()


def hash_passwords(passwords: list[str], algorithm: str = "sha256") -> dict[str, str]:
    """Return a mapping of password → hash for each password in *passwords*."""
    return {p: hash_password(p, algorithm) for p in passwords}


# ---------------------------------------------------------------------------
# Pure-Python wordlist attack simulation
# ---------------------------------------------------------------------------

def simulate_wordlist_attack(
    target_hashes: dict[str, str],
    wordlist: list[str],
    algorithm: str = "sha256",
    max_attempts: int | None = None,
) -> dict[str, Any]:
    """
    Simulate a dictionary attack against *target_hashes* using *wordlist*.

    Parameters
    ----------
    target_hashes : Mapping of password → hash (the 'database' to crack).
    wordlist      : List of candidate passwords to try.
    algorithm     : Hash algorithm to use (md5, sha1, sha256, sha512).
    max_attempts  : Stop after this many attempts (None = unlimited).

    Returns
    -------
    dict with keys:
        cracked          – {password: hash} for successfully cracked entries
        attempts         – total candidates tried
        time_seconds     – elapsed wall-clock time
        success_rate     – fraction of target_hashes cracked (0.0–1.0)
        passwords_found  – list of plaintext passwords recovered
    """
    if not target_hashes:
        return {
            "cracked": {},
            "attempts": 0,
            "time_seconds": 0.0,
            "success_rate": 0.0,
            "passwords_found": [],
        }

    # Build reverse map: hash → password for fast lookup
    hash_to_password: dict[str, str] = {v: k for k, v in target_hashes.items()}
    remaining: set[str] = set(hash_to_password.keys())

    cracked: dict[str, str] = {}
    attempts = 0
    start = time.perf_counter()

    for candidate in wordlist:
        if not remaining:
            break
        if max_attempts is not None and attempts >= max_attempts:
            break

        candidate_hash = hash_password(candidate, algorithm)
        attempts += 1

        if candidate_hash in remaining:
            original_password = hash_to_password[candidate_hash]
            cracked[original_password] = candidate_hash
            remaining.discard(candidate_hash)

    elapsed = time.perf_counter() - start
    success_rate = len(cracked) / len(target_hashes) if target_hashes else 0.0

    return {
        "cracked": cracked,
        "attempts": attempts,
        "time_seconds": round(elapsed, 4),
        "success_rate": round(success_rate, 4),
        "passwords_found": list(cracked.keys()),
    }


# ---------------------------------------------------------------------------
# Hashcat integration
# ---------------------------------------------------------------------------

def _tool_available(tool_name: str) -> bool:
    """Return True if *tool_name* is found on PATH."""
    try:
        subprocess.run(
            [tool_name, "--version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_hashcat(
    hash_file: str,
    wordlist_file: str,
    hash_mode: int = 0,
    output_file: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run Hashcat in dictionary-attack mode (mode 0) against *hash_file*.

    Parameters
    ----------
    hash_file     : Path to a file containing one hash per line.
    wordlist_file : Path to the wordlist to use.
    hash_mode     : Hashcat hash-type code (0=MD5, 100=SHA1, 1400=SHA256…).
    output_file   : Optional path to write cracked results.
    extra_args    : Additional CLI arguments forwarded to hashcat.

    Returns
    -------
    dict with keys: returncode, stdout, stderr, output_file
    """
    if not _tool_available("hashcat"):
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "hashcat not found on PATH.",
            "output_file": None,
        }

    out_path = output_file
    if out_path is None:
        fd, out_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
    cmd = [
        "hashcat",
        "-m", str(hash_mode),
        "-a", "0",          # dictionary attack
        hash_file,
        wordlist_file,
        "-o", out_path,
        "--force",
        "--quiet",
    ]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_file": out_path,
    }


def run_john(
    hash_file: str,
    wordlist_file: str,
    format_flag: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run John the Ripper in wordlist mode against *hash_file*.

    Parameters
    ----------
    hash_file     : Path to a file containing hashes.
    wordlist_file : Path to the wordlist.
    format_flag   : John format string (e.g. 'Raw-MD5', 'Raw-SHA256').
    extra_args    : Additional CLI arguments forwarded to john.

    Returns
    -------
    dict with keys: returncode, stdout, stderr, cracked_passwords
    """
    if not _tool_available("john"):
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "john not found on PATH.",
            "cracked_passwords": [],
        }

    cmd = ["john", f"--wordlist={wordlist_file}", hash_file]
    if format_flag:
        cmd.append(f"--format={format_flag}")
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    # Retrieve cracked passwords with --show
    show_cmd = ["john", "--show", hash_file]
    if format_flag:
        show_cmd.append(f"--format={format_flag}")
    show_result = subprocess.run(show_cmd, capture_output=True, text=True)
    cracked: list[str] = []
    for line in show_result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            cracked.append(parts[1])

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "cracked_passwords": cracked,
    }


# ---------------------------------------------------------------------------
# Convenience: prepare hash file
# ---------------------------------------------------------------------------

def write_hash_file(hashes: list[str], path: str) -> None:
    """Write *hashes* (one per line) to *path*."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for h in hashes:
            fh.write(h + "\n")


def print_crack_result(result: dict[str, Any]) -> None:
    """Pretty-print a simulation crack result."""
    sep = "=" * 60
    print(sep)
    print("  Cracking Simulation Result")
    print(sep)
    print(f"  Attempts         : {result['attempts']:,}")
    print(f"  Time (seconds)   : {result['time_seconds']}")
    print(f"  Passwords cracked: {len(result['passwords_found'])}")
    print(f"  Success rate     : {result['success_rate'] * 100:.1f}%")
    if result["passwords_found"]:
        print("\n  Cracked passwords:")
        for p in result["passwords_found"]:
            print(f"    ✓ {p}")
    print(sep)
