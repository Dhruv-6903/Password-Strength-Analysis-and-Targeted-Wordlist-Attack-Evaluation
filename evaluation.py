"""
evaluation.py — Experimental Evaluation & Comparison

Compares the effectiveness of:
  • Custom-generated wordlists
  • Default/generic wordlists (e.g. rockyou.txt or any file)
  • Combined wordlists

Metrics measured:
  • Success rate (% passwords cracked)
  • Time taken to crack
  • Number of attempts required

Optionally generates charts and a summary table.
"""

from __future__ import annotations

import os
import time
from typing import Any

from cracking_simulation import (
    hash_passwords,
    simulate_wordlist_attack,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_wordlist_file(path: str, max_entries: int = 500_000) -> list[str]:
    """Load a plain-text wordlist file (one entry per line)."""
    words: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.rstrip("\n")
            if word:
                words.append(word)
            if len(words) >= max_entries:
                break
    return words


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------

def evaluate_wordlists(
    target_passwords: list[str],
    wordlists: dict[str, list[str]],
    algorithm: str = "sha256",
) -> dict[str, dict[str, Any]]:
    """
    Run a simulated dictionary attack for each wordlist against
    *target_passwords* and return per-wordlist metrics.

    Parameters
    ----------
    target_passwords : Plain-text passwords to crack.
    wordlists        : Mapping of label → list of candidate passwords.
    algorithm        : Hash algorithm to use for simulation.

    Returns
    -------
    Mapping of label → result dict with keys:
        cracked, attempts, time_seconds, success_rate, passwords_found,
        wordlist_size
    """
    target_hashes = hash_passwords(target_passwords, algorithm)
    results: dict[str, dict[str, Any]] = {}

    for label, wordlist in wordlists.items():
        result = simulate_wordlist_attack(target_hashes, wordlist, algorithm)
        result["wordlist_size"] = len(wordlist)
        results[label] = result

    return results


def compare_wordlists(
    target_passwords: list[str],
    custom_wordlist: list[str],
    generic_wordlist_path: str | None = None,
    algorithm: str = "sha256",
) -> dict[str, dict[str, Any]]:
    """
    Compare custom-generated vs generic (file-based) vs combined wordlists.

    Parameters
    ----------
    target_passwords      : Plain-text passwords to try to crack.
    custom_wordlist       : In-memory custom wordlist.
    generic_wordlist_path : Path to a generic wordlist file (optional).
    algorithm             : Hash algorithm.

    Returns
    -------
    Results dict keyed by "custom", "generic" (if available), "combined"
    (if generic available).
    """
    wordlists: dict[str, list[str]] = {
        "custom": custom_wordlist,
    }

    if generic_wordlist_path and os.path.isfile(generic_wordlist_path):
        generic = _load_wordlist_file(generic_wordlist_path)
        wordlists["generic"] = generic
        # Merge, deduplicate, preserve custom-first order
        seen: set[str] = set(custom_wordlist)
        combined = list(custom_wordlist)
        for w in generic:
            if w not in seen:
                combined.append(w)
                seen.add(w)
        wordlists["combined"] = combined

    return evaluate_wordlists(target_passwords, wordlists, algorithm)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def print_comparison_table(results: dict[str, dict[str, Any]]) -> None:
    """Print a formatted comparison table to stdout."""
    try:
        from tabulate import tabulate
        _tabulate_available = True
    except ImportError:
        _tabulate_available = False

    headers = ["Wordlist", "Candidates", "Attempts", "Cracked", "Success %", "Time (s)"]
    rows = []
    for label, res in results.items():
        rows.append([
            label,
            f"{res.get('wordlist_size', 'N/A'):,}" if isinstance(res.get('wordlist_size'), int) else "N/A",
            f"{res['attempts']:,}",
            len(res["passwords_found"]),
            f"{res['success_rate'] * 100:.1f}%",
            res["time_seconds"],
        ])

    sep = "=" * 70
    print(sep)
    print("  Wordlist Comparison Results")
    print(sep)
    if _tabulate_available:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        # Fallback plain-text table
        col_widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
        fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
        print(fmt.format(*headers))
        print("-" * sum(col_widths))
        for row in rows:
            print(fmt.format(*row))
    print(sep)


def generate_charts(
    results: dict[str, dict[str, Any]],
    output_dir: str = ".",
) -> list[str]:
    """
    Generate bar charts comparing wordlist performance.

    Returns a list of file paths to the saved chart images.
    """
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("matplotlib not available – skipping chart generation.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    saved_paths: list[str] = []

    labels = list(results.keys())
    success_rates = [results[l]["success_rate"] * 100 for l in labels]
    times = [results[l]["time_seconds"] for l in labels]
    attempts = [results[l]["attempts"] for l in labels]

    # --- Success Rate chart ---
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, success_rates, color=["#2196F3", "#FF5722", "#4CAF50"][:len(labels)])
    ax.set_title("Wordlist Comparison — Success Rate (%)", fontsize=14, fontweight="bold")
    ax.set_ylabel("Success Rate (%)")
    ax.set_ylim(0, 110)
    for bar, val in zip(bars, success_rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{val:.1f}%",
            ha="center",
            va="bottom",
        )
    plt.tight_layout()
    sr_path = os.path.join(output_dir, "success_rate_comparison.png")
    plt.savefig(sr_path)
    plt.close(fig)
    saved_paths.append(sr_path)

    # --- Time chart ---
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, times, color=["#9C27B0", "#FF9800", "#009688"][:len(labels)])
    ax.set_title("Wordlist Comparison — Cracking Time (s)", fontsize=14, fontweight="bold")
    ax.set_ylabel("Time (seconds)")
    for bar, val in zip(bars, times):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{val:.3f}s",
            ha="center",
            va="bottom",
        )
    plt.tight_layout()
    time_path = os.path.join(output_dir, "cracking_time_comparison.png")
    plt.savefig(time_path)
    plt.close(fig)
    saved_paths.append(time_path)

    # --- Attempts chart ---
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, attempts, color=["#F44336", "#3F51B5", "#8BC34A"][:len(labels)])
    ax.set_title("Wordlist Comparison — Number of Attempts", fontsize=14, fontweight="bold")
    ax.set_ylabel("Attempts")
    for bar, val in zip(bars, attempts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{val:,}",
            ha="center",
            va="bottom",
        )
    plt.tight_layout()
    att_path = os.path.join(output_dir, "attempts_comparison.png")
    plt.savefig(att_path)
    plt.close(fig)
    saved_paths.append(att_path)

    return saved_paths


def generate_report(
    results: dict[str, dict[str, Any]],
    target_passwords: list[str],
    output_path: str = "evaluation_report.txt",
) -> str:
    """
    Write a plain-text evaluation report to *output_path*.

    Returns the path to the written file.
    """
    lines: list[str] = [
        "=" * 70,
        "  PASSWORD CRACKING EVALUATION REPORT",
        "=" * 70,
        "",
        f"  Target passwords tested : {len(target_passwords)}",
        "",
        "  WORDLIST RESULTS",
        "-" * 70,
    ]

    for label, res in results.items():
        lines += [
            f"",
            f"  Wordlist      : {label}",
            f"  Attempts      : {res['attempts']:,}",
            f"  Cracked       : {len(res['passwords_found'])}",
            f"  Success rate  : {res['success_rate'] * 100:.1f}%",
            f"  Time (s)      : {res['time_seconds']}",
        ]
        if res["passwords_found"]:
            lines.append("  Cracked passwords:")
            for p in res["passwords_found"]:
                lines.append(f"    ✓  {p}")

    lines += [
        "",
        "=" * 70,
        "  ANALYSIS & INSIGHTS",
        "=" * 70,
        "",
    ]

    # Automated insight generation
    best = max(results.items(), key=lambda kv: kv[1]["success_rate"])
    worst = min(results.items(), key=lambda kv: kv[1]["success_rate"])
    fastest = min(results.items(), key=lambda kv: kv[1]["time_seconds"])

    lines += [
        f"  • Best-performing wordlist  : '{best[0]}' "
        f"({best[1]['success_rate'] * 100:.1f}% success rate)",
        f"  • Least-effective wordlist  : '{worst[0]}' "
        f"({worst[1]['success_rate'] * 100:.1f}% success rate)",
        f"  • Fastest wordlist          : '{fastest[0]}' "
        f"({fastest[1]['time_seconds']:.4f}s)",
        "",
        "  NOTES",
        "  -----",
        "  Custom wordlists built from personal information tend to outperform",
        "  generic wordlists for targeted individuals because they exploit",
        "  context-specific patterns (name + DOB, pet + year, etc.).",
        "",
        "  Generic wordlists (e.g. rockyou.txt) are more effective against",
        "  random samples of the wider population where common passwords",
        "  (password123, qwerty, etc.) are prevalent.",
        "",
        "  Combining both strategies maximises coverage in practice.",
        "",
        "=" * 70,
    ]

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return output_path
