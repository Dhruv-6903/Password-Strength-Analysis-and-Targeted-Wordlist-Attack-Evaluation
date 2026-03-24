"""
main.py — CLI entry point for the Password Strength Analyzer &
          Targeted Wordlist Attack Evaluation tool.

Usage examples
--------------
# Analyze a password
python main.py analyze --password "MyP@ss2024"

# Generate a custom wordlist
python main.py generate --name Alice --surname Smith --dob 19900101 \
    --pet Fluffy --city London --keywords work --output wordlist.txt

# Run a cracking simulation
python main.py crack --wordlist wordlist.txt --passwords "alice123" "fluffy2024" \
    --algorithm sha256

# Full evaluation (custom vs generic)
python main.py evaluate --name Alice --surname Smith --dob 19900101 \
    --passwords "alice123" "fluffy2024" \
    --generic-wordlist /usr/share/wordlists/rockyou.txt \
    --output-dir results/

# Generate charts from a previous evaluation
python main.py chart --results-dir results/
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from analyzer import analyze_password, print_analysis
from cracking_simulation import print_crack_result, simulate_wordlist_attack, hash_passwords
from evaluation import (
    compare_wordlists,
    generate_charts,
    generate_report,
    print_comparison_table,
)
from wordlist_generator import (
    export_wordlist,
    generate_wordlist,
    print_wordlist_summary,
)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> None:
    passwords: list[str] = args.password
    user_inputs: list[str] = args.user_inputs or []

    for pw in passwords:
        result = analyze_password(pw, user_inputs=user_inputs)
        print_analysis(result)


def cmd_generate(args: argparse.Namespace) -> None:
    keywords: list[str] = args.keywords or []
    wordlist = generate_wordlist(
        name=args.name,
        surname=args.surname,
        date_of_birth=args.dob,
        pet_name=args.pet,
        city=args.city,
        keywords=keywords,
    )

    output_path: str | None = args.output
    if output_path:
        count = export_wordlist(wordlist, output_path)
        print_wordlist_summary(wordlist, output_path)
    else:
        print_wordlist_summary(wordlist)


def cmd_crack(args: argparse.Namespace) -> None:
    # Load wordlist from file
    wordlist: list[str] = []
    with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\n")
            if w:
                wordlist.append(w)

    target_passwords: list[str] = args.passwords
    algorithm: str = args.algorithm

    target_hashes = hash_passwords(target_passwords, algorithm)
    result = simulate_wordlist_attack(target_hashes, wordlist, algorithm)
    print_crack_result(result)


def cmd_evaluate(args: argparse.Namespace) -> None:
    keywords: list[str] = args.keywords or []
    custom_wordlist = generate_wordlist(
        name=args.name,
        surname=args.surname,
        date_of_birth=args.dob,
        pet_name=args.pet,
        city=args.city,
        keywords=keywords,
    )

    target_passwords: list[str] = args.passwords
    generic_path: str | None = args.generic_wordlist
    output_dir: str = args.output_dir or "."
    algorithm: str = args.algorithm

    results = compare_wordlists(
        target_passwords,
        custom_wordlist,
        generic_path,
        algorithm,
    )

    print_comparison_table(results)

    # Save report
    report_path = f"{output_dir}/evaluation_report.txt"
    generate_report(results, target_passwords, report_path)
    print(f"\n  Report saved to : {report_path}")

    # Save custom wordlist if requested
    if args.save_wordlist:
        wl_path = f"{output_dir}/custom_wordlist.txt"
        export_wordlist(custom_wordlist, wl_path)
        print(f"  Wordlist saved  : {wl_path}")

    # Generate charts
    saved = generate_charts(results, output_dir)
    if saved:
        print(f"\n  Charts saved:")
        for p in saved:
            print(f"    {p}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psa",
        description=(
            "Password Strength Analyzer and Targeted Wordlist Attack Evaluation Tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- analyze ----
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analyze the strength of one or more passwords.",
    )
    p_analyze.add_argument(
        "--password", "-p",
        nargs="+",
        required=True,
        metavar="PASSWORD",
        help="One or more passwords to analyze.",
    )
    p_analyze.add_argument(
        "--user-inputs",
        nargs="*",
        metavar="TOKEN",
        help="User-specific tokens to improve dictionary matching (name, city…).",
    )

    # ---- generate ----
    p_generate = subparsers.add_parser(
        "generate",
        help="Generate a custom targeted wordlist.",
    )
    p_generate.add_argument("--name", help="Target's first name.")
    p_generate.add_argument("--surname", help="Target's surname / family name.")
    p_generate.add_argument("--dob", metavar="DATE", help="Date of birth (e.g. 19900101).")
    p_generate.add_argument("--pet", metavar="PET_NAME", help="Pet name.")
    p_generate.add_argument("--city", help="City or place name.")
    p_generate.add_argument(
        "--keywords", nargs="*", metavar="KEYWORD",
        help="Additional keywords (company, team, hobby…).",
    )
    p_generate.add_argument(
        "--output", "-o", metavar="FILE",
        help="Output file path for the wordlist (.txt).",
    )

    # ---- crack ----
    p_crack = subparsers.add_parser(
        "crack",
        help="Simulate a dictionary attack against a set of passwords.",
    )
    p_crack.add_argument(
        "--wordlist", "-w", required=True, metavar="FILE",
        help="Path to the wordlist file to use.",
    )
    p_crack.add_argument(
        "--passwords", "-p", nargs="+", required=True, metavar="PASSWORD",
        help="Target plain-text passwords to crack.",
    )
    p_crack.add_argument(
        "--algorithm", "-a", default="sha256",
        choices=["md5", "sha1", "sha256", "sha512"],
        help="Hash algorithm (default: sha256).",
    )

    # ---- evaluate ----
    p_evaluate = subparsers.add_parser(
        "evaluate",
        help=(
            "Generate a custom wordlist, run evaluation against target passwords, "
            "and compare with a generic wordlist."
        ),
    )
    p_evaluate.add_argument("--name", help="Target's first name.")
    p_evaluate.add_argument("--surname", help="Target's surname.")
    p_evaluate.add_argument("--dob", metavar="DATE", help="Date of birth (e.g. 19900101).")
    p_evaluate.add_argument("--pet", metavar="PET_NAME", help="Pet name.")
    p_evaluate.add_argument("--city", help="City or place name.")
    p_evaluate.add_argument(
        "--keywords", nargs="*", metavar="KEYWORD",
        help="Additional keywords.",
    )
    p_evaluate.add_argument(
        "--passwords", "-p", nargs="+", required=True, metavar="PASSWORD",
        help="Target plain-text passwords to evaluate against.",
    )
    p_evaluate.add_argument(
        "--generic-wordlist", metavar="FILE",
        help="Path to a generic wordlist file (e.g. rockyou.txt) for comparison.",
    )
    p_evaluate.add_argument(
        "--algorithm", "-a", default="sha256",
        choices=["md5", "sha1", "sha256", "sha512"],
        help="Hash algorithm (default: sha256).",
    )
    p_evaluate.add_argument(
        "--output-dir", "-o", default="results",
        metavar="DIR",
        help="Directory to save the report and charts (default: results/).",
    )
    p_evaluate.add_argument(
        "--save-wordlist", action="store_true",
        help="Also save the generated custom wordlist to the output directory.",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "analyze": cmd_analyze,
        "generate": cmd_generate,
        "crack": cmd_crack,
        "evaluate": cmd_evaluate,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        handler(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
