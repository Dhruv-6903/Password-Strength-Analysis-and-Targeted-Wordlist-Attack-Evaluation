# Password Strength Analysis and Targeted Wordlist Attack Evaluation

A Python-based tool for analysing password strength, generating custom targeted
wordlists, and evaluating their effectiveness in simulated dictionary attacks.

---

## Features

| Category | What's included |
|---|---|
| **Password Analysis** | zxcvbn scoring, custom entropy calculation, sequential/repeated/leet/year pattern detection |
| **Wordlist Generation** | Personal-info inputs (name, DOB, pet, city, keywords), permutations, leet-speak, year/suffix appending |
| **Pattern Enrichment** | `name123`, `Name@year`, leet substitutions (`a→@/4`, `e→3`, `o→0`, …), common structures |
| **Export** | Plain-text `.txt` (compatible with Hashcat & John the Ripper) |
| **Cracking Simulation** | Pure-Python dictionary attack simulation (MD5/SHA1/SHA256/SHA512) |
| **Tool Integration** | Optional Hashcat and John the Ripper wrapper helpers |
| **Evaluation** | Compares custom vs generic wordlists — success rate, time, attempts |
| **Charts & Report** | Bar charts (matplotlib) and plain-text evaluation report |
| **CLI** | `argparse`-based CLI with four sub-commands |

---

## Repository Structure

```
├── main.py                  # CLI entry point (argparse)
├── analyzer.py              # Password strength analyzer
├── wordlist_generator.py    # Custom wordlist generator
├── cracking_simulation.py   # Cracking simulation + Hashcat/John wrappers
├── evaluation.py            # Evaluation, comparison, charting, reporting
├── requirements.txt         # Python dependencies
└── tests/
    ├── test_analyzer.py
    ├── test_wordlist_generator.py
    ├── test_cracking_simulation.py
    └── test_evaluation.py
```

---

## Installation

```bash
pip install -r requirements.txt
```

Dependencies: `zxcvbn`, `nltk`, `matplotlib`, `tabulate`, `passlib`

---

## Usage

### 1. Analyze Password Strength

```bash
python main.py analyze --password "MyDog2024" "p@ssw0rd"
```

Sample output:
```
============================================================
  Password Analysis Report
============================================================
  Password         : ********
  Length           : 8
  Entropy (bits)   : 48.7
  Strength Score   : 0 / 4  (Very Weak)
  Est. Crack Time  : less than a second

  Patterns Detected:
    • leet_substitutions

  Suggestions:
    → Add another word or two. Uncommon words are better.
    → Predictable substitutions like '@' instead of 'a' don't help very much.
============================================================
```

You can also pass user-specific tokens to improve dictionary matching:

```bash
python main.py analyze --password "alice1990" --user-inputs alice smith
```

---

### 2. Generate a Custom Wordlist

```bash
python main.py generate \
  --name Alice \
  --surname Smith \
  --dob 19900101 \
  --pet Fluffy \
  --city London \
  --keywords work football \
  --output wordlist.txt
```

The generator produces:
- Plain, uppercased, and capitalised forms
- Common suffixes (`123`, `!`, `@`, …)
- Year appended (1970–2025)
- Leet substitutions (`a→@/4`, `e→3`, `o→0`, `s→$/5`, `i→1/!`, …)
- Two-token combinations from the first four tokens
- Pattern templates: `{word}123`, `{Word}@{year}`, `{WORD}`, …

---

### 3. Simulate a Cracking Attack

```bash
python main.py crack \
  --wordlist wordlist.txt \
  --passwords "alice123" "fluffy2024" "notinlist" \
  --algorithm sha256
```

```
============================================================
  Cracking Simulation Result
============================================================
  Attempts         : 1,628
  Time (seconds)   : 0.0012
  Passwords cracked: 2
  Success rate     : 66.7%

  Cracked passwords:
    ✓ alice123
    ✓ fluffy2024
============================================================
```

---

### 4. Full Evaluation (Custom vs Generic)

```bash
python main.py evaluate \
  --name Alice \
  --surname Smith \
  --dob 19900101 \
  --pet Fluffy \
  --city London \
  --passwords "alice123" "fluffy2024" "smith1990" "notcrackable" \
  --generic-wordlist /usr/share/wordlists/rockyou.txt \
  --output-dir results/ \
  --save-wordlist
```

This command:
1. Generates a custom wordlist from personal info.
2. Runs a simulated dictionary attack with the custom list.
3. If `--generic-wordlist` is provided, also tests the generic list and a
   combined list.
4. Prints a comparison table (success rate, time, attempts).
5. Saves a plain-text report to `results/evaluation_report.txt`.
6. Saves bar charts to `results/`.

**Sample comparison table:**

```
+------------+------------+-----------+-------------+------------+
| Wordlist   |   Attempts |   Cracked | Success %   |   Time (s) |
+============+============+===========+=============+============+
| custom     |      1,132 |         3 | 75.0%       |     0.0008 |
| generic    |    300,000 |         1 | 25.0%       |     0.5312 |
| combined   |    301,132 |         4 | 100.0%      |     0.5420 |
+------------+------------+-----------+-------------+------------+
```

---

## Hashcat / John the Ripper Integration

The `cracking_simulation` module provides wrapper helpers that call the real
tools when they are installed:

```python
from cracking_simulation import run_hashcat, run_john, write_hash_file

# Write hashes to a file
write_hash_file(["5f4dcc3b5aa765d61d8327de..."], "hashes.txt")

# Run Hashcat (mode 0 = MD5)
result = run_hashcat("hashes.txt", "wordlist.txt", hash_mode=0)

# Run John the Ripper
result = run_john("hashes.txt", "wordlist.txt", format_flag="Raw-SHA256")
```

If Hashcat or John are not installed, the functions return a descriptive error
message rather than raising an exception.

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

86 tests covering:
- Entropy calculation
- Sequential / repeated / leet / year pattern detection
- Wordlist generation (tokens, leet variants, pattern templates)
- Hash functions and cracking simulation
- Evaluation metrics and report generation

---

## Analysis & Insights

| Scenario | Better wordlist |
|---|---|
| Targeted attack on a specific individual | **Custom** — exploits name, DOB, pet, city patterns |
| Broad attack on a large credential dump | **Generic** (rockyou.txt) — covers common passwords |
| Maximum coverage | **Combined** — custom first, then generic |

**Limitations:**
- The simulation measures dictionary-attack coverage only; brute-force and
  rule-based attacks (e.g. Hashcat rules) are not simulated.
- Wordlist size is capped at 100,000 entries by default to stay responsive.
- Without a real hash database the success rate only reflects in-memory
  simulation.

**Improvements:**
- Add Markov-chain or neural-network-based candidate generation.
- Support bcrypt / Argon2 hash types for more realistic cracking times.
- Integrate HIBP (Have I Been Pwned) dataset for breach-aware analysis.
