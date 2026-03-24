"""Unit tests for evaluation.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import tempfile
from evaluation import (
    evaluate_wordlists,
    compare_wordlists,
    generate_report,
)


class TestEvaluateWordlists:
    def test_basic_evaluation(self):
        targets = ["alice123", "bob456"]
        wordlists = {
            "custom": ["alice123", "wrong"],
            "generic": ["bob456", "wrong2"],
        }
        results = evaluate_wordlists(targets, wordlists)
        assert "custom" in results
        assert "generic" in results

    def test_success_rate_100(self):
        targets = ["hello"]
        wordlists = {"test": ["hello"]}
        results = evaluate_wordlists(targets, wordlists)
        assert results["test"]["success_rate"] == 1.0

    def test_success_rate_0(self):
        targets = ["hello"]
        wordlists = {"test": ["wrong"]}
        results = evaluate_wordlists(targets, wordlists)
        assert results["test"]["success_rate"] == 0.0

    def test_result_structure(self):
        targets = ["test"]
        wordlists = {"w": ["test"]}
        results = evaluate_wordlists(targets, wordlists)
        keys = {"cracked", "attempts", "time_seconds", "success_rate", "passwords_found", "wordlist_size"}
        assert keys.issubset(results["w"].keys())


class TestCompareWordlists:
    def test_custom_only_when_no_generic(self):
        targets = ["alice123"]
        custom = ["alice123", "wrong"]
        results = compare_wordlists(targets, custom)
        assert "custom" in results
        assert "generic" not in results
        assert "combined" not in results

    def test_generic_loaded_when_file_given(self):
        targets = ["generic_pass"]
        custom = ["custom_pass"]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("generic_pass\nother_pass\n")
            path = f.name
        try:
            results = compare_wordlists(targets, custom, generic_wordlist_path=path)
            assert "generic" in results
            assert "combined" in results
            assert results["generic"]["success_rate"] == 1.0
        finally:
            os.unlink(path)

    def test_combined_cracks_both(self):
        targets = ["custom_pass", "generic_pass"]
        custom = ["custom_pass"]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("generic_pass\n")
            path = f.name
        try:
            results = compare_wordlists(targets, custom, generic_wordlist_path=path)
            assert results["combined"]["success_rate"] == 1.0
        finally:
            os.unlink(path)


class TestGenerateReport:
    def test_creates_file(self):
        targets = ["alice123"]
        results = {
            "custom": {
                "cracked": {"alice123": "hash"},
                "attempts": 5,
                "time_seconds": 0.01,
                "success_rate": 1.0,
                "passwords_found": ["alice123"],
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "report.txt")
            path = generate_report(results, targets, report_path)
            assert os.path.isfile(path)
            with open(path) as fh:
                content = fh.read()
            assert "EVALUATION REPORT" in content
            assert "custom" in content

    def test_report_contains_insights(self):
        targets = ["test"]
        results = {
            "custom": {
                "cracked": {},
                "attempts": 10,
                "time_seconds": 0.001,
                "success_rate": 0.0,
                "passwords_found": [],
            },
            "generic": {
                "cracked": {"test": "hash"},
                "attempts": 3,
                "time_seconds": 0.002,
                "success_rate": 1.0,
                "passwords_found": ["test"],
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_report(results, targets, os.path.join(tmpdir, "r.txt"))
            with open(path) as fh:
                content = fh.read()
            assert "ANALYSIS" in content
            assert "Best-performing" in content
