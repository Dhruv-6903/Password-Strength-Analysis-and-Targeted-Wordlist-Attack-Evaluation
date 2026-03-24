"""Unit tests for analyzer.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from analyzer import (
    analyze_password,
    _entropy_bits,
    _has_sequential_chars,
    _has_sequential_keyboard,
    _has_repeated_chars,
    _has_leet_pattern,
    _has_year_pattern,
    _common_password_structures,
)


class TestEntropyBits:
    def test_lowercase_only(self):
        import math
        e = _entropy_bits("abc")
        assert e == pytest.approx(3 * math.log2(26), rel=0.01)

    def test_empty_string(self):
        assert _entropy_bits("") == 0.0

    def test_all_charsets(self):
        import math
        pw = "Aa1!"
        expected = 4 * math.log2(26 + 26 + 10 + 32)
        assert _entropy_bits(pw) == pytest.approx(expected, rel=0.01)


class TestSequentialChars:
    def test_detects_alphabet_run(self):
        assert _has_sequential_chars("abcde") is True

    def test_no_sequential(self):
        assert _has_sequential_chars("acegi") is False

    def test_short_run_not_flagged(self):
        # threshold is 4, so "abc" (3 chars) should NOT be flagged
        assert _has_sequential_chars("abc") is False

    def test_case_insensitive(self):
        assert _has_sequential_chars("ABCDE") is True


class TestSequentialKeyboard:
    def test_detects_qwer(self):
        assert _has_sequential_keyboard("qwer") is True

    def test_detects_asdf(self):
        assert _has_sequential_keyboard("asdf") is True

    def test_detects_1234(self):
        assert _has_sequential_keyboard("1234") is True

    def test_no_keyboard_sequence(self):
        assert _has_sequential_keyboard("xyz") is False


class TestRepeatedChars:
    def test_detects_repeated(self):
        assert _has_repeated_chars("aaa") is True

    def test_no_repeated(self):
        assert _has_repeated_chars("abc") is False

    def test_threshold_boundary(self):
        # "aa" is only 2 — default threshold is 3 — should NOT flag
        assert _has_repeated_chars("aa") is False
        assert _has_repeated_chars("aaa") is True


class TestLeetPattern:
    def test_detects_at_sign(self):
        assert _has_leet_pattern("p@ssword") is True

    def test_detects_3(self):
        assert _has_leet_pattern("passw3rd") is True

    def test_no_leet(self):
        assert _has_leet_pattern("plainword") is False


class TestYearPattern:
    def test_detects_year_1990(self):
        assert _has_year_pattern("alice1990") is True

    def test_detects_year_2024(self):
        assert _has_year_pattern("pass2024!") is True

    def test_detects_year_2030(self):
        assert _has_year_pattern("pass2030!") is True

    def test_no_year(self):
        assert _has_year_pattern("alice123") is False


class TestCommonPasswordStructures:
    def test_word_plus_digits(self):
        structs = _common_password_structures("alice123")
        assert "word+digits" in structs

    def test_capitalized_word(self):
        structs = _common_password_structures("Alice")
        assert "capitalized_word" in structs

    def test_year_detected(self):
        structs = _common_password_structures("alice1990")
        assert "contains_year" in structs

    def test_special_suffix(self):
        structs = _common_password_structures("alice!")
        assert "special_char_suffix" in structs


class TestAnalyzePassword:
    def test_returns_expected_keys(self):
        result = analyze_password("test")
        expected_keys = {
            "password", "length", "entropy_bits", "score",
            "strength_label", "crack_time_display",
            "patterns_detected", "suggestions", "zxcvbn_result",
        }
        assert expected_keys.issubset(result.keys())

    def test_length(self):
        result = analyze_password("hello")
        assert result["length"] == 5

    def test_weak_password_score(self):
        result = analyze_password("password")
        # zxcvbn should give this a low score
        assert result["score"] <= 2

    def test_strong_password(self):
        result = analyze_password("T#r7kX!q9@Lm2$Pv")
        assert result["score"] >= 3

    def test_sequential_pattern_detected(self):
        result = analyze_password("abcdefgh")
        assert "sequential_alphabetic_chars" in result["patterns_detected"]

    def test_repeated_pattern_detected(self):
        result = analyze_password("aaabc")
        assert "repeated_chars" in result["patterns_detected"]

    def test_leet_pattern_detected(self):
        result = analyze_password("p@ssw0rd")
        assert "leet_substitutions" in result["patterns_detected"]

    def test_year_pattern_detected(self):
        result = analyze_password("alice2023!")
        assert "year_pattern" in result["patterns_detected"]

    def test_short_password_suggestion(self):
        result = analyze_password("abc")
        assert any("8 characters" in s for s in result["suggestions"])

    def test_user_inputs_accepted(self):
        result = analyze_password("alice1990", user_inputs=["alice", "smith"])
        assert result is not None

    def test_strength_labels(self):
        labels = {"Very Weak", "Weak", "Fair", "Strong", "Very Strong"}
        result = analyze_password("hello")
        assert result["strength_label"] in labels
