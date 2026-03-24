"""Unit tests for wordlist_generator.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import tempfile
from wordlist_generator import (
    generate_wordlist,
    export_wordlist,
    _leet_variants,
    _apply_pattern,
)


class TestLeetVariants:
    def test_no_leet_chars(self):
        variants = _leet_variants("xyz")
        assert "xyz" in variants

    def test_a_variants(self):
        variants = _leet_variants("a")
        assert "a" in variants
        assert "@" in variants
        assert "4" in variants

    def test_e_variants(self):
        variants = _leet_variants("e")
        assert "e" in variants
        assert "3" in variants

    def test_multiple_chars(self):
        variants = _leet_variants("ae")
        # Should include both standard and leet versions
        assert len(variants) >= 1


class TestApplyPattern:
    def test_word_pattern(self):
        result = _apply_pattern("{word}", "Alice", "2023")
        assert result == "alice"

    def test_capitalized_pattern(self):
        result = _apply_pattern("{Word}", "alice", "2023")
        assert result == "Alice"

    def test_upper_pattern(self):
        result = _apply_pattern("{WORD}", "alice", "2023")
        assert result == "ALICE"

    def test_word_year_pattern(self):
        result = _apply_pattern("{word}{year}", "alice", "2024")
        assert result == "alice2024"

    def test_at_year_pattern(self):
        result = _apply_pattern("{word}@{year}", "alice", "2023")
        assert result == "alice@2023"


class TestGenerateWordlist:
    def test_basic_generation(self):
        wl = generate_wordlist(name="Alice")
        assert len(wl) > 0

    def test_name_in_wordlist(self):
        wl = generate_wordlist(name="Alice")
        lower_wl = [w.lower() for w in wl]
        assert "alice" in lower_wl

    def test_surname_in_wordlist(self):
        wl = generate_wordlist(surname="Smith")
        lower_wl = [w.lower() for w in wl]
        assert "smith" in lower_wl

    def test_combined_tokens(self):
        wl = generate_wordlist(name="Alice", surname="Smith")
        assert len(wl) > 0

    def test_dob_tokens_included(self):
        wl = generate_wordlist(name="Alice", date_of_birth="19900101")
        # Year portion (1990) should appear somewhere in the list
        assert any("1990" in w for w in wl)

    def test_pet_name(self):
        wl = generate_wordlist(name="Alice", pet_name="Fluffy")
        lower_wl = [w.lower() for w in wl]
        assert "fluffy" in lower_wl

    def test_city(self):
        wl = generate_wordlist(name="Alice", city="London")
        lower_wl = [w.lower() for w in wl]
        assert "london" in lower_wl

    def test_keywords(self):
        wl = generate_wordlist(name="Alice", keywords=["soccer"])
        lower_wl = [w.lower() for w in wl]
        assert "soccer" in lower_wl

    def test_no_duplicates(self):
        wl = generate_wordlist(name="Alice", surname="Smith")
        assert len(wl) == len(set(wl))

    def test_missing_inputs_raises(self):
        with pytest.raises(ValueError):
            generate_wordlist()

    def test_leet_variants_present(self):
        wl = generate_wordlist(name="alice")
        # '@' substitutions should appear somewhere
        assert any("@" in w for w in wl)

    def test_year_appended(self):
        wl = generate_wordlist(name="alice")
        # Some entries should have years appended
        assert any(w.startswith("alice") and w[5:].isdigit() for w in wl)

    def test_max_size_respected(self):
        from wordlist_generator import MAX_WORDLIST_SIZE
        wl = generate_wordlist(
            name="Alice", surname="Smith", pet_name="Fluffy",
            city="London", keywords=["work", "football"],
        )
        assert len(wl) <= MAX_WORDLIST_SIZE


class TestExportWordlist:
    def test_writes_file(self):
        wl = ["password1", "test123", "alice!"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            count = export_wordlist(wl, path)
            assert count == 3
            with open(path) as fh:
                lines = [l.rstrip("\n") for l in fh.readlines()]
            assert lines == wl
        finally:
            os.unlink(path)

    def test_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "subdir", "wordlist.txt")
            export_wordlist(["hello"], path)
            assert os.path.isfile(path)
