"""Unit tests for cracking_simulation.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import tempfile
from cracking_simulation import (
    hash_password,
    hash_passwords,
    simulate_wordlist_attack,
    write_hash_file,
)


class TestHashPassword:
    def test_md5(self):
        import hashlib
        expected = hashlib.md5(b"test").hexdigest()
        assert hash_password("test", "md5") == expected

    def test_sha1(self):
        import hashlib
        expected = hashlib.sha1(b"test").hexdigest()
        assert hash_password("test", "sha1") == expected

    def test_sha256(self):
        import hashlib
        expected = hashlib.sha256(b"test").hexdigest()
        assert hash_password("test", "sha256") == expected

    def test_sha512(self):
        import hashlib
        expected = hashlib.sha512(b"test").hexdigest()
        assert hash_password("test", "sha512") == expected

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            hash_password("test", "crc32")

    def test_consistent_output(self):
        h1 = hash_password("hello", "sha256")
        h2 = hash_password("hello", "sha256")
        assert h1 == h2

    def test_different_passwords_differ(self):
        h1 = hash_password("password1", "sha256")
        h2 = hash_password("password2", "sha256")
        assert h1 != h2


class TestHashPasswords:
    def test_returns_dict(self):
        result = hash_passwords(["a", "b", "c"])
        assert isinstance(result, dict)
        assert len(result) == 3

    def test_keys_are_passwords(self):
        result = hash_passwords(["hello", "world"])
        assert "hello" in result
        assert "world" in result


class TestSimulateWordlistAttack:
    def setup_method(self):
        self.target_passwords = ["alice123", "fluffy2024", "secret"]
        self.algorithm = "sha256"
        self.target_hashes = hash_passwords(self.target_passwords, self.algorithm)

    def test_cracks_exact_match(self):
        result = simulate_wordlist_attack(
            self.target_hashes,
            ["alice123"],
            self.algorithm,
        )
        assert "alice123" in result["passwords_found"]
        assert result["success_rate"] == pytest.approx(1 / 3, rel=0.01)

    def test_cracks_all(self):
        result = simulate_wordlist_attack(
            self.target_hashes,
            self.target_passwords,
            self.algorithm,
        )
        assert result["success_rate"] == 1.0
        assert set(result["passwords_found"]) == set(self.target_passwords)

    def test_no_crack(self):
        result = simulate_wordlist_attack(
            self.target_hashes,
            ["wrong1", "wrong2"],
            self.algorithm,
        )
        assert result["success_rate"] == 0.0
        assert result["passwords_found"] == []

    def test_empty_wordlist(self):
        result = simulate_wordlist_attack(self.target_hashes, [], self.algorithm)
        assert result["attempts"] == 0
        assert result["success_rate"] == 0.0

    def test_empty_target(self):
        result = simulate_wordlist_attack({}, ["alice123"], self.algorithm)
        assert result["attempts"] == 0

    def test_max_attempts_respected(self):
        result = simulate_wordlist_attack(
            self.target_hashes,
            ["wrong"] * 1000 + self.target_passwords,
            self.algorithm,
            max_attempts=5,
        )
        assert result["attempts"] <= 5

    def test_returns_timing(self):
        result = simulate_wordlist_attack(
            self.target_hashes,
            self.target_passwords,
            self.algorithm,
        )
        assert result["time_seconds"] >= 0.0

    def test_returns_attempt_count(self):
        wordlist = ["wrong1", "wrong2", "alice123"]
        result = simulate_wordlist_attack(
            self.target_hashes,
            wordlist,
            self.algorithm,
        )
        assert result["attempts"] == 3  # all candidates tried


class TestWriteHashFile:
    def test_writes_hashes(self):
        hashes = ["abc123", "def456"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            write_hash_file(hashes, path)
            with open(path) as fh:
                lines = [l.rstrip("\n") for l in fh.readlines()]
            assert lines == hashes
        finally:
            os.unlink(path)
