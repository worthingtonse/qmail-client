"""
test_balance.py - Pytest test suite for wallet balance API

Tests coin scanner module with proper pytest assertions.
Run with: pytest tests/test_balance.py -v
"""

import os
import sys
import struct
import tempfile
import shutil

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False

from src.coin_scanner import (
    parse_coin_file,
    scan_coins_in_directory,
    parse_denomination_code,
    get_denomination_breakdown
)


def create_test_coin_file(file_path, denomination_code):
    """
    Create a test .bin file with specified denomination code at byte 34.

    Args:
        file_path: Path to create file
        denomination_code: Signed int8 value for denomination
    """
    # Create 35 bytes (minimum size) with denomination at byte 34
    data = bytearray(35)
    # Set denomination at byte 34 (0-indexed)
    struct.pack_into('b', data, 34, denomination_code)

    with open(file_path, 'wb') as f:
        f.write(data)


class TestDenominationParsing:
    """Test denomination code to value conversion."""

    def test_fractional_denomination(self):
        """Test fractional CloudCoin value (0.1)."""
        value = parse_denomination_code(-1)
        assert abs(value - 0.1) < 0.0001

    def test_one_coin(self):
        """Test 1 CloudCoin value."""
        value = parse_denomination_code(0)
        assert abs(value - 1.0) < 0.0001

    def test_ten_coins(self):
        """Test 10 CloudCoin value."""
        value = parse_denomination_code(1)
        assert abs(value - 10.0) < 0.0001

    def test_hundred_coins(self):
        """Test 100 CloudCoin value."""
        value = parse_denomination_code(2)
        assert abs(value - 100.0) < 0.0001

    def test_thousand_coins(self):
        """Test 1000 CloudCoin value."""
        value = parse_denomination_code(3)
        assert abs(value - 1000.0) < 0.0001

    def test_key_coin_special_case(self):
        """Test Key coin (code 11 = 0 value)."""
        value = parse_denomination_code(11)
        assert value == 0.0


class TestBinaryFileParsing:
    """Test parsing .bin CloudCoin files."""

    def setup_method(self):
        """Create temporary test directory."""
        self.test_dir = tempfile.mkdtemp(prefix="cointest_")

    def teardown_method(self):
        """Clean up temporary test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_parse_fractional_coin(self):
        """Test parsing 0.1 CloudCoin."""
        file_path = os.path.join(self.test_dir, "coin_0.1.bin")
        create_test_coin_file(file_path, -1)

        err, value = parse_coin_file(file_path)
        assert err == 0  # SUCCESS
        assert value is not None
        assert abs(value - 0.1) < 0.0001

    def test_parse_one_coin(self):
        """Test parsing 1 CloudCoin."""
        file_path = os.path.join(self.test_dir, "coin_1.bin")
        create_test_coin_file(file_path, 0)

        err, value = parse_coin_file(file_path)
        assert err == 0
        assert value is not None
        assert abs(value - 1.0) < 0.0001

    def test_parse_hundred_coin(self):
        """Test parsing 100 CloudCoin."""
        file_path = os.path.join(self.test_dir, "coin_100.bin")
        create_test_coin_file(file_path, 2)

        err, value = parse_coin_file(file_path)
        assert err == 0
        assert value is not None
        assert abs(value - 100.0) < 0.0001

    def test_parse_key_coin(self):
        """Test parsing Key coin (special case)."""
        file_path = os.path.join(self.test_dir, "coin_key.bin")
        create_test_coin_file(file_path, 11)

        err, value = parse_coin_file(file_path)
        assert err == 0
        assert value is not None
        assert value == 0.0

    def test_reject_truncated_file(self):
        """Test that files < 35 bytes are rejected."""
        truncated_path = os.path.join(self.test_dir, "truncated.bin")
        with open(truncated_path, 'wb') as f:
            f.write(b'\x00' * 20)  # Only 20 bytes

        err, value = parse_coin_file(truncated_path)
        assert err != 0  # Should return error code
        assert value is None

    def test_reject_34_byte_file(self):
        """Test that exactly 34-byte files are rejected."""
        edge_case_path = os.path.join(self.test_dir, "edge.bin")
        with open(edge_case_path, 'wb') as f:
            f.write(b'\x00' * 34)  # Exactly 34 bytes

        err, value = parse_coin_file(edge_case_path)
        assert err != 0  # Should return error code
        assert value is None


class TestDirectoryScanning:
    """Test directory scanning functionality."""

    def setup_method(self):
        """Create temporary test directory."""
        self.test_dir = tempfile.mkdtemp(prefix="cointest_")

    def teardown_method(self):
        """Clean up temporary test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_scan_mixed_denominations(self):
        """Test scanning directory with mixed denominations."""
        # Create test coins: 3x 1CC, 2x 100CC, 1x 0.1CC
        test_coins = [
            ("coin1.bin", 0),    # 1 CC
            ("coin2.bin", 0),    # 1 CC
            ("coin3.bin", 0),    # 1 CC
            ("coin4.bin", 2),    # 100 CC
            ("coin5.bin", 2),    # 100 CC
            ("coin6.bin", -1),   # 0.1 CC
        ]

        for filename, code in test_coins:
            file_path = os.path.join(self.test_dir, filename)
            create_test_coin_file(file_path, code)

        expected_total = 3 * 1.0 + 2 * 100.0 + 1 * 0.1
        expected_count = 6

        total_value, coin_count, denoms = scan_coins_in_directory(self.test_dir)

        assert coin_count == expected_count
        assert abs(total_value - expected_total) < 0.0001
        assert denoms[1.0] == 3
        assert denoms[100.0] == 2
        assert denoms[0.1] == 1

    def test_ignore_non_bin_files(self):
        """Test that non-.bin files are ignored."""
        # Create .bin files and other files
        create_test_coin_file(os.path.join(self.test_dir, "coin1.bin"), 0)
        create_test_coin_file(os.path.join(self.test_dir, "coin2.bin"), 0)

        # Create non-.bin files that should be ignored
        with open(os.path.join(self.test_dir, "readme.txt"), 'w') as f:
            f.write("Ignore me")
        with open(os.path.join(self.test_dir, "data.json"), 'w') as f:
            f.write("{}")

        total_value, coin_count, denoms = scan_coins_in_directory(self.test_dir)

        # Should only count the 2 .bin files
        assert coin_count == 2
        assert abs(total_value - 2.0) < 0.0001

    def test_empty_directory(self):
        """Test scanning empty directory."""
        total_value, coin_count, denoms = scan_coins_in_directory(self.test_dir)

        assert coin_count == 0
        assert total_value == 0.0
        assert len(denoms) == 0

    def test_nonexistent_directory(self):
        """Test scanning non-existent directory."""
        fake_dir = os.path.join(self.test_dir, "does_not_exist")

        total_value, coin_count, denoms = scan_coins_in_directory(fake_dir)

        assert coin_count == 0
        assert total_value == 0.0
        assert len(denoms) == 0


class TestDenominationBreakdown:
    """Test denomination breakdown functionality."""

    def test_standard_denominations(self):
        """Test breakdown with standard CloudCoin denominations."""
        denom_counts = {
            1.0: 50,
            100.0: 10,
            0.1: 5
        }

        breakdown = get_denomination_breakdown(denom_counts)

        assert breakdown["1"] == 50
        assert breakdown["100"] == 10
        assert breakdown["0.1"] == 5

    def test_power_of_10_denominations(self):
        """Test breakdown with all valid power-of-10 denominations."""
        denom_counts = {
            10.0: 20,      # Valid: 10^1
            1000.0: 5,     # Valid: 10^3
            0.01: 3        # Valid: 10^-2
        }

        breakdown = get_denomination_breakdown(denom_counts)

        assert breakdown["10"] == 20
        assert breakdown["1000"] == 5
        assert breakdown["0.01"] == 3
        # Should not have "other" category
        assert "other" not in breakdown or breakdown.get("other") == 0

    def test_key_coins_in_other(self):
        """Test that Key coins (value=0) go into 'other' category."""
        denom_counts = {
            1.0: 10,
            0.0: 5  # Key coins
        }

        breakdown = get_denomination_breakdown(denom_counts)

        assert breakdown["1"] == 10
        assert breakdown["other"] == 5

    def test_non_power_of_10_in_other(self):
        """Test that non-power-of-10 values go into 'other' category."""
        denom_counts = {
            1.0: 10,
            5.0: 3,  # Not a power of 10
            25.0: 2  # Not a power of 10
        }

        breakdown = get_denomination_breakdown(denom_counts)

        assert breakdown["1"] == 10
        assert breakdown["other"] == 5  # 3 + 2


if __name__ == "__main__":
    if HAS_PYTEST:
        pytest.main([__file__, "-v"])
    else:
        print("=" * 70)
        print("WARNING: pytest not installed. Install with: pip install pytest")
        print("Running basic sanity check instead...")
        print("=" * 70)
        print()

        # Run basic sanity checks
        passed = 0
        failed = 0

        # Test denomination parsing
        test_obj = TestDenominationParsing()
        for method_name in dir(test_obj):
            if method_name.startswith('test_'):
                try:
                    getattr(test_obj, method_name)()
                    print(f"[PASS] {method_name}")
                    passed += 1
                except AssertionError as e:
                    print(f"[FAIL] {method_name}: {e}")
                    failed += 1

        print()
        print("=" * 70)
        print(f"Results: {passed} passed, {failed} failed")
        print("For full test suite, install pytest and run: pytest tests/test_balance.py -v")
        print("=" * 70)
