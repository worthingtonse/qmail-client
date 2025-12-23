"""
test_coin_break.py - Unit Tests for CloudCoin Break (Make Change) Functionality

Tests the break protocol functions in protocol.py and coin_break.py.
No network operations - pure unit tests for packet construction and helpers.

Author: Claude Opus 4.5
Date: 2025-12-22
"""

import os
import sys
import struct
import unittest
import zlib

# Add src and tests to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_utils import (
    generate_test_an, verify_challenge_format,
    assert_header_valid, create_mock_logger
)

from protocol import (
    build_make_change_payload, build_make_change_header,
    build_complete_make_change_request, ProtocolErrorCode,
    CMD_MAKE_CHANGE, CMD_GROUP_CHANGE, ENC_SHARED_SECRET
)

from coin_break import (
    CoinToBreak, BreakResult,
    _generate_starting_sn, _generate_pans,
    MIN_STARTING_SN, MAX_STARTING_SN,
    DENOM_TO_CODE, CODE_TO_DENOM,
    MIN_CONSENSUS, STATUS_SUCCESS,
    CC_RAIDA_COUNT
)


# ============================================================================
# TESTS FOR PROTOCOL: build_make_change_payload()
# ============================================================================

class TestBuildMakeChangePayload(unittest.TestCase):
    """Tests for build_make_change_payload() function."""

    def test_build_make_change_payload_valid(self):
        """Test building payload with valid parameters."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, payload, challenge = build_make_change_payload(
            original_dn=2,  # 100cc
            original_sn=12345678,
            original_an=original_an,
            starting_sn=1000000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(payload), 203)
        self.assertEqual(len(challenge), 16)
        self.assertTrue(verify_challenge_format(challenge))

        print("test_build_make_change_payload_valid: PASSED")

    def test_build_make_change_payload_size(self):
        """Test that payload is exactly 203 bytes."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, payload, _ = build_make_change_payload(
            original_dn=1,
            original_sn=999999,
            original_an=original_an,
            starting_sn=500000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        # Verify exact size: 16 + 1 + 4 + 16 + 4 + 160 + 2 = 203
        self.assertEqual(len(payload), 203)

        print("test_build_make_change_payload_size: PASSED")

    def test_build_make_change_payload_big_endian_serial_numbers(self):
        """Test that serial numbers are encoded in big-endian format."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        # Use specific serial numbers to verify byte order
        original_sn = 0x12345678
        starting_sn = 0xAABBCCDD

        err, payload, _ = build_make_change_payload(
            original_dn=2,
            original_sn=original_sn,
            original_an=original_an,
            starting_sn=starting_sn,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Original SN at bytes 17-20 (big-endian)
        original_sn_bytes = payload[17:21]
        self.assertEqual(original_sn_bytes, bytes([0x12, 0x34, 0x56, 0x78]))

        # Starting SN at bytes 37-40 (big-endian)
        starting_sn_bytes = payload[37:41]
        self.assertEqual(starting_sn_bytes, bytes([0xAA, 0xBB, 0xCC, 0xDD]))

        # Verify we can unpack correctly with big-endian
        unpacked_orig = struct.unpack('>I', payload[17:21])[0]
        unpacked_start = struct.unpack('>I', payload[37:41])[0]
        self.assertEqual(unpacked_orig, original_sn)
        self.assertEqual(unpacked_start, starting_sn)

        print("test_build_make_change_payload_big_endian_serial_numbers: PASSED")

    def test_build_make_change_payload_structure(self):
        """Test that payload structure matches specification."""
        original_an = b'\xAA' * 16  # Recognizable pattern
        pans = [bytes([i] * 16) for i in range(10)]  # Distinct patterns

        err, payload, challenge = build_make_change_payload(
            original_dn=3,  # 1000cc
            original_sn=0x00ABCDEF,
            original_an=original_an,
            starting_sn=0x00123456,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Bytes 0-15: Challenge
        self.assertEqual(payload[0:16], challenge)

        # Byte 16: Denomination code
        self.assertEqual(payload[16], 3)

        # Bytes 17-20: Original SN (big-endian)
        self.assertEqual(payload[17:21], bytes([0x00, 0xAB, 0xCD, 0xEF]))

        # Bytes 21-36: Original AN
        self.assertEqual(payload[21:37], original_an)

        # Bytes 37-40: Starting SN (big-endian)
        self.assertEqual(payload[37:41], bytes([0x00, 0x12, 0x34, 0x56]))

        # Bytes 41-200: 10 PANs (16 bytes each)
        for i in range(10):
            offset = 41 + (i * 16)
            self.assertEqual(payload[offset:offset + 16], pans[i])

        # Bytes 201-202: Terminator
        self.assertEqual(payload[201:203], bytes([0x3E, 0x3E]))

        print("test_build_make_change_payload_structure: PASSED")

    def test_build_make_change_payload_challenge_crc(self):
        """Test that challenge has correct CRC."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, payload, challenge = build_make_change_payload(
            original_dn=1,
            original_sn=12345,
            original_an=original_an,
            starting_sn=100000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Challenge format: 12 random + 4 CRC
        random_part = challenge[:12]
        crc_part = challenge[12:16]

        expected_crc = zlib.crc32(random_part) & 0xFFFFFFFF
        actual_crc = struct.unpack('>I', crc_part)[0]

        self.assertEqual(expected_crc, actual_crc)

        print("test_build_make_change_payload_challenge_crc: PASSED")

    def test_build_make_change_payload_invalid_an(self):
        """Test payload with invalid AN (too short)."""
        pans = [os.urandom(16) for _ in range(10)]

        err, payload, _ = build_make_change_payload(
            original_dn=1,
            original_sn=12345,
            original_an=bytes(5),  # Too short
            starting_sn=100000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_payload_invalid_an: PASSED")

    def test_build_make_change_payload_invalid_pans_count(self):
        """Test payload with wrong number of PANs."""
        original_an = generate_test_an()

        # Too few PANs
        err, _, _ = build_make_change_payload(
            original_dn=1, original_sn=12345, original_an=original_an,
            starting_sn=100000, pans=[os.urandom(16) for _ in range(5)]
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        # Too many PANs
        err, _, _ = build_make_change_payload(
            original_dn=1, original_sn=12345, original_an=original_an,
            starting_sn=100000, pans=[os.urandom(16) for _ in range(15)]
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_payload_invalid_pans_count: PASSED")

    def test_build_make_change_payload_invalid_pan_size(self):
        """Test payload with invalid PAN size."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(9)]
        pans.append(bytes(8))  # One PAN too short

        err, _, _ = build_make_change_payload(
            original_dn=1,
            original_sn=12345,
            original_an=original_an,
            starting_sn=100000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_payload_invalid_pan_size: PASSED")

    def test_build_make_change_payload_all_denominations(self):
        """Test payload building for all valid denominations."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        for denom in [0, 1, 2, 3]:  # 1cc, 10cc, 100cc, 1000cc
            err, payload, _ = build_make_change_payload(
                original_dn=denom,
                original_sn=12345678,
                original_an=original_an,
                starting_sn=100000,
                pans=pans
            )

            self.assertEqual(err, ProtocolErrorCode.SUCCESS)
            self.assertEqual(payload[16], denom)

        print("test_build_make_change_payload_all_denominations: PASSED")


# ============================================================================
# TESTS FOR PROTOCOL: build_make_change_header()
# ============================================================================

class TestBuildMakeChangeHeader(unittest.TestCase):
    """Tests for build_make_change_header() function."""

    def test_build_make_change_header_valid(self):
        """Test building header with valid parameters."""
        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=2,
            serial_number=12345678
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(header), 32)

        print("test_build_make_change_header_valid: PASSED")

    def test_build_make_change_header_command_group_and_code(self):
        """Test that header has correct command group and code."""
        err, header = build_make_change_header(
            raida_id=5,
            body_length=203,
            denomination=1,
            serial_number=999999
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Command Group at byte 4 = 9 (Change Services)
        self.assertEqual(header[4], CMD_GROUP_CHANGE)
        self.assertEqual(header[4], 9)

        # Command Code at byte 5 = 94 (Make Change)
        self.assertEqual(header[5], CMD_MAKE_CHANGE)
        self.assertEqual(header[5], 94)

        print("test_build_make_change_header_command_group_and_code: PASSED")

    def test_build_make_change_header_encryption_type(self):
        """Test that header uses encryption type 1 (shared secret)."""
        err, header = build_make_change_header(
            raida_id=10,
            body_length=203,
            denomination=2,
            serial_number=12345678
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Encryption type at byte 16 = 1 (shared secret / AN-based)
        self.assertEqual(header[16], ENC_SHARED_SECRET)
        self.assertEqual(header[16], 1)

        print("test_build_make_change_header_encryption_type: PASSED")

    def test_build_make_change_header_all_raida_ids(self):
        """Test header with all valid RAIDA IDs (0-24)."""
        for raida_id in range(25):
            err, header = build_make_change_header(
                raida_id=raida_id,
                body_length=203,
                denomination=1,
                serial_number=12345
            )

            self.assertEqual(err, ProtocolErrorCode.SUCCESS)
            self.assertEqual(header[2], raida_id)

        print("test_build_make_change_header_all_raida_ids: PASSED")

    def test_build_make_change_header_invalid_raida(self):
        """Test header with invalid RAIDA ID."""
        err, _ = build_make_change_header(
            raida_id=25,
            body_length=203,
            denomination=1,
            serial_number=12345
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        err, _ = build_make_change_header(
            raida_id=-1,
            body_length=203,
            denomination=1,
            serial_number=12345
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_header_invalid_raida: PASSED")

    def test_build_make_change_header_serial_number_big_endian(self):
        """Test that serial number in header is big-endian."""
        serial_number = 0x12345678

        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=2,
            serial_number=serial_number
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Serial number at bytes 18-21 (4 bytes, big-endian)
        sn_bytes = header[18:22]
        self.assertEqual(sn_bytes, bytes([0x12, 0x34, 0x56, 0x78]))

        print("test_build_make_change_header_serial_number_big_endian: PASSED")


# ============================================================================
# TESTS FOR PROTOCOL: build_complete_make_change_request()
# ============================================================================

class TestBuildCompleteMakeChangeRequest(unittest.TestCase):
    """Tests for build_complete_make_change_request() function."""

    def test_build_complete_make_change_request_valid(self):
        """Test building complete request with valid parameters."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, request, challenge, nonce = build_complete_make_change_request(
            raida_id=0,
            original_dn=2,
            original_sn=12345678,
            original_an=original_an,
            starting_sn=1000000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertGreater(len(request), 32)  # Header + encrypted payload
        self.assertEqual(len(challenge), 16)
        self.assertEqual(len(nonce), 8)

        print("test_build_complete_make_change_request_valid: PASSED")

    def test_build_complete_make_change_request_header_correct(self):
        """Test that complete request has correct header."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, request, _, _ = build_complete_make_change_request(
            raida_id=5,
            original_dn=1,
            original_sn=999999,
            original_an=original_an,
            starting_sn=500000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        header = request[:32]
        # RAIDA ID
        self.assertEqual(header[2], 5)
        # Command Group
        self.assertEqual(header[4], CMD_GROUP_CHANGE)
        # Command Code
        self.assertEqual(header[5], CMD_MAKE_CHANGE)
        # Encryption type
        self.assertEqual(header[16], ENC_SHARED_SECRET)

        print("test_build_complete_make_change_request_header_correct: PASSED")

    def test_build_complete_make_change_request_all_raidas(self):
        """Test building request for all 25 RAIDAs."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        for raida_id in range(25):
            err, request, _, _ = build_complete_make_change_request(
                raida_id=raida_id,
                original_dn=2,
                original_sn=12345678,
                original_an=original_an,
                starting_sn=1000000,
                pans=pans
            )

            self.assertEqual(err, ProtocolErrorCode.SUCCESS)
            self.assertEqual(request[2], raida_id)

        print("test_build_complete_make_change_request_all_raidas: PASSED")


# ============================================================================
# TESTS FOR COIN_BREAK: Helper Functions
# ============================================================================

class TestCoinBreakHelpers(unittest.TestCase):
    """Tests for coin_break.py helper functions."""

    def test_generate_starting_sn_in_range(self):
        """Test that generated SNs are within valid range."""
        for _ in range(100):
            sn = _generate_starting_sn()
            self.assertGreaterEqual(sn, MIN_STARTING_SN)
            self.assertLessEqual(sn, MAX_STARTING_SN)

        print("test_generate_starting_sn_in_range: PASSED")

    def test_generate_starting_sn_randomness(self):
        """Test that generated SNs are random (not all same)."""
        sns = [_generate_starting_sn() for _ in range(50)]
        unique_sns = set(sns)

        # Should have multiple different values
        self.assertGreater(len(unique_sns), 10)

        print("test_generate_starting_sn_randomness: PASSED")

    def test_generate_pans_structure(self):
        """Test that PANs have correct structure."""
        pans = _generate_pans()

        # Should be 25 lists (one per RAIDA)
        self.assertEqual(len(pans), CC_RAIDA_COUNT)
        self.assertEqual(len(pans), 25)

        # Each list should have 10 PANs (one per new coin)
        for raida_pans in pans:
            self.assertEqual(len(raida_pans), 10)

        # Each PAN should be 16 bytes
        for raida_pans in pans:
            for pan in raida_pans:
                self.assertEqual(len(pan), 16)

        print("test_generate_pans_structure: PASSED")

    def test_generate_pans_uniqueness(self):
        """Test that all PANs are unique."""
        pans = _generate_pans()

        # Flatten all PANs
        all_pans = [pan for raida_pans in pans for pan in raida_pans]
        self.assertEqual(len(all_pans), 250)  # 25 RAIDAs × 10 coins

        # Check uniqueness using hex representation
        unique_pans = set(p.hex() for p in all_pans)
        self.assertEqual(len(unique_pans), 250)

        print("test_generate_pans_uniqueness: PASSED")

    def test_denomination_codes(self):
        """Test denomination code mappings."""
        # Value to code
        self.assertEqual(DENOM_TO_CODE[0.1], -1)
        self.assertEqual(DENOM_TO_CODE[1], 0)
        self.assertEqual(DENOM_TO_CODE[10], 1)
        self.assertEqual(DENOM_TO_CODE[100], 2)
        self.assertEqual(DENOM_TO_CODE[1000], 3)

        # Code to value
        self.assertEqual(CODE_TO_DENOM[-1], 0.1)
        self.assertEqual(CODE_TO_DENOM[0], 1)
        self.assertEqual(CODE_TO_DENOM[1], 10)
        self.assertEqual(CODE_TO_DENOM[2], 100)
        self.assertEqual(CODE_TO_DENOM[3], 1000)

        print("test_denomination_codes: PASSED")


# ============================================================================
# TESTS FOR COIN_BREAK: Data Structures
# ============================================================================

class TestCoinBreakDataStructures(unittest.TestCase):
    """Tests for coin_break.py data structures."""

    def test_coin_to_break_creation(self):
        """Test CoinToBreak dataclass creation."""
        ans = [os.urandom(16) for _ in range(25)]

        coin = CoinToBreak(
            serial_number=12345678,
            denomination=2,
            ans=ans,
            file_path="/path/to/coin.bin"
        )

        self.assertEqual(coin.serial_number, 12345678)
        self.assertEqual(coin.denomination, 2)
        self.assertEqual(len(coin.ans), 25)
        self.assertEqual(coin.file_path, "/path/to/coin.bin")

        print("test_coin_to_break_creation: PASSED")

    def test_coin_to_break_get_value(self):
        """Test CoinToBreak.get_value() method."""
        for denom_code, expected_value in CODE_TO_DENOM.items():
            coin = CoinToBreak(
                serial_number=1,
                denomination=denom_code
            )
            self.assertEqual(coin.get_value(), expected_value)

        print("test_coin_to_break_get_value: PASSED")

    def test_break_result_success(self):
        """Test BreakResult dataclass for success case."""
        result = BreakResult(
            success=True,
            original_coin=CoinToBreak(serial_number=1, denomination=2),
            new_coins=[],  # Would be populated with LockerCoins
            raida_statuses=[250] * 25,
            pass_count=25,
            error_message=""
        )

        self.assertTrue(result.success)
        self.assertEqual(result.pass_count, 25)
        self.assertEqual(result.error_message, "")

        print("test_break_result_success: PASSED")

    def test_break_result_failure(self):
        """Test BreakResult dataclass for failure case."""
        result = BreakResult(
            success=False,
            original_coin=None,
            new_coins=[],
            raida_statuses=[0] * 25,
            pass_count=5,
            error_message="Consensus failed"
        )

        self.assertFalse(result.success)
        self.assertEqual(result.pass_count, 5)
        self.assertEqual(result.error_message, "Consensus failed")

        print("test_break_result_failure: PASSED")


# ============================================================================
# TESTS FOR COIN_BREAK: Constants
# ============================================================================

class TestCoinBreakConstants(unittest.TestCase):
    """Tests for coin_break.py constants."""

    def test_min_consensus(self):
        """Test minimum consensus requirement."""
        self.assertEqual(MIN_CONSENSUS, 13)
        # Should be majority of 25 RAIDAs
        self.assertGreater(MIN_CONSENSUS, 25 // 2)

        print("test_min_consensus: PASSED")

    def test_sn_range(self):
        """Test serial number range constants."""
        self.assertEqual(MIN_STARTING_SN, 100_000)
        self.assertEqual(MAX_STARTING_SN, 16_777_215)

        # Must leave room for 10 sequential SNs
        self.assertGreater(MAX_STARTING_SN - MIN_STARTING_SN, 10)

        print("test_sn_range: PASSED")

    def test_status_codes(self):
        """Test status code constants."""
        self.assertEqual(STATUS_SUCCESS, 250)

        print("test_status_codes: PASSED")


# ============================================================================
# TESTS FOR BYTE ORDER VERIFICATION
# ============================================================================

class TestByteOrder(unittest.TestCase):
    """Specific tests to verify big-endian byte order is used consistently."""

    def test_payload_serial_number_byte_order(self):
        """Verify payload serial numbers use big-endian."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        # Test with max valid serial number
        max_sn = 16777215  # 0x00FFFFFF

        err, payload, _ = build_make_change_payload(
            original_dn=2,
            original_sn=max_sn,
            original_an=original_an,
            starting_sn=max_sn,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Big-endian: most significant byte first
        # 0x00FFFFFF = [0x00, 0xFF, 0xFF, 0xFF]
        self.assertEqual(payload[17:21], bytes([0x00, 0xFF, 0xFF, 0xFF]))
        self.assertEqual(payload[37:41], bytes([0x00, 0xFF, 0xFF, 0xFF]))

        print("test_payload_serial_number_byte_order: PASSED")

    def test_header_serial_number_byte_order(self):
        """Verify header serial number uses big-endian."""
        test_sn = 0x01020304

        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=1,
            serial_number=test_sn
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Bytes 18-21: Serial number in big-endian
        self.assertEqual(header[18:22], bytes([0x01, 0x02, 0x03, 0x04]))

        print("test_header_serial_number_byte_order: PASSED")

    def test_complete_request_uses_big_endian(self):
        """Verify complete request uses big-endian throughout."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        original_sn = 0xAABBCCDD
        starting_sn = 0x11223344

        err, request, _, _ = build_complete_make_change_request(
            raida_id=0,
            original_dn=2,
            original_sn=original_sn,
            original_an=original_an,
            starting_sn=starting_sn,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Header serial number at bytes 18-21 (big-endian)
        self.assertEqual(request[18:22], bytes([0xAA, 0xBB, 0xCC, 0xDD]))

        print("test_complete_request_uses_big_endian: PASSED")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for CloudCoin Break (Make Change) Functionality")
    print("=" * 70)
    unittest.main(verbosity=2)
