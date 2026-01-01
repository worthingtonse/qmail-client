"""
test_make_change_protocol.py - Unit Tests for Make Change Protocol Functions

Tests the protocol.py Make Change functions independently.
No dependencies on coin_break.py.

Author: Claude Opus 4.5
Date: 2025-12-22
"""

import os
import sys
import struct
import unittest
import zlib

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from protocol import (
    build_make_change_payload, build_make_change_header,
    build_complete_make_change_request, ProtocolErrorCode,
    CMD_MAKE_CHANGE, CMD_GROUP_CHANGE, ENC_NONE
)

# Constants alignment for server-true testing
# Matches protocol.c and cmd_locker.c requirements
TEST_CMD_GROUP = 8  # Server Group 8 (Locker)
TEST_CMD_CODE = 90   # Server Command 90 (Make Change)
TEST_ENC_TYPE = 0   # Plaintext Type 0 as requested

# Valid SNs within the server-enforced range: 32,768 - 131,071
SAFE_ORIGINAL_SN = 40000
SAFE_STARTING_SN = 50000


def generate_test_an():
    """Generate a random 16-byte AN for testing."""
    return os.urandom(16)


def verify_challenge_format(challenge):
    """Verify that a challenge has correct format (12 random + 4 CRC)."""
    if not challenge or len(challenge) != 16:
        return False
    random_bytes = challenge[:12]
    crc_bytes = challenge[12:16]
    expected_crc = zlib.crc32(random_bytes) & 0xFFFFFFFF
    actual_crc = struct.unpack('>I', crc_bytes)[0]
    return expected_crc == actual_crc


class TestBuildMakeChangePayload(unittest.TestCase):
    """Tests for build_make_change_payload() function."""

    def test_build_make_change_payload_valid(self):
        """Test building payload with valid parameters within safe SN range."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, payload, challenge = build_make_change_payload(
            original_dn=2,
            original_sn=SAFE_ORIGINAL_SN,
            original_an=original_an,
            starting_sn=SAFE_STARTING_SN,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(payload), 203)
        self.assertEqual(len(challenge), 16)
        self.assertTrue(verify_challenge_format(challenge))
        print("test_build_make_change_payload_valid: PASSED")

    def test_build_make_change_payload_big_endian_serial_numbers(self):
        """Test that serial numbers are encoded in big-endian format."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        # Use SNs that fit in the server range but have clear byte patterns
        original_sn = 0x00010000 # 65536
        starting_sn = 0x000186A0 # 100000

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
        self.assertEqual(original_sn_bytes, bytes([0x00, 0x01, 0x00, 0x00]))

        # Starting SN at bytes 37-40 (big-endian)
        starting_sn_bytes = payload[37:41]
        self.assertEqual(starting_sn_bytes, bytes([0x00, 0x01, 0x86, 0xA0]))

        # Verify we can unpack correctly with big-endian
        unpacked_orig = struct.unpack('>I', payload[17:21])[0]
        unpacked_start = struct.unpack('>I', payload[37:41])[0]
        self.assertEqual(unpacked_orig, original_sn)
        self.assertEqual(unpacked_start, starting_sn)

        print("test_build_make_change_payload_big_endian_serial_numbers: PASSED")

    def test_build_make_change_payload_structure(self):
        """Test that payload structure matches specification."""
        original_an = b'\xAA' * 16
        pans = [bytes([i] * 16) for i in range(10)]

        # SNs 40000 (0x9C40) and 80000 (0x13880)
        err, payload, challenge = build_make_change_payload(
            original_dn=3,
            original_sn=40000,
            original_an=original_an,
            starting_sn=80000,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Bytes 0-15: Challenge
        self.assertEqual(payload[0:16], challenge)

        # Byte 16: Denomination code
        self.assertEqual(payload[16], 3)

        # Bytes 17-20: Original SN (big-endian)
        self.assertEqual(payload[17:21], bytes([0x00, 0x00, 0x9C, 0x40]))

        # Bytes 21-36: Original AN (Offset 21 matches cmd_locker.c:1060)
        self.assertEqual(payload[21:37], original_an)

        # Bytes 37-40: Starting SN (big-endian)
        self.assertEqual(payload[37:41], bytes([0x00, 0x01, 0x38, 0x80]))

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
            original_sn=SAFE_ORIGINAL_SN,
            original_an=original_an,
            starting_sn=SAFE_STARTING_SN,
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
            original_sn=SAFE_ORIGINAL_SN,
            original_an=bytes(5),  # Too short
            starting_sn=SAFE_STARTING_SN,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_make_change_payload_invalid_an: PASSED")

    def test_build_make_change_payload_invalid_pans_count(self):
        """Test payload with wrong number of PANs."""
        original_an = generate_test_an()

        # Too few PANs
        err, _, _ = build_make_change_payload(
            original_dn=1, original_sn=SAFE_ORIGINAL_SN, original_an=original_an,
            starting_sn=SAFE_STARTING_SN, pans=[os.urandom(16) for _ in range(5)]
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        # Too many PANs
        err, _, _ = build_make_change_payload(
            original_dn=1, original_sn=SAFE_ORIGINAL_SN, original_an=original_an,
            starting_sn=SAFE_STARTING_SN, pans=[os.urandom(16) for _ in range(15)]
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_payload_invalid_pans_count: PASSED")


class TestBuildMakeChangeHeader(unittest.TestCase):
    """Tests for build_make_change_header() function."""

    def test_build_make_change_header_valid(self):
        """Test building header with valid parameters."""
        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=2,
            serial_number=SAFE_ORIGINAL_SN
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
            serial_number=SAFE_ORIGINAL_SN
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Command Group at byte 4 = 8 (Locker Services) per protocol.c:134
        self.assertEqual(header[4], CMD_GROUP_CHANGE)
        self.assertEqual(header[4], TEST_CMD_GROUP)

        # Command Code at byte 5 = 90 (Make Change) per protocol.c:144
        self.assertEqual(header[5], CMD_MAKE_CHANGE)
        self.assertEqual(header[5], TEST_CMD_CODE)

        print("test_build_make_change_header_command_group_and_code: PASSED")

    def test_build_make_change_header_encryption_type(self):
        """Test that header uses encryption type 0 (plaintext)."""
        err, header = build_make_change_header(
            raida_id=10,
            body_length=203,
            denomination=2,
            serial_number=SAFE_ORIGINAL_SN,
            encryption_type=TEST_ENC_TYPE
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Encryption type at byte 16 = 0 (Plaintext)
        self.assertEqual(header[16], ENC_NONE)
        self.assertEqual(header[16], 0)

        print("test_build_make_change_header_encryption_type: PASSED")

    def test_build_make_change_header_all_raida_ids(self):
        """Test header with all valid RAIDA IDs (0-24)."""
        for raida_id in range(25):
            err, header = build_make_change_header(
                raida_id=raida_id,
                body_length=203,
                denomination=1,
                serial_number=SAFE_ORIGINAL_SN
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
            serial_number=SAFE_ORIGINAL_SN
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        err, _ = build_make_change_header(
            raida_id=-1,
            body_length=203,
            denomination=1,
            serial_number=SAFE_ORIGINAL_SN
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_make_change_header_invalid_raida: PASSED")

    def test_build_make_change_header_serial_number_big_endian(self):
        """Test that serial number in header is big-endian."""
        serial_number = 0x000186A0 # 100000

        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=2,
            serial_number=serial_number
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Serial number at bytes 18-21 (4 bytes, big-endian)
        sn_bytes = header[18:22]
        self.assertEqual(sn_bytes, bytes([0x00, 0x01, 0x86, 0xA0]))

        print("test_build_make_change_header_serial_number_big_endian: PASSED")


class TestBuildCompleteMakeChangeRequest(unittest.TestCase):
    """Tests for build_complete_make_change_request() function."""

    def test_build_complete_make_change_request_valid(self):
        """Test building complete request with valid parameters."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        err, request, challenge, nonce = build_complete_make_change_request(
            raida_id=0,
            original_dn=2,
            original_sn=SAFE_ORIGINAL_SN,
            original_an=original_an,
            starting_sn=SAFE_STARTING_SN,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(request), 32 + 203)  # Header + plaintext payload
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
            original_sn=SAFE_ORIGINAL_SN,
            original_an=original_an,
            starting_sn=SAFE_STARTING_SN,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        header = request[:32]
        # RAIDA ID
        self.assertEqual(header[2], 5)
        # Command Group
        self.assertEqual(header[4], TEST_CMD_GROUP)
        # Command Code
        self.assertEqual(header[5], TEST_CMD_CODE)
        # Encryption type
        self.assertEqual(header[16], TEST_ENC_TYPE)

        print("test_build_complete_make_change_request_header_correct: PASSED")

    def test_build_complete_make_change_request_all_raidas(self):
        """Test building request for all 25 RAIDAs."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        for raida_id in range(25):
            err, request, _, _ = build_complete_make_change_request(
                raida_id=raida_id,
                original_dn=2,
                original_sn=SAFE_ORIGINAL_SN,
                original_an=original_an,
                starting_sn=SAFE_STARTING_SN,
                pans=pans
            )

            self.assertEqual(err, ProtocolErrorCode.SUCCESS)
            self.assertEqual(request[2], raida_id)

        print("test_build_complete_make_change_request_all_raidas: PASSED")


class TestByteOrderVerification(unittest.TestCase):
    """Verify big-endian byte order is used consistently."""

    def test_payload_serial_number_byte_order(self):
        """Verify payload serial numbers use big-endian."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        safe_sn = 100000  # 0x000186A0

        err, payload, _ = build_make_change_payload(
            original_dn=2,
            original_sn=safe_sn,
            original_an=original_an,
            starting_sn=safe_sn,
            pans=pans
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Big-endian: [0x00, 0x01, 0x86, 0xA0]
        self.assertEqual(payload[17:21], bytes([0x00, 0x01, 0x86, 0xA0]))
        self.assertEqual(payload[37:41], bytes([0x00, 0x01, 0x86, 0xA0]))

        print("test_payload_serial_number_byte_order: PASSED")

    def test_header_serial_number_byte_order(self):
        """Verify header serial number uses big-endian."""
        test_sn = 0x000186A0

        err, header = build_make_change_header(
            raida_id=0,
            body_length=203,
            denomination=1,
            serial_number=test_sn
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Bytes 18-21: Serial number in big-endian
        self.assertEqual(header[18:22], bytes([0x00, 0x01, 0x86, 0xA0]))

        print("test_header_serial_number_byte_order: PASSED")

    def test_complete_request_uses_big_endian(self):
        """Verify complete request uses big-endian throughout."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        # Using 0x0001AABB (109243) and 0x0001CCDD (117981) to stay in range
        original_sn = 0x0001AABB 
        starting_sn = 0x0001CCDD

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
        self.assertEqual(request[18:22], bytes([0x00, 0x01, 0xAA, 0xBB]))

        print("test_complete_request_uses_big_endian: PASSED")


        def test_build_make_change_payload_out_of_range_sn(self):
         """Test that SNs outside the 32768-131071 range return ERR_INVALID_BODY."""
        original_an = generate_test_an()
        pans = [os.urandom(16) for _ in range(10)]

        # Test with SN too low (e.g., 100)
        err, _, _ = build_make_change_payload(
            original_dn=2, original_sn=40000, original_an=original_an,
            starting_sn=100, pans=pans
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        # Test with SN too high (e.g., 200,000)
        err, _, _ = build_make_change_payload(
            original_dn=2, original_sn=40000, original_an=original_an,
            starting_sn=200000, pans=pans
        )
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_make_change_payload_out_of_range_sn: PASSED")


if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for Make Change Protocol Functions")
    print("=" * 70)
    unittest.main(verbosity=2)