"""
test_protocol_upload.py - Unit Tests for Upload Protocol Functions

Tests the Upload command protocol building functions in protocol.py.
No network operations - pure unit tests for packet construction.

Author: Claude Opus 4.5
Date: 2025-12-18
"""

import os
import sys
import struct
import unittest
import zlib

# Add src and tests to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Note: Using manual helpers since test_utils may also be outdated
def generate_test_an(): return os.urandom(16)
def generate_test_locker_code(): return os.urandom(8)
def generate_test_file_group_guid(): return os.urandom(16)
def verify_challenge_format(challenge):
    if not challenge or len(challenge) != 16: return False
    rb = challenge[:12]
    expected_crc = struct.pack(">I", zlib.crc32(rb) & 0xFFFFFFFF)
    return challenge[12:] == expected_crc

from protocol import (
    build_upload_header, build_upload_payload, build_complete_upload_request,
    validate_upload_response, ProtocolErrorCode,
    CMD_UPLOAD, CMD_GROUP_QMAIL, ENC_NONE,
    weeks_to_duration_code
)

from qmail_types import StorageDuration


class TestBuildUploadHeader(unittest.TestCase):
    """Tests for build_upload_header() function."""

    def test_build_upload_header_valid(self):
        """Test building header with valid parameters."""
        locker_code = generate_test_locker_code()
        body_length = 1024

        err, header = build_upload_header(
            raida_id=0,
            locker_code=locker_code,
            body_length=body_length
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(header), 32)

        # Verify command group and code
        self.assertEqual(header[4], CMD_GROUP_QMAIL)  # Command Group = 6
        self.assertEqual(header[5], CMD_UPLOAD)       # Command = 60

        # Verify RAIDA ID
        self.assertEqual(header[2], 0)

        # Verify encryption type is 0 (Plaintext) for Phase I compatibility
        self.assertEqual(header[16], ENC_NONE)

        print("test_build_upload_header_valid: PASSED")

    def test_build_upload_header_all_raida_ids(self):
        """Test header with all valid RAIDA IDs (0-24)."""
        locker_code = generate_test_locker_code()

        for raida_id in range(25):
            err, header = build_upload_header(raida_id, locker_code, 128)
            self.assertEqual(err, ProtocolErrorCode.SUCCESS)
            self.assertEqual(header[2], raida_id)

        print("test_build_upload_header_all_raida_ids: PASSED")

    def test_build_upload_header_invalid_raida(self):
        """Test header with invalid RAIDA ID."""
        locker_code = generate_test_locker_code()

        err, header = build_upload_header(25, locker_code, 128)
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        err, header = build_upload_header(-1, locker_code, 128)
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)

        print("test_build_upload_header_invalid_raida: PASSED")

    def test_build_upload_header_denomination_in_header(self):
        """Test that denomination byte is placed in header index 17."""
        locker_code = generate_test_locker_code()
        err, header = build_upload_header(0, locker_code, 128, denomination=3)

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        # Byte 17 = Denomination per protocol.c:354
        self.assertEqual(header[17], 3)

        print("test_build_upload_header_denomination_in_header: PASSED")


class TestBuildUploadPayload(unittest.TestCase):
    """Tests for build_upload_payload() function."""

    def test_build_upload_payload_valid(self):
        """Test building payload with valid parameters."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()
        stripe_data = os.urandom(1000)

        err, payload, challenge = build_upload_payload(
            denomination=1,
            serial_number=12345678,
            device_id=1,
            an=an,
            file_group_guid=guid,
            locker_code=locker_code,
            storage_duration=StorageDuration.ONE_MONTH,
            stripe_data=stripe_data
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertGreater(len(payload), 0)

        # Verify challenge format
        self.assertEqual(len(challenge), 16)
        self.assertTrue(verify_challenge_format(challenge))

        print("test_build_upload_payload_valid: PASSED")

    def test_build_upload_payload_coin_type(self):
        """Test coin type in payload."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()
        stripe_data = os.urandom(100)

        err, payload, _ = build_upload_payload(
            denomination=1, serial_number=12345678, device_id=1,
            an=an, file_group_guid=guid, locker_code=locker_code,
            storage_duration=StorageDuration.ONE_MONTH, stripe_data=stripe_data
        )

        # Coin type at offset 24-25
        coin_type = struct.unpack('>H', payload[24:26])[0]
        self.assertEqual(coin_type, 0x0006)

        print("test_build_upload_payload_coin_type: PASSED")

    def test_build_upload_payload_file_guid(self):
        """Test file group GUID in payload at correct offset."""
        an = generate_test_an()
        guid = b'\xAA' * 16 
        locker_code = generate_test_locker_code()
        stripe_data = os.urandom(100)

        err, payload, _ = build_upload_payload(
            denomination=1, serial_number=12345678, device_id=1,
            an=an, file_group_guid=guid, locker_code=locker_code,
            storage_duration=StorageDuration.ONE_MONTH, stripe_data=stripe_data
        )

        # GUID at offset 48-63 (following 48-byte preamble)
        # Matches cmd_qmail.c binary mapping
        stored_guid = payload[48:64]
        self.assertEqual(stored_guid, guid)

        print("test_build_upload_payload_file_guid: PASSED")

    def test_build_upload_payload_invalid_an(self):
        """Test payload with invalid AN."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        err, payload, _ = build_upload_payload(
            denomination=1, serial_number=12345678, device_id=1,
            an=bytes(5),  # Too short
            file_group_guid=guid, locker_code=locker_code,
            storage_duration=StorageDuration.ONE_MONTH, stripe_data=b'test'
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_upload_payload_invalid_an: PASSED")


class TestBuildCompleteUploadRequest(unittest.TestCase):
    """Tests for build_complete_upload_request() function."""

    def test_build_complete_upload_request(self):
        """Test building complete upload request."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()
        stripe_data = os.urandom(500)

        err, request, challenge, nonce = build_complete_upload_request(
            raida_id=5,
            denomination=1,
            serial_number=12345678,
            device_id=1,
            an=an,
            file_group_guid=guid,
            locker_code=locker_code,
            storage_duration=StorageDuration.ONE_MONTH,
            stripe_data=stripe_data
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertGreater(len(request), 32)

        # Verify RAIDA ID in header
        self.assertEqual(request[2], 5)

        # Verify challenge
        self.assertEqual(len(challenge), 16)

        print("test_build_complete_upload_request: PASSED")


class TestValidateUploadResponse(unittest.TestCase):
    """Tests for validate_upload_response() function."""

    def test_validate_upload_response_success(self):
        """Test successful upload response (Status 250 at Byte 2)."""
        challenge = os.urandom(16)

        response = bytearray(32)
        response[2] = 250  # Success at offset 2 per protocol.c:502
        response[16:32] = challenge # Challenge Echo at offset 16

        err, status, msg = validate_upload_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(status, 250)
        print("test_validate_upload_response_success: PASSED")

    def test_validate_upload_response_invalid_an(self):
        """Test invalid AN response (Status 200 at Byte 2)."""
        challenge = os.urandom(16)

        response = bytearray(32)
        response[2] = 200  # ERROR_INVALID_AN
        response[16:32] = challenge

        err, status, msg = validate_upload_response(bytes(response), challenge)

        # Triggers Reactive Healing via ERR_INVALID_BODY
        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        self.assertEqual(status, 200)
        print("test_validate_upload_response_invalid_an: PASSED")

    def test_validate_upload_response_challenge_mismatch(self):
        """Test challenge mismatch detection."""
        challenge = os.urandom(16)
        wrong_challenge = os.urandom(16)

        response = bytearray(32)
        response[2] = 250
        response[16:32] = wrong_challenge

        err, status, msg = validate_upload_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_validate_upload_response_challenge_mismatch: PASSED")

    def test_validate_upload_response_too_short(self):
        """Test response too short."""
        challenge = os.urandom(16)
        short_response = bytes(10)

        err, status, msg = validate_upload_response(short_response, challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INCOMPLETE_DATA)
        print("test_validate_upload_response_too_short: PASSED")


class TestWeeksToDurationCode(unittest.TestCase):
    """Tests for weeks_to_duration_code() function."""

    def test_weeks_to_duration_mappings(self):
        """Test standard week to duration code mappings."""
        test_cases = [
            (1, StorageDuration.ONE_WEEK),
            (2, StorageDuration.ONE_MONTH),
            (8, StorageDuration.THREE_MONTHS),
            (26, StorageDuration.SIX_MONTHS),
            (52, StorageDuration.ONE_YEAR),
            (100, StorageDuration.PERMANENT),
        ]

        for weeks, expected in test_cases:
            result = weeks_to_duration_code(weeks)
            self.assertEqual(result, expected, f"weeks={weeks}")

        print("test_weeks_to_duration_mappings: PASSED")


if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for Upload Protocol Functions")
    print("=" * 70)
    unittest.main(verbosity=2)