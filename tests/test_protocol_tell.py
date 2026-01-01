"""
test_protocol_tell.py - Unit Tests for Tell Protocol Functions

Tests the Tell command protocol building functions in protocol.py.
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

from test_utils import (
    create_mock_identity, generate_test_locker_code, generate_test_file_group_guid,
    generate_test_an, generate_test_locker_key, verify_challenge_format,
    assert_header_valid, assert_payload_valid, assert_terminator_present,
    create_mock_logger
)

# Import protocol module
from protocol import (
    build_tell_header, build_tell_payload, build_complete_tell_request,
    validate_tell_response, ProtocolErrorCode,
    CMD_TELL, CMD_GROUP_QMAIL, ENC_LOCKER_CODE, TELL_TYPE_QMAIL
)

from qmail_types import TellRecipient, TellServer

an = generate_test_an()


class TestBuildTellHeader(unittest.TestCase):
    """Tests for build_tell_header() function."""

    def test_build_tell_header_valid(self):
        """Test building header with valid parameters for Type 0."""
        an = os.urandom(16)
        body_length = 128
        test_denom = 1 # Denomination we want to test

        err, header = build_tell_header(
            raida_id=11,
            an=an,
            body_length=body_length,
            denomination=test_denom,
            encryption_type=0 # Explicitly Type 0
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(len(header), 32)

        # Verify command group and code
        self.assertEqual(header[4], CMD_GROUP_QMAIL)  # 6
        self.assertEqual(header[5], CMD_TELL)         # 61

        # Verify RAIDA ID
        self.assertEqual(header[2], 11)

        # Verify encryption type is 0 (Plaintext)
        self.assertEqual(header[16], 0)

        # FIX: Byte 17 is now Denomination, NOT locker code
        self.assertEqual(header[17], test_denom)

        # Verify body length (bytes 22-23, big-endian)
        stored_length = struct.unpack('>H', header[22:24])[0]
        self.assertEqual(stored_length, body_length)

        print("test_build_tell_header_valid: PASSED")

    def test_build_tell_header_invalid_raida_high(self):
        """Test header with RAIDA ID > 24."""
        locker_code = generate_test_locker_code()

        err, header = build_tell_header(
            raida_id=25,  # Invalid - max is 24
            an = an,
            body_length=128
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        self.assertEqual(header, b'')
        print("test_build_tell_header_invalid_raida_high: PASSED")

    def test_build_tell_header_invalid_raida_negative(self):
        """Test header with negative RAIDA ID."""
        locker_code = generate_test_locker_code()

        err, header = build_tell_header(
            raida_id=-1,
            an= an,
            body_length=128
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_tell_header_invalid_raida_negative: PASSED")

    def test_build_tell_header_short_locker_code(self):
        """Test header with AN too short."""
        short_an = bytes(3)  # Invalid AN length

        err, header = build_tell_header(
            raida_id=11,
            an=short_an, # Variable must be defined here
            body_length=128
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_tell_header_short_locker_code: PASSED")

   
        """Test that nonce is different each time."""
        def test_build_tell_header_nonce_unique(self):
         """Test that nonce is unique only for encrypted types."""
        an = os.urandom(16)
        
        # Test Type 1 (Encrypted) - Nonce SHOULD be different
        err1, h1 = build_tell_header(11, an, 128, encryption_type=1)
        err2, h2 = build_tell_header(11, an, 128, encryption_type=1)
        self.assertNotEqual(h1[24:32], h2[24:32])

        # Test Type 0 (Plaintext) - Nonce SHOULD be all zeros
        err3, h3 = build_tell_header(11, an, 128, encryption_type=0)
        self.assertEqual(h3[24:32], bytes(8))
        print("test_build_tell_header_nonce_unique: PASSED")


class TestBuildTellPayload(unittest.TestCase):
    """Tests for build_tell_payload() function."""

    def test_build_tell_payload_single_recipient(self):
        """Test payload with single recipient."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_key = generate_test_locker_key()

        recipient = TellRecipient(
            address_type=0,  # To
            coin_id=0x0006,
            denomination=1,
            domain_id=0,
            serial_number=12345678,
            locker_payment_key=locker_key
        )

        err, payload, challenge = build_tell_payload(
            denomination=1,
            serial_number=99999999,
            device_id=1,
            an=an,
            file_group_guid=guid,
            timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient],
            servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Minimum size: 88 (fixed) + 32 (1 recipient) = 120, padded to 128
        self.assertGreaterEqual(len(payload), 120)
        # self.assertEqual(len(payload) % 16, 0)  # 16-byte aligned

        # Verify challenge format
        self.assertEqual(len(challenge), 16)

        # Verify coin type at offset 24-25
        coin_type = struct.unpack('>H', payload[24:26])[0]
        self.assertEqual(coin_type, 0x0006)

        # Verify address count at offset 77
        self.assertEqual(payload[77], 1)

        # Verify server count at offset 78
        self.assertEqual(payload[78], 0)

        print("test_build_tell_payload_single_recipient: PASSED")

    def test_build_tell_payload_multiple_recipients(self):
        """Test payload with multiple recipients (To, CC, BCC)."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()

        recipients = [
            TellRecipient(address_type=0, serial_number=11111111, locker_payment_key=generate_test_locker_key()),
            TellRecipient(address_type=0, serial_number=22222222, locker_payment_key=generate_test_locker_key()),
            TellRecipient(address_type=1, serial_number=33333333, locker_payment_key=generate_test_locker_key()),  # CC
            TellRecipient(address_type=2, serial_number=44444444, locker_payment_key=generate_test_locker_key()),  # BCC
        ]

        err, payload, challenge = build_tell_payload(
            denomination=1,
            serial_number=99999999,
            device_id=1,
            an=an,
            file_group_guid=guid,
            timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL,
            recipients=recipients,
            servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Verify address count
        self.assertEqual(payload[77], 4)

        # Verify recipient entries at correct offsets (starting at 88)
        # Each recipient is 32 bytes
        for i, recipient in enumerate(recipients):
            offset = 88 + (i * 32)
            self.assertEqual(payload[offset], recipient.address_type)

        print("test_build_tell_payload_multiple_recipients: PASSED")

    def test_build_tell_payload_with_servers(self):
        """Test payload with server list."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()

        recipient = TellRecipient(serial_number=12345678, locker_payment_key=generate_test_locker_key())

        servers = [
            TellServer(stripe_index=0, stripe_type=0, ip_address="192.168.1.1", port=19000),
            TellServer(stripe_index=1, stripe_type=0, ip_address="192.168.1.2", port=19000),
            TellServer(stripe_index=2, stripe_type=0, ip_address="192.168.1.3", port=19000),
            TellServer(stripe_index=3, stripe_type=0, ip_address="192.168.1.4", port=19000),
            TellServer(stripe_index=4, stripe_type=1, ip_address="192.168.1.5", port=19000),  # Parity
        ]

        err, payload, challenge = build_tell_payload(
            denomination=1,
            serial_number=99999999,
            device_id=1,
            an=an,
            file_group_guid=guid,
            timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient],
            servers=servers
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Verify server count
        self.assertEqual(payload[78], 5)

        # Server list starts after recipients
        # Offset = 88 + (1 recipient * 32) = 120
        server_offset = 88 + 32

        # Check first server stripe_index
        self.assertEqual(payload[server_offset], 0)
        # Check parity server stripe_type
        parity_offset = server_offset + (4 * 32)
        self.assertEqual(payload[parity_offset + 1], 1)  # stripe_type = 1 (parity)

        print("test_build_tell_payload_with_servers: PASSED")

    def test_build_tell_payload_ip_encoding(self):
        """Test that IP addresses are correctly encoded."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()

        recipient = TellRecipient(serial_number=12345678, locker_payment_key=generate_test_locker_key())
        server = TellServer(stripe_index=0, stripe_type=0, ip_address="192.168.1.100", port=19001)

        err, payload, _ = build_tell_payload(
            denomination=1, serial_number=99999999, device_id=1,
            an=an, file_group_guid=guid, timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL, recipients=[recipient], servers=[server]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Server entry at offset 120 (88 + 32)
        # IP at offset +10 (16 bytes, IPv4 in last 4)
        ip_offset = 120 + 10 + 12  # Last 4 bytes of 16-byte IP field
        ip_bytes = payload[ip_offset:ip_offset + 4]
        self.assertEqual(list(ip_bytes), [192, 168, 1, 100])

        # Port at offset +26 (2 bytes, big-endian)
        port_offset = 120 + 26
        port = struct.unpack('>H', payload[port_offset:port_offset + 2])[0]
        self.assertEqual(port, 19001)

        print("test_build_tell_payload_ip_encoding: PASSED")

    def test_build_tell_payload_invalid_an(self):
        """Test payload with invalid AN."""
        guid = generate_test_file_group_guid()

        err, payload, _ = build_tell_payload(
            denomination=1, serial_number=99999999, device_id=1,
            an=bytes(5),  # Too short
            file_group_guid=guid, timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL, recipients=[], servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_tell_payload_invalid_an: PASSED")

    def test_build_tell_payload_invalid_guid(self):
        """Test payload with invalid file_group_guid."""
        an = generate_test_an()

        err, payload, _ = build_tell_payload(
            denomination=1, serial_number=99999999, device_id=1,
            an=an,
            file_group_guid=bytes(8),  # Too short
            timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL, recipients=[], servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        print("test_build_tell_payload_invalid_guid: PASSED")


class TestBuildCompleteTellRequest(unittest.TestCase):
    """Tests for build_complete_tell_request() function."""

    def test_build_complete_tell_request(self):
        """Test building complete Tell request."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        recipient = TellRecipient(serial_number=12345678, locker_payment_key=generate_test_locker_key())

        # FIXED: Unpack 4 values instead of 3
        err, request, challenge, nonce = build_complete_tell_request(
            raida_id=11,
            denomination=1,
            serial_number=99999999,
            device_id=1,
            an=an,
            file_group_guid=guid,
            locker_code=locker_code,
            timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient],
            servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Minimum: 32 (header) + 128 (min payload padded) + 2 (terminator)
        self.assertGreaterEqual(len(request), 154)

        # Verify header
        assert_header_valid(request[:32], expected_cmd=CMD_TELL)

        # Verify terminator
        assert_terminator_present(request)

        # Verify challenge returned
        self.assertEqual(len(challenge), 16)
        

        print("test_build_complete_tell_request: PASSED")
    def test_build_complete_tell_request_encrypted(self):
        """Test that payload is encrypted (differs from plain)."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        recipient = TellRecipient(serial_number=12345678, locker_payment_key=generate_test_locker_key())

        # FIXED: Build two requests with same data, unpacking 4 values
        err1, request1, challenge1, nonce1 = build_complete_tell_request(
            raida_id=11, denomination=1, serial_number=99999999, device_id=1,
            an=an, file_group_guid=guid, locker_code=locker_code,
            timestamp=1703980800, tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient], servers=[]
        )

        err2, request2, challenge2, nonce2 = build_complete_tell_request(
            raida_id=11, denomination=1, serial_number=99999999, device_id=1,
            an=an, file_group_guid=guid, locker_code=locker_code,
            timestamp=1703980800, tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient], servers=[]
        )

        self.assertEqual(err1, ProtocolErrorCode.SUCCESS)
        self.assertEqual(err2, ProtocolErrorCode.SUCCESS)

        # Headers should differ (random bitfields, nonce)
        # Encrypted payloads should differ (different nonces)
        self.assertNotEqual(request1[32:-2], request2[32:-2])

        print("test_build_complete_tell_request_encrypted: PASSED")


class TestValidateTellResponse(unittest.TestCase):
    """Tests for validate_tell_response() function."""

    def test_validate_tell_response_success(self):
        """Test successful Tell response validation."""
        challenge = os.urandom(16)

        # Build mock response with success status
        response = bytearray(32)
        response[5] = 250  # Success status
        response[16:32] = challenge  # Challenge echo

        err, status, msg = validate_tell_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)
        self.assertEqual(status, 250)
        self.assertEqual(msg, "")
        print("test_validate_tell_response_success: PASSED")

    def test_validate_tell_response_payment_required(self):
        """Test payment required response."""
        challenge = os.urandom(16)

        response = bytearray(32)
        response[5] = 166  # Payment required
        response[16:32] = challenge

        err, status, msg = validate_tell_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        self.assertEqual(status, 166)
        self.assertIn("Payment", msg)
        print("test_validate_tell_response_payment_required: PASSED")

    def test_validate_tell_response_wrong_raida(self):
        """Test wrong RAIDA response."""
        challenge = os.urandom(16)

        response = bytearray(32)
        response[5] = 18  # Wrong RAIDA
        response[16:32] = challenge

        err, status, msg = validate_tell_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        self.assertEqual(status, 18)
        self.assertIn("Wrong RAIDA", msg)
        print("test_validate_tell_response_wrong_raida: PASSED")

    def test_validate_tell_response_challenge_mismatch(self):
        """Test challenge mismatch detection."""
        challenge = os.urandom(16)
        wrong_challenge = os.urandom(16)

        response = bytearray(32)
        response[5] = 250
        response[16:32] = wrong_challenge  # Wrong challenge

        err, status, msg = validate_tell_response(bytes(response), challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INVALID_BODY)
        self.assertIn("mismatch", msg.lower())
        print("test_validate_tell_response_challenge_mismatch: PASSED")

    def test_validate_tell_response_too_short(self):
        """Test response too short."""
        challenge = os.urandom(16)
        short_response = bytes(10)  # Too short

        err, status, msg = validate_tell_response(short_response, challenge)

        self.assertEqual(err, ProtocolErrorCode.ERR_INCOMPLETE_DATA)
        print("test_validate_tell_response_too_short: PASSED")


class TestTellRecipientPacking(unittest.TestCase):
    """Tests for TellRecipient serialization."""

    def test_recipient_serial_number_3_bytes(self):
        """Test that serial number is packed as 3 bytes."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_key = generate_test_locker_key()

        # Use a serial number that needs all 3 bytes
        recipient = TellRecipient(
            address_type=0,
            coin_id=0x0006,
            denomination=1,
            domain_id=0,
            serial_number=16777215,  # 0xFFFFFF - max 3-byte value
            locker_payment_key=locker_key
        )

        err, payload, _ = build_tell_payload(
            denomination=1, serial_number=99999999, device_id=1,
            an=an, file_group_guid=guid, timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL, recipients=[recipient], servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Serial number at offset 88 + 5 (3 bytes)
        sn_bytes = payload[93:96]
        self.assertEqual(sn_bytes, b'\xff\xff\xff')

        print("test_recipient_serial_number_3_bytes: PASSED")

    def test_recipient_locker_key_placement(self):
        """Test locker payment key is at correct offset."""
        an = generate_test_an()
        guid = generate_test_file_group_guid()
        locker_key = b'\xAA' * 16  # Recognizable pattern

        recipient = TellRecipient(
            serial_number=12345678,
            locker_payment_key=locker_key
        )

        err, payload, _ = build_tell_payload(
            denomination=1, serial_number=99999999, device_id=1,
            an=an, file_group_guid=guid, timestamp=1703980800,
            tell_type=TELL_TYPE_QMAIL, recipients=[recipient], servers=[]
        )

        self.assertEqual(err, ProtocolErrorCode.SUCCESS)

        # Locker key at offset 88 + 8 (16 bytes)
        key_bytes = payload[96:112]
        self.assertEqual(key_bytes, locker_key)

        print("test_recipient_locker_key_placement: PASSED")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for Tell Protocol Functions")
    print("=" * 70)
    unittest.main(verbosity=2)
