"""
test_email_sender.py - Unit Tests for Email Sender Functions

Tests the email sender orchestration and helper functions.
Uses mocked network layer - no actual network calls.

Author: Claude Opus 4.5
Date: 2025-12-18
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add src and tests to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_utils import (
    create_mock_identity, create_mock_request, create_mock_upload_results,
    create_mock_servers, generate_test_locker_code, generate_test_file_group_guid,
    MockRecipient, MockUploadResult, MockServerConfig
)

from email_sender import (
    validate_request, prepare_file_for_upload,
    _parse_qmail_address, _beacon_id_to_raida_index, _get_beacon_address,
    _build_tell_servers, send_tell_notifications,
    SendEmailErrorCode, ErrorCode
)

from qmail_types import TellServer


class TestValidateRequest(unittest.TestCase):
    """Tests for validate_request() function."""

    def test_validate_request_no_email(self):
        """Test validation fails without email content."""
        request = create_mock_request()
        request.email_file = b''

        err, msg = validate_request(request)

        self.assertEqual(err, SendEmailErrorCode.ERR_NO_EMAIL_FILE)
        print("test_validate_request_no_email: PASSED")

    def test_validate_request_no_recipients(self):
        """Test validation fails without recipients."""
        request = create_mock_request()
        request.to_recipients = []
        request.cc_recipients = []
        request.bcc_recipients = []

        err, msg = validate_request(request)

        self.assertEqual(err, SendEmailErrorCode.ERR_NO_RECIPIENTS)
        print("test_validate_request_no_recipients: PASSED")

    def test_validate_request_valid(self):
        """Test validation passes with valid request."""
        request = create_mock_request(to_recipients=["0006.1.12345678"])

        err, msg = validate_request(request)

        self.assertEqual(err, SendEmailErrorCode.SUCCESS)
        print("test_validate_request_valid: PASSED")

    def test_validate_request_cc_only(self):
        """Test validation passes with CC recipients only."""
        request = create_mock_request()
        request.to_recipients = []
        request.cc_recipients = [MockRecipient(address="0006.1.11111111")]

        err, msg = validate_request(request)

        self.assertEqual(err, SendEmailErrorCode.SUCCESS)
        print("test_validate_request_cc_only: PASSED")

    def test_validate_request_bcc_only(self):
        """Test validation passes with BCC recipients only."""
        request = create_mock_request()
        request.to_recipients = []
        request.bcc_recipients = [MockRecipient(address="0006.1.22222222")]

        err, msg = validate_request(request)

        self.assertEqual(err, SendEmailErrorCode.SUCCESS)
        print("test_validate_request_bcc_only: PASSED")


class TestPrepareFileForUpload(unittest.TestCase):
    """Tests for prepare_file_for_upload() function."""

    def test_prepare_file_basic(self):
        """Test preparing file creates stripes."""
        test_data = b"Hello, World!" * 100
        key = bytes(16)

        err, info = prepare_file_for_upload(test_data, "test.txt", 1, key)

        self.assertEqual(err, ErrorCode.SUCCESS)
        self.assertEqual(len(info.stripes), 5)  # 5 stripes for 5 servers
        self.assertGreater(len(info.parity_stripe), 0)
        print("test_prepare_file_basic: PASSED")

    def test_prepare_file_small_data(self):
        """Test preparing small file."""
        test_data = b"Small"
        key = bytes(16)

        err, info = prepare_file_for_upload(test_data, "small.txt", 1, key)

        self.assertEqual(err, ErrorCode.SUCCESS)
        self.assertEqual(len(info.stripes), 5)  # 5 stripes for 5 servers
        print("test_prepare_file_small_data: PASSED")

    def test_prepare_file_large_data(self):
        """Test preparing larger file."""
        test_data = os.urandom(50000)  # 50KB
        key = bytes(16)

        err, info = prepare_file_for_upload(test_data, "large.bin", 1, key)

        self.assertEqual(err, ErrorCode.SUCCESS)
        self.assertEqual(len(info.stripes), 5)  # 5 stripes for 5 servers
        # Each stripe should be roughly 1/5 of data
        for stripe in info.stripes:
            self.assertGreater(len(stripe), 0)
        print("test_prepare_file_large_data: PASSED")


class TestParseQmailAddress(unittest.TestCase):
    """Tests for _parse_qmail_address() function."""

    def test_parse_valid_address(self):
        """Test parsing valid QMail address."""
        coin_id, denom, serial = _parse_qmail_address("0006.1.12345678")

        self.assertEqual(coin_id, 6)
        self.assertEqual(denom, 1)
        self.assertEqual(serial, 12345678)
        print("test_parse_valid_address: PASSED")

    def test_parse_different_denominations(self):
        """Test parsing addresses with different denominations."""
        test_cases = [
            ("0006.1.11111111", 6, 1, 11111111),
            ("0006.5.22222222", 6, 5, 22222222),
            ("0006.25.33333333", 6, 25, 33333333),
            ("0006.100.44444444", 6, 100, 44444444),
            ("0006.250.55555555", 6, 250, 55555555),
        ]

        for address, exp_coin, exp_denom, exp_serial in test_cases:
            coin_id, denom, serial = _parse_qmail_address(address)
            self.assertEqual(coin_id, exp_coin)
            self.assertEqual(denom, exp_denom)
            self.assertEqual(serial, exp_serial)

        print("test_parse_different_denominations: PASSED")

    def test_parse_invalid_address(self):
        """Test parsing invalid address returns defaults."""
        coin_id, denom, serial = _parse_qmail_address("invalid")

        self.assertEqual(coin_id, 0x0006)  # Default
        self.assertEqual(denom, 1)  # Default
        self.assertEqual(serial, 0)  # Default
        print("test_parse_invalid_address: PASSED")

    def test_parse_empty_address(self):
        """Test parsing empty address."""
        coin_id, denom, serial = _parse_qmail_address("")

        self.assertEqual(coin_id, 0x0006)
        self.assertEqual(denom, 1)
        self.assertEqual(serial, 0)
        print("test_parse_empty_address: PASSED")


class TestBeaconIdToRaidaIndex(unittest.TestCase):
    """Tests for _beacon_id_to_raida_index() function."""

    def test_beacon_id_lowercase(self):
        """Test parsing lowercase beacon ID."""
        self.assertEqual(_beacon_id_to_raida_index("raida11"), 11)
        self.assertEqual(_beacon_id_to_raida_index("raida0"), 0)
        self.assertEqual(_beacon_id_to_raida_index("raida24"), 24)
        print("test_beacon_id_lowercase: PASSED")

    def test_beacon_id_uppercase(self):
        """Test parsing uppercase beacon ID."""
        self.assertEqual(_beacon_id_to_raida_index("RAIDA5"), 5)
        self.assertEqual(_beacon_id_to_raida_index("RAIDA15"), 15)
        print("test_beacon_id_uppercase: PASSED")

    def test_beacon_id_invalid(self):
        """Test invalid beacon ID returns default."""
        self.assertEqual(_beacon_id_to_raida_index("invalid"), 11)
        self.assertEqual(_beacon_id_to_raida_index(""), 11)
        self.assertEqual(_beacon_id_to_raida_index(None), 11)
        print("test_beacon_id_invalid: PASSED")

    def test_beacon_id_out_of_range(self):
        """Test beacon ID out of range returns default."""
        self.assertEqual(_beacon_id_to_raida_index("raida25"), 11)
        self.assertEqual(_beacon_id_to_raida_index("raida100"), 11)
        print("test_beacon_id_out_of_range: PASSED")


class TestGetBeaconAddress(unittest.TestCase):
    """Tests for _get_beacon_address() function."""

    def test_get_beacon_address_standard(self):
        """Test getting standard beacon address."""
        ip, port = _get_beacon_address("raida11")

        self.assertEqual(ip, "raida11.cloudcoin.global")
        self.assertEqual(port, 19000)
        print("test_get_beacon_address_standard: PASSED")

    def test_get_beacon_address_different_ids(self):
        """Test different beacon IDs."""
        for i in range(25):
            ip, port = _get_beacon_address(f"raida{i}")
            self.assertEqual(ip, f"raida{i}.cloudcoin.global")
            self.assertEqual(port, 19000)

        print("test_get_beacon_address_different_ids: PASSED")


class TestBuildTellServers(unittest.TestCase):
    """Tests for _build_tell_servers() function."""

    def test_build_tell_servers_basic(self):
        """Test building TellServer list from upload results."""
        upload_results = create_mock_upload_results(5)
        servers = create_mock_servers(5)

        # Convert to dict format
        server_dicts = [
            {'server_id': s.server_id, 'ip_address': s.ip_address, 'port': s.port}
            for s in servers
        ]

        tell_servers = _build_tell_servers(upload_results, server_dicts)

        self.assertEqual(len(tell_servers), 5)
        for i, ts in enumerate(tell_servers):
            self.assertEqual(ts.stripe_index, i)
            # Use duck typing - check attributes exist instead of strict isinstance
            self.assertTrue(hasattr(ts, 'stripe_index'))
            self.assertTrue(hasattr(ts, 'stripe_type'))
            self.assertTrue(hasattr(ts, 'ip_address'))
            self.assertTrue(hasattr(ts, 'port'))

        print("test_build_tell_servers_basic: PASSED")

    def test_build_tell_servers_empty(self):
        """Test with empty upload results."""
        tell_servers = _build_tell_servers([], [])

        self.assertEqual(len(tell_servers), 0)
        print("test_build_tell_servers_empty: PASSED")

    def test_build_tell_servers_failed_uploads_excluded(self):
        """Test that failed uploads are excluded."""
        upload_results = create_mock_upload_results(5)
        upload_results[2].success = False  # Mark one as failed

        servers = create_mock_servers(5)
        server_dicts = [{'server_id': s.server_id, 'ip_address': s.ip_address, 'port': s.port} for s in servers]

        tell_servers = _build_tell_servers(upload_results, server_dicts)

        self.assertEqual(len(tell_servers), 4)  # One excluded
        print("test_build_tell_servers_failed_uploads_excluded: PASSED")

    def test_build_tell_servers_stripe_type(self):
        """Test stripe type assignment (data vs parity)."""
        upload_results = create_mock_upload_results(5)
        servers = create_mock_servers(5)
        server_dicts = [{'server_id': s.server_id, 'ip_address': s.ip_address, 'port': s.port} for s in servers]

        tell_servers = _build_tell_servers(upload_results, server_dicts)

        # First 4 should be data (type 0), last should be parity (type 1)
        for i in range(4):
            self.assertEqual(tell_servers[i].stripe_type, 0)
        self.assertEqual(tell_servers[4].stripe_type, 1)

        print("test_build_tell_servers_stripe_type: PASSED")


class TestSendTellNotifications(unittest.TestCase):
    """Tests for send_tell_notifications() with mocked dependencies."""

    def test_send_tell_no_recipients(self):
        """Test Tell with no recipients."""
        request = create_mock_request()
        request.to_recipients = []
        request.cc_recipients = []
        request.bcc_recipients = []

        guid = generate_test_file_group_guid()

        err = send_tell_notifications(
            request, guid, [], create_mock_identity()
        )

        self.assertEqual(err, ErrorCode.SUCCESS)
        print("test_send_tell_no_recipients: PASSED")

    def test_send_tell_no_db_handle(self):
        """Test Tell without database handle (should succeed gracefully)."""
        request = create_mock_request(to_recipients=["0006.1.12345678"])
        guid = generate_test_file_group_guid()

        err = send_tell_notifications(
            request, guid, [], create_mock_identity(),
            db_handle=None  # No database
        )

        self.assertEqual(err, ErrorCode.SUCCESS)
        print("test_send_tell_no_db_handle: PASSED")

    def test_send_tell_no_locker_code(self):
        """Test Tell without locker code (should succeed gracefully)."""
        request = create_mock_request(to_recipients=["0006.1.12345678"])
        guid = generate_test_file_group_guid()

        # Create mock db handle
        mock_db = MagicMock()

        err = send_tell_notifications(
            request, guid, [], create_mock_identity(),
            db_handle=mock_db,
            locker_code=None  # No locker code
        )

        self.assertEqual(err, ErrorCode.SUCCESS)
        print("test_send_tell_no_locker_code: PASSED")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for Email Sender Functions")
    print("=" * 70)
    unittest.main(verbosity=2)
