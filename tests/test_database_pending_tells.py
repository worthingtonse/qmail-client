"""
test_database_pending_tells.py - Unit Tests for PendingTells Database Functions

Tests the PendingTells CRUD operations in database.py.
Uses temporary SQLite database for isolation.

Author: Claude Opus 4.5
Date: 2025-12-18
"""

import os
import sys
import unittest
import tempfile
import json

# Add src and tests to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_utils import (
    generate_test_locker_code, generate_test_file_group_guid,
    create_mock_logger
)

from database import (
    init_database, close_database, DatabaseErrorCode,
    insert_pending_tell, get_pending_tells, update_pending_tell_status,
    delete_pending_tell, get_user_by_address, fix_null_beacon_ids,
    store_contact
)


class TestPendingTellsCRUD(unittest.TestCase):
    """Tests for PendingTells table CRUD operations."""

    @classmethod
    def setUpClass(cls):
        """Create temporary database for all tests."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_qmail.db")

    def setUp(self):
        """Initialize fresh database before each test."""
        # Remove existing db if present
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

        err, self.handle = init_database(self.db_path)
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertIsNotNone(self.handle)

    def tearDown(self):
        """Close database after each test."""
        if hasattr(self, 'handle') and self.handle:
            close_database(self.handle)

    @classmethod
    def tearDownClass(cls):
        """Clean up temp directory."""
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)

    def test_insert_pending_tell(self):
        """Test inserting a pending Tell."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()
        server_list = json.dumps([{"stripe_index": 0, "ip_address": "1.2.3.4", "port": 19000}])

        err, tell_id = insert_pending_tell(
            self.handle,
            file_group_guid=guid,
            recipient_address="0006.1.12345678",
            recipient_type=0,  # To
            beacon_server_id="raida11",
            locker_code=locker_code,
            server_list_json=server_list
        )

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertGreater(tell_id, 0)
        print(f"test_insert_pending_tell: PASSED (tell_id={tell_id})")

    def test_insert_pending_tell_invalid_params(self):
        """Test insert with missing parameters."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        # Missing recipient_address
        err, tell_id = insert_pending_tell(
            self.handle,
            file_group_guid=guid,
            recipient_address="",  # Empty
            recipient_type=0,
            beacon_server_id="raida11",
            locker_code=locker_code,
            server_list_json="{}"
        )

        self.assertEqual(err, DatabaseErrorCode.ERR_INVALID_PARAM)
        print("test_insert_pending_tell_invalid_params: PASSED")

    def test_get_pending_tells_empty(self):
        """Test querying empty PendingTells table."""
        err, tells = get_pending_tells(self.handle, status='pending')

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertEqual(len(tells), 0)
        print("test_get_pending_tells_empty: PASSED")

    def test_get_pending_tells_with_data(self):
        """Test querying PendingTells with data."""
        # Insert multiple tells
        for i in range(3):
            guid = generate_test_file_group_guid()
            locker_code = generate_test_locker_code()
            insert_pending_tell(
                self.handle,
                file_group_guid=guid,
                recipient_address=f"0006.1.{10000000 + i}",
                recipient_type=i % 3,
                beacon_server_id=f"raida{i}",
                locker_code=locker_code,
                server_list_json="{}"
            )

        err, tells = get_pending_tells(self.handle, status='pending')

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertEqual(len(tells), 3)

        # Verify fields populated
        for tell in tells:
            self.assertIn('tell_id', tell)
            self.assertIn('recipient_address', tell)
            self.assertIn('beacon_server_id', tell)
            self.assertEqual(tell['status'], 'pending')

        print("test_get_pending_tells_with_data: PASSED")

    def test_get_pending_tells_filter_by_status(self):
        """Test filtering by status."""
        guid1 = generate_test_file_group_guid()
        guid2 = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        # Insert pending tell
        err, tell_id1 = insert_pending_tell(
            self.handle, guid1, "0006.1.11111111", 0, "raida11",
            locker_code, "{}"
        )

        # Insert another and mark as failed
        err, tell_id2 = insert_pending_tell(
            self.handle, guid2, "0006.1.22222222", 0, "raida11",
            locker_code, "{}"
        )
        update_pending_tell_status(self.handle, tell_id2, 'failed')

        # Query pending only
        err, pending = get_pending_tells(self.handle, status='pending')
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]['tell_id'], tell_id1)

        # Query failed only
        err, failed = get_pending_tells(self.handle, status='failed')
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]['tell_id'], tell_id2)

        print("test_get_pending_tells_filter_by_status: PASSED")

    def test_update_pending_tell_status(self):
        """Test updating Tell status."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        err, tell_id = insert_pending_tell(
            self.handle, guid, "0006.1.12345678", 0, "raida11",
            locker_code, "{}"
        )
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

        # Update to sent
        err = update_pending_tell_status(
            self.handle, tell_id, 'sent', error_message=None
        )
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

        # Verify status changed
        err, tells = get_pending_tells(self.handle, status='sent')
        self.assertEqual(len(tells), 1)
        self.assertEqual(tells[0]['status'], 'sent')

        print("test_update_pending_tell_status: PASSED")

    def test_update_pending_tell_increment_retry(self):
        """Test incrementing retry count."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        err, tell_id = insert_pending_tell(
            self.handle, guid, "0006.1.12345678", 0, "raida11",
            locker_code, "{}"
        )

        # Increment retry 3 times
        for i in range(3):
            err = update_pending_tell_status(
                self.handle, tell_id, 'pending',
                error_message=f"Retry {i + 1} failed",
                increment_retry=True
            )
            self.assertEqual(err, DatabaseErrorCode.SUCCESS)

        # Verify retry count
        err, tells = get_pending_tells(self.handle, status='pending')
        self.assertEqual(len(tells), 1)
        self.assertEqual(tells[0]['retry_count'], 3)
        self.assertEqual(tells[0]['error_message'], "Retry 3 failed")

        print("test_update_pending_tell_increment_retry: PASSED")

    def test_update_pending_tell_not_found(self):
        """Test updating non-existent Tell."""
        err = update_pending_tell_status(
            self.handle, 99999, 'failed', error_message="Test"
        )

        self.assertEqual(err, DatabaseErrorCode.ERR_NOT_FOUND)
        print("test_update_pending_tell_not_found: PASSED")

    def test_delete_pending_tell(self):
        """Test deleting a pending Tell."""
        guid = generate_test_file_group_guid()
        locker_code = generate_test_locker_code()

        err, tell_id = insert_pending_tell(
            self.handle, guid, "0006.1.12345678", 0, "raida11",
            locker_code, "{}"
        )

        # Verify exists
        err, tells = get_pending_tells(self.handle, status='pending')
        self.assertEqual(len(tells), 1)

        # Delete
        err = delete_pending_tell(self.handle, tell_id)
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

        # Verify deleted
        err, tells = get_pending_tells(self.handle, status='pending')
        self.assertEqual(len(tells), 0)

        print("test_delete_pending_tell: PASSED")

    def test_delete_pending_tell_not_found(self):
        """Test deleting non-existent Tell."""
        err = delete_pending_tell(self.handle, 99999)
        self.assertEqual(err, DatabaseErrorCode.ERR_NOT_FOUND)
        print("test_delete_pending_tell_not_found: PASSED")


class TestGetUserByAddress(unittest.TestCase):
    """Tests for get_user_by_address() function."""

    @classmethod
    def setUpClass(cls):
        """Create temporary database."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_qmail.db")

    def setUp(self):
        """Initialize fresh database."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        err, self.handle = init_database(self.db_path)
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

    def tearDown(self):
        """Close database."""
        if hasattr(self, 'handle') and self.handle:
            close_database(self.handle)

    @classmethod
    def tearDownClass(cls):
        """Clean up temp directory."""
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)

    def test_get_user_by_address_found(self):
        """Test finding existing user by address."""
        # Insert a user
        contact = {
            'first_name': 'John',
            'last_name': 'Doe',
            'auto_address': '0006.1.12345678',
            'beacon_id': 'raida5',
            'description': 'Test user'
        }
        err, user_id = store_contact(self.handle, contact)
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

        # Look up by address
        err, user = get_user_by_address(self.handle, '0006.1.12345678')

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertIsNotNone(user)
        self.assertEqual(user['first_name'], 'John')
        self.assertEqual(user['beacon_id'], 'raida5')

        print("test_get_user_by_address_found: PASSED")

    def test_get_user_by_address_not_found(self):
        """Test querying non-existent address."""
        err, user = get_user_by_address(self.handle, '0006.1.99999999')

        self.assertEqual(err, DatabaseErrorCode.ERR_NOT_FOUND)
        self.assertIsNone(user)

        print("test_get_user_by_address_not_found: PASSED")

    def test_get_user_by_address_empty_address(self):
        """Test with empty address."""
        err, user = get_user_by_address(self.handle, '')

        self.assertEqual(err, DatabaseErrorCode.ERR_INVALID_PARAM)
        self.assertIsNone(user)

        print("test_get_user_by_address_empty_address: PASSED")


class TestFixNullBeaconIds(unittest.TestCase):
    """Tests for fix_null_beacon_ids() function."""

    @classmethod
    def setUpClass(cls):
        """Create temporary database."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_qmail.db")

    def setUp(self):
        """Initialize fresh database."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        err, self.handle = init_database(self.db_path)
        self.assertEqual(err, DatabaseErrorCode.SUCCESS)

    def tearDown(self):
        """Close database."""
        if hasattr(self, 'handle') and self.handle:
            close_database(self.handle)

    @classmethod
    def tearDownClass(cls):
        """Clean up temp directory."""
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)

    def test_fix_null_beacon_ids(self):
        """Test fixing users with null beacon IDs."""
        # Insert users with null/empty beacon_id
        users = [
            {'first_name': 'User1', 'last_name': 'Test', 'auto_address': '0006.1.11111111', 'beacon_id': None},
            {'first_name': 'User2', 'last_name': 'Test', 'auto_address': '0006.1.22222222', 'beacon_id': ''},
            {'first_name': 'User3', 'last_name': 'Test', 'auto_address': '0006.1.33333333', 'beacon_id': 'raida5'},
        ]

        for user in users:
            store_contact(self.handle, user)

        # Fix null beacon IDs
        err, count = fix_null_beacon_ids(self.handle, 'raida11')

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertEqual(count, 2)  # Two users had null/empty

        # Verify all users now have beacon_id
        err, user1 = get_user_by_address(self.handle, '0006.1.11111111')
        self.assertEqual(user1['beacon_id'], 'raida11')

        err, user2 = get_user_by_address(self.handle, '0006.1.22222222')
        self.assertEqual(user2['beacon_id'], 'raida11')

        # User3 should still have original beacon
        err, user3 = get_user_by_address(self.handle, '0006.1.33333333')
        self.assertEqual(user3['beacon_id'], 'raida5')

        print("test_fix_null_beacon_ids: PASSED")

    def test_fix_null_beacon_ids_none_to_fix(self):
        """Test when no users have null beacon IDs."""
        # Insert user with valid beacon
        user = {'first_name': 'User', 'last_name': 'Test', 'auto_address': '0006.1.11111111', 'beacon_id': 'raida0'}
        store_contact(self.handle, user)

        err, count = fix_null_beacon_ids(self.handle, 'raida11')

        self.assertEqual(err, DatabaseErrorCode.SUCCESS)
        self.assertEqual(count, 0)

        print("test_fix_null_beacon_ids_none_to_fix: PASSED")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("  Running Unit Tests for PendingTells Database Functions")
    print("=" * 70)
    unittest.main(verbosity=2)
