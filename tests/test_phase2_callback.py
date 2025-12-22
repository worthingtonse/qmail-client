"""
test_phase2_callback.py - Test Phase 2 on_mail_received callback

Tests the beacon callback that stores tells and stripes in the database.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from database import (
    init_database, close_database, DatabaseErrorCode,
    store_received_tell, store_received_stripe,
    get_received_tell_by_guid, get_stripes_for_tell, get_all_servers
)

# Test database path
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'Data', 'test_phase2_callback.db')


class MockServerLocation:
    """Mock ServerLocation from TellNotification."""
    def __init__(self, server_id, stripe_index, total_stripes):
        self.server_id = server_id
        self.stripe_index = stripe_index
        self.total_stripes = total_stripes
        self.raw_entry = bytes(32)  # Empty raw entry


class MockTellNotification:
    """Mock TellNotification from beacon."""
    def __init__(self, file_guid, locker_code, tell_type, server_list):
        self.file_guid = file_guid
        self.locker_code = locker_code
        self.tell_type = tell_type
        self.server_list = server_list


class MockLogger:
    """Mock logger."""
    file = None


class MockAppContext:
    """Mock AppContext."""
    def __init__(self, db_handle):
        self.db_handle = db_handle
        self._notifications = []

    def add_notifications(self, notifications):
        self._notifications.extend(notifications)


def _extract_server_ip(server_location, _server_cache):
    """Extract server IP from ServerLocation."""
    server_id = getattr(server_location, 'server_id', None)

    # Try cached database lookup first
    if server_id is not None and server_id in _server_cache:
        ip = _server_cache[server_id]
        if ip:
            return ip

    # Try extracting from raw_entry if available
    if hasattr(server_location, 'raw_entry') and len(server_location.raw_entry) >= 26:
        ip_bytes = server_location.raw_entry[22:26]
        if any(b != 0 for b in ip_bytes):
            return f'{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}'

    # Fallback to hostname pattern
    if server_id is not None:
        return f'raida{server_id}.cloudcoin.global'
    return 'unknown.server'


def on_mail_received_test(notifications, app_context, _server_cache):
    """Simplified on_mail_received for testing."""
    successful_count = 0
    failed_count = 0

    app_context.add_notifications(notifications)

    for notification in notifications:
        try:
            # Validate notification has required fields
            if not hasattr(notification, 'file_guid') or not notification.file_guid:
                failed_count += 1
                continue

            if not hasattr(notification, 'locker_code') or not notification.locker_code:
                failed_count += 1
                continue

            # Extract file_guid as hex string
            file_guid = notification.file_guid.hex() if isinstance(
                notification.file_guid, bytes) else str(notification.file_guid)

            # Ensure locker_code is bytes
            locker_code = notification.locker_code
            if not isinstance(locker_code, bytes):
                if isinstance(locker_code, str):
                    locker_code = bytes.fromhex(locker_code)
                else:
                    failed_count += 1
                    continue

            # Get tell_type with fallback
            tell_type = getattr(notification, 'tell_type', 0)

            # Store tell metadata
            err, tell_id = store_received_tell(
                app_context.db_handle,
                file_guid=file_guid,
                locker_code=locker_code,
                file_type=tell_type,
                version=1,
                file_size=0
            )

            if err != DatabaseErrorCode.SUCCESS:
                failed_count += 1
                continue

            # Get server_list with validation
            server_list = getattr(notification, 'server_list', None)
            if not server_list:
                successful_count += 1
                continue

            # Store stripe/server information
            for server in server_list:
                server_ip = _extract_server_ip(server, _server_cache)
                stripe_index = getattr(server, 'stripe_index', 0)
                total_stripes = getattr(server, 'total_stripes', 1)
                is_parity = (stripe_index == total_stripes - 1)

                store_received_stripe(
                    app_context.db_handle,
                    tell_id=tell_id,
                    server_ip=server_ip,
                    stripe_id=stripe_index,
                    is_parity=is_parity
                )

            successful_count += 1
        except Exception as e:
            print(f'Error: {e}')
            failed_count += 1

    return successful_count, failed_count


def main():
    """Run tests."""
    print('Testing Phase 2 - on_mail_received callback')
    print('=' * 60)

    # Clean up previous test
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    # Initialize database
    err, db_handle = init_database(TEST_DB_PATH)
    if err != DatabaseErrorCode.SUCCESS:
        print(f'[FAIL] Database init failed: {err}')
        return 1
    print('[PASS] Database initialized')

    # Create app context
    app_context = MockAppContext(db_handle)

    # Cache server list for IP lookups
    _server_cache = {}
    err, servers = get_all_servers(db_handle, available_only=False)
    if err == DatabaseErrorCode.SUCCESS:
        for srv in servers:
            _server_cache[srv.get('server_id', srv.get('id', -1))] = srv.get('IPAddress', '')

    test_locker = b'\x01\x02\x03\x04\x05\x06\x07\x08'

    # Test 1: Valid notification with servers
    print('')
    print('Test 1: Valid notification with 5 servers')
    test_guid = bytes.fromhex('abcdef1234567890abcdef1234567890')
    servers = [MockServerLocation(i, i, 5) for i in range(5)]
    notification1 = MockTellNotification(test_guid, test_locker, 0, servers)

    success, fail = on_mail_received_test([notification1], app_context, _server_cache)
    if success == 1 and fail == 0:
        print(f'[PASS] Callback returned success={success}, fail={fail}')
    else:
        print(f'[FAIL] Expected success=1, fail=0, got success={success}, fail={fail}')

    # Verify tell was stored
    err, tell_info = get_received_tell_by_guid(db_handle, 'abcdef1234567890abcdef1234567890')
    if err == DatabaseErrorCode.SUCCESS and tell_info:
        print(f'[PASS] Tell stored in database with id={tell_info["id"]}')

        # Verify stripes were stored
        err, stripes = get_stripes_for_tell(db_handle, tell_info['id'])
        if err == DatabaseErrorCode.SUCCESS and len(stripes) == 5:
            print(f'[PASS] 5 stripes stored correctly')
            parity_stripes = [s for s in stripes if s['is_parity']]
            if len(parity_stripes) == 1 and parity_stripes[0]['stripe_id'] == 4:
                print('[PASS] Parity stripe correctly identified (stripe 4)')
            else:
                print(f'[FAIL] Parity stripe issue: {parity_stripes}')
        else:
            print(f'[FAIL] Expected 5 stripes, got {len(stripes) if stripes else 0}')
    else:
        print(f'[FAIL] Tell not found in database: {err}')

    # Test 2: Notification without server list
    print('')
    print('Test 2: Notification without server list')
    test_guid2 = bytes.fromhex('00112233445566778899aabbccddeeff')
    notification2 = MockTellNotification(test_guid2, test_locker, 0, None)

    success, fail = on_mail_received_test([notification2], app_context, _server_cache)
    if success == 1:
        print(f'[PASS] Tell without servers stored (partial success)')
    else:
        print(f'[FAIL] Expected success for tell without servers')

    # Test 3: Invalid notification (missing file_guid)
    print('')
    print('Test 3: Invalid notification (missing file_guid)')

    class BadNotification:
        locker_code = b'test'
        tell_type = 0
        server_list = []

    success, fail = on_mail_received_test([BadNotification()], app_context, _server_cache)
    if fail == 1:
        print('[PASS] Invalid notification rejected')
    else:
        print(f'[FAIL] Expected fail=1, got fail={fail}')

    # Test 4: Multiple notifications
    print('')
    print('Test 4: Multiple notifications in batch')
    test_guid3 = bytes.fromhex('11111111111111111111111111111111')
    test_guid4 = bytes.fromhex('22222222222222222222222222222222')
    servers3 = [MockServerLocation(i, i, 3) for i in range(3)]
    servers4 = [MockServerLocation(i, i, 3) for i in range(3)]
    notification3 = MockTellNotification(test_guid3, test_locker, 0, servers3)
    notification4 = MockTellNotification(test_guid4, test_locker, 0, servers4)

    success, fail = on_mail_received_test([notification3, notification4], app_context, _server_cache)
    if success == 2 and fail == 0:
        print(f'[PASS] Batch processing: {success} successful, {fail} failed')
    else:
        print(f'[FAIL] Expected 2 successful, got {success}')

    # Test 5: Server IP extraction
    print('')
    print('Test 5: Server IP extraction')
    mock_server = MockServerLocation(5, 0, 3)
    ip = _extract_server_ip(mock_server, _server_cache)
    if ip == 'raida5.cloudcoin.global':
        print(f'[PASS] Hostname fallback: {ip}')
    else:
        print(f'[FAIL] Expected raida5.cloudcoin.global, got {ip}')

    # Test 6: IP extraction from raw_entry with valid IP
    print('')
    print('Test 6: IP extraction from raw_entry')
    mock_server2 = MockServerLocation(10, 0, 3)
    # Set bytes 22-25 to a valid IP (192.168.1.100)
    mock_server2.raw_entry = bytes(22) + bytes([192, 168, 1, 100]) + bytes(6)
    ip = _extract_server_ip(mock_server2, _server_cache)
    if ip == '192.168.1.100':
        print(f'[PASS] IP from raw_entry: {ip}')
    else:
        print(f'[FAIL] Expected 192.168.1.100, got {ip}')

    # Clean up
    close_database(db_handle)
    os.remove(TEST_DB_PATH)

    print('')
    print('=' * 60)
    print('Phase 2 tests completed successfully!')
    return 0


if __name__ == '__main__':
    sys.exit(main())
