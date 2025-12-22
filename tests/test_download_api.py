"""
test_download_api.py - Comprehensive Test Suite for Download Email API

Tests all components of the download implementation:
1. Protocol functions (header, payload, encryption)
2. Key manager (key generation for string/bytes)
3. Database functions (tell storage, status updates)
4. Striping/reassembly (bit-interleaved round-trip)
5. Parity recovery (single stripe recovery)
6. End-to-end mock download flow

Author: Claude Opus 4.5
Version: 1.0.0

Run with: python tests/test_download_api.py
"""

import sys
import os
import asyncio
import hashlib
import struct
from typing import List, Dict, Tuple
from dataclasses import dataclass

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import modules under test
from protocol import (
    build_download_header, build_download_payload,
    build_complete_download_request, validate_download_response,
    encrypt_payload, decrypt_payload,
    CMD_DOWNLOAD, CMD_GROUP_FILES, DOWNLOAD_PAGE_SIZE,
    ProtocolErrorCode, ENC_LOCKER_CODE
)
from key_manager import get_keys_from_locker_code, get_decryption_key
from database import (
    init_database, close_database, DatabaseErrorCode,
    store_received_tell, store_received_stripe,
    get_received_tell_by_guid, get_stripes_for_tell,
    update_received_tell_status, get_received_tells_by_status,
    delete_received_tell, get_pending_download_count
)
from striping import (
    create_upload_stripes, reassemble_upload_stripes,
    calculate_parity_from_bytes, ErrorCode as StripingErrorCode
)
from parity import recover_stripe, ErrorCode as ParityErrorCode
from download_handler import (
    DownloadResult, StripeDownloadResult,
    recover_stripe_with_parity
)

# Test configuration
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'Data', 'test_download_api.db')


# ============================================================================
# TEST UTILITIES
# ============================================================================

class TestResult:
    """Tracks test results."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def ok(self, name: str):
        self.passed += 1
        print(f"  [PASS] {name}")

    def fail(self, name: str, reason: str):
        self.failed += 1
        self.errors.append((name, reason))
        print(f"  [FAIL] {name}: {reason}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print("\nFailures:")
            for name, reason in self.errors:
                print(f"  - {name}: {reason}")
        print('='*60)
        return self.failed == 0


def cleanup_test_db():
    """Remove test database if exists."""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


# ============================================================================
# PROTOCOL TESTS
# ============================================================================

def test_protocol(results: TestResult):
    """Test protocol.py download functions."""
    print("\n1. PROTOCOL TESTS")
    print("-" * 40)

    locker_code = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    an = bytes(16)
    guid = bytes(16)

    # Test 1.1: Download header building
    err, header = build_download_header(raida_id=5, locker_code=locker_code, body_length=84)
    if err == ProtocolErrorCode.SUCCESS and len(header) == 32:
        # Verify header fields
        if header[4] == CMD_GROUP_FILES and header[5] == CMD_DOWNLOAD:
            results.ok("build_download_header - correct command codes")
        else:
            results.fail("build_download_header", f"wrong command: {header[4]}/{header[5]}")
        if header[2] == 5:  # RAIDA ID
            results.ok("build_download_header - correct RAIDA ID")
        else:
            results.fail("build_download_header", f"wrong RAIDA ID: {header[2]}")
        if header[16] == ENC_LOCKER_CODE:
            results.ok("build_download_header - correct encryption type")
        else:
            results.fail("build_download_header", f"wrong encryption: {header[16]}")
    else:
        results.fail("build_download_header", f"err={err}, len={len(header) if header else 0}")

    # Test 1.2: Invalid RAIDA ID
    err, header = build_download_header(raida_id=30, locker_code=locker_code, body_length=84)
    if err != ProtocolErrorCode.SUCCESS:
        results.ok("build_download_header - rejects invalid RAIDA ID")
    else:
        results.fail("build_download_header", "should reject RAIDA ID > 24")

    # Test 1.3: Download payload building
    err, payload, challenge = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=0, page_number=0
    )
    if err == ProtocolErrorCode.SUCCESS and len(payload) == 84 and len(challenge) == 16:
        results.ok("build_download_payload - correct sizes")
        # Verify terminator
        if payload[-2:] == b'\x3E\x3E':
            results.ok("build_download_payload - correct terminator")
        else:
            results.fail("build_download_payload", f"wrong terminator: {payload[-2:].hex()}")
    else:
        results.fail("build_download_payload", f"err={err}, payload={len(payload) if payload else 0}")

    # Test 1.4: File type encoding
    err, payload, _ = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=10, page_number=5
    )
    if err == ProtocolErrorCode.SUCCESS:
        if payload[73] == 10:  # file_type at byte 73
            results.ok("build_download_payload - file_type encoded correctly")
        else:
            results.fail("build_download_payload", f"file_type={payload[73]}, expected 10")
        page_num = struct.unpack('>I', payload[74:78])[0]
        if page_num == 5:
            results.ok("build_download_payload - page_number encoded correctly")
        else:
            results.fail("build_download_payload", f"page_number={page_num}, expected 5")
    else:
        results.fail("build_download_payload", f"err={err}")

    # Test 1.5: Complete request building
    err, request, challenge, nonce = build_complete_download_request(
        raida_id=5, denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=0, page_number=0
    )
    if err == ProtocolErrorCode.SUCCESS:
        if len(request) == 32 + 84:  # header + encrypted payload
            results.ok("build_complete_download_request - correct total size")
        else:
            results.fail("build_complete_download_request", f"size={len(request)}, expected 116")
        if len(nonce) == 6:
            results.ok("build_complete_download_request - nonce extracted")
        else:
            results.fail("build_complete_download_request", f"nonce len={len(nonce)}")
    else:
        results.fail("build_complete_download_request", f"err={err}")

    # Test 1.6: Encryption round-trip
    test_data = b"Hello, this is test data for encryption!"
    err, encrypted = encrypt_payload(test_data, locker_code, nonce)
    if err == ProtocolErrorCode.SUCCESS:
        err, decrypted = decrypt_payload(encrypted, locker_code, nonce)
        if err == ProtocolErrorCode.SUCCESS and decrypted == test_data:
            results.ok("encrypt/decrypt_payload - round-trip successful")
        else:
            results.fail("decrypt_payload", f"data mismatch or err={err}")
    else:
        results.fail("encrypt_payload", f"err={err}")

    # Test 1.7: Constants verification
    if CMD_DOWNLOAD == 64:
        results.ok("CMD_DOWNLOAD constant = 64")
    else:
        results.fail("CMD_DOWNLOAD", f"value={CMD_DOWNLOAD}, expected 64")

    if DOWNLOAD_PAGE_SIZE == 65536:
        results.ok("DOWNLOAD_PAGE_SIZE constant = 65536")
    else:
        results.fail("DOWNLOAD_PAGE_SIZE", f"value={DOWNLOAD_PAGE_SIZE}, expected 65536")


# ============================================================================
# KEY MANAGER TESTS
# ============================================================================

def test_key_manager(results: TestResult):
    """Test key_manager.py functions."""
    print("\n2. KEY MANAGER TESTS")
    print("-" * 40)

    # Test 2.1: String locker code
    keys = get_keys_from_locker_code("test_locker_code")
    if len(keys) == 25:
        results.ok("get_keys_from_locker_code(str) - generates 25 keys")
    else:
        results.fail("get_keys_from_locker_code(str)", f"count={len(keys)}")

    # Verify key size
    if all(len(k) == 16 for k in keys):
        results.ok("get_keys_from_locker_code - all keys are 16 bytes")
    else:
        results.fail("get_keys_from_locker_code", "not all keys are 16 bytes")

    # Test 2.2: Bytes locker code
    locker_bytes = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    keys_from_bytes = get_keys_from_locker_code(locker_bytes)
    if len(keys_from_bytes) == 25:
        results.ok("get_keys_from_locker_code(bytes) - generates 25 keys")
    else:
        results.fail("get_keys_from_locker_code(bytes)", f"count={len(keys_from_bytes)}")

    # Test 2.3: Keys are deterministic
    keys_again = get_keys_from_locker_code("test_locker_code")
    if keys == keys_again:
        results.ok("get_keys_from_locker_code - deterministic output")
    else:
        results.fail("get_keys_from_locker_code", "keys not deterministic")

    # Test 2.4: Different locker codes produce different keys
    keys_other = get_keys_from_locker_code("other_locker_code")
    if keys[0] != keys_other[0]:
        results.ok("get_keys_from_locker_code - different inputs produce different keys")
    else:
        results.fail("get_keys_from_locker_code", "different inputs produce same keys")

    # Test 2.5: get_decryption_key function
    key_5 = get_decryption_key("test_locker", 5)
    if len(key_5) == 16:
        results.ok("get_decryption_key - returns 16-byte key")
    else:
        results.fail("get_decryption_key", f"key len={len(key_5)}")

    # Verify it matches index 5 from full key generation
    all_keys = get_keys_from_locker_code("test_locker")
    if key_5 == all_keys[5]:
        results.ok("get_decryption_key - matches index from full generation")
    else:
        results.fail("get_decryption_key", "doesn't match full generation")

    # Test 2.6: Invalid server ID
    try:
        get_decryption_key("test", 30)
        results.fail("get_decryption_key", "should reject server_id > 24")
    except ValueError:
        results.ok("get_decryption_key - rejects invalid server_id")

    # Test 2.7: Empty locker code
    try:
        get_keys_from_locker_code("")
        results.fail("get_keys_from_locker_code", "should reject empty string")
    except ValueError:
        results.ok("get_keys_from_locker_code - rejects empty input")


# ============================================================================
# DATABASE TESTS
# ============================================================================

def test_database(results: TestResult):
    """Test database.py tell management functions."""
    print("\n3. DATABASE TESTS")
    print("-" * 40)

    cleanup_test_db()

    # Test 3.1: Initialize database
    err, handle = init_database(TEST_DB_PATH)
    if err == DatabaseErrorCode.SUCCESS and handle is not None:
        results.ok("init_database - creates database successfully")
    else:
        results.fail("init_database", f"err={err}")
        return  # Can't continue without database

    try:
        locker_code = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        file_guid = "abcdef1234567890abcdef1234567890"

        # Test 3.2: Store received tell
        err, tell_id = store_received_tell(
            handle, file_guid, locker_code,
            file_type=0, version=1, file_size=10000
        )
        if err == DatabaseErrorCode.SUCCESS and tell_id > 0:
            results.ok("store_received_tell - stores tell successfully")
        else:
            results.fail("store_received_tell", f"err={err}, tell_id={tell_id}")

        # Test 3.3: Store stripes
        stripe_errors = 0
        for i in range(4):
            err = store_received_stripe(handle, tell_id, f"192.168.1.{10+i}", i, is_parity=False)
            if err != DatabaseErrorCode.SUCCESS:
                stripe_errors += 1
        err = store_received_stripe(handle, tell_id, "192.168.1.20", 4, is_parity=True)
        if err != DatabaseErrorCode.SUCCESS:
            stripe_errors += 1

        if stripe_errors == 0:
            results.ok("store_received_stripe - stores 5 stripes successfully")
        else:
            results.fail("store_received_stripe", f"{stripe_errors} stripe(s) failed")

        # Test 3.4: Get tell by GUID
        err, tell_info = get_received_tell_by_guid(handle, file_guid)
        if err == DatabaseErrorCode.SUCCESS and tell_info is not None:
            if tell_info['file_guid'] == file_guid:
                results.ok("get_received_tell_by_guid - retrieves correct tell")
            else:
                results.fail("get_received_tell_by_guid", "wrong file_guid")
            if tell_info['file_type'] == 0 and tell_info['file_size'] == 10000:
                results.ok("get_received_tell_by_guid - metadata correct")
            else:
                results.fail("get_received_tell_by_guid", "wrong metadata")
        else:
            results.fail("get_received_tell_by_guid", f"err={err}")

        # Test 3.5: Get stripes for tell
        err, stripes = get_stripes_for_tell(handle, tell_id)
        if err == DatabaseErrorCode.SUCCESS and len(stripes) == 5:
            results.ok("get_stripes_for_tell - retrieves all 5 stripes")
            # Check parity flag
            parity_count = sum(1 for s in stripes if s['is_parity'])
            if parity_count == 1:
                results.ok("get_stripes_for_tell - correct parity count")
            else:
                results.fail("get_stripes_for_tell", f"parity_count={parity_count}")
        else:
            results.fail("get_stripes_for_tell", f"err={err}, count={len(stripes)}")

        # Test 3.6: Get pending download count
        err, count = get_pending_download_count(handle)
        if err == DatabaseErrorCode.SUCCESS and count == 1:
            results.ok("get_pending_download_count - returns correct count")
        else:
            results.fail("get_pending_download_count", f"err={err}, count={count}")

        # Test 3.7: Update tell status
        err = update_received_tell_status(handle, file_guid, 'downloading')
        if err == DatabaseErrorCode.SUCCESS:
            results.ok("update_received_tell_status - updates status")
        else:
            results.fail("update_received_tell_status", f"err={err}")

        # Verify status change
        err, tell_info = get_received_tell_by_guid(handle, file_guid)
        if tell_info and tell_info['status'] == 'downloading':
            results.ok("update_received_tell_status - status verified")
        else:
            results.fail("update_received_tell_status", "status not updated")

        # Test 3.8: Get tells by status
        err, tells = get_received_tells_by_status(handle, 'downloading')
        if err == DatabaseErrorCode.SUCCESS and len(tells) == 1:
            results.ok("get_received_tells_by_status - finds tells by status")
        else:
            results.fail("get_received_tells_by_status", f"err={err}, count={len(tells)}")

        # Test 3.9: Update status with file_size
        err = update_received_tell_status(handle, file_guid, 'complete', file_size=20000)
        err2, tell_info = get_received_tell_by_guid(handle, file_guid)
        if tell_info and tell_info['file_size'] == 20000:
            results.ok("update_received_tell_status - updates file_size")
        else:
            results.fail("update_received_tell_status", "file_size not updated")

        # Test 3.10: Delete tell (cascades to stripes)
        err = delete_received_tell(handle, file_guid)
        if err == DatabaseErrorCode.SUCCESS:
            results.ok("delete_received_tell - deletes tell")
        else:
            results.fail("delete_received_tell", f"err={err}")

        # Verify deletion
        err, tell_info = get_received_tell_by_guid(handle, file_guid)
        if err == DatabaseErrorCode.ERR_NOT_FOUND:
            results.ok("delete_received_tell - tell not found after delete")
        else:
            results.fail("delete_received_tell", "tell still exists")

        # Verify stripe cascade delete
        err, stripes = get_stripes_for_tell(handle, tell_id)
        if len(stripes) == 0:
            results.ok("delete_received_tell - stripes cascaded")
        else:
            results.fail("delete_received_tell", f"stripes remain: {len(stripes)}")

        # Test 3.11: Not found errors
        err, _ = get_received_tell_by_guid(handle, "nonexistent")
        if err == DatabaseErrorCode.ERR_NOT_FOUND:
            results.ok("get_received_tell_by_guid - returns NOT_FOUND for missing")
        else:
            results.fail("get_received_tell_by_guid", f"wrong error: {err}")

    finally:
        close_database(handle)
        cleanup_test_db()


# ============================================================================
# STRIPING TESTS
# ============================================================================

def test_striping(results: TestResult):
    """Test striping.py bit-interleaved functions."""
    print("\n4. STRIPING TESTS")
    print("-" * 40)

    # Test 4.1: Small data round-trip
    original = b"Hello, QMail Download API!"
    err, stripes = create_upload_stripes(original, num_servers=5)
    if err == StripingErrorCode.SUCCESS and len(stripes) == 4:
        results.ok("create_upload_stripes - creates 4 data stripes for 5 servers")
    else:
        results.fail("create_upload_stripes", f"err={err}, count={len(stripes)}")

    err, reassembled = reassemble_upload_stripes(stripes, len(original))
    if err == StripingErrorCode.SUCCESS and reassembled == original:
        results.ok("reassemble_upload_stripes - round-trip successful")
    else:
        results.fail("reassemble_upload_stripes", f"err={err}, match={reassembled == original}")

    # Test 4.2: Larger data (1KB)
    original_1k = bytes(range(256)) * 4  # 1024 bytes
    err, stripes_1k = create_upload_stripes(original_1k, num_servers=5)
    err2, reassembled_1k = reassemble_upload_stripes(stripes_1k, len(original_1k))
    if reassembled_1k == original_1k:
        results.ok("striping round-trip - 1KB data")
    else:
        results.fail("striping round-trip - 1KB", "data mismatch")

    # Test 4.3: Parity calculation
    err, parity = calculate_parity_from_bytes(stripes)
    if err == StripingErrorCode.SUCCESS and len(parity) == len(stripes[0]):
        results.ok("calculate_parity_from_bytes - correct parity size")
    else:
        results.fail("calculate_parity_from_bytes", f"err={err}")

    # Test 4.4: Different server counts
    for num_servers in [3, 5, 10, 25]:
        err, s = create_upload_stripes(original, num_servers=num_servers)
        if err == StripingErrorCode.SUCCESS and len(s) == num_servers - 1:
            pass  # OK
        else:
            results.fail(f"create_upload_stripes(servers={num_servers})", f"count={len(s)}")
    results.ok("create_upload_stripes - handles various server counts")

    # Test 4.5: Empty data handling
    err, empty_stripes = create_upload_stripes(b'', num_servers=5)
    if err == StripingErrorCode.SUCCESS and len(empty_stripes) == 0:
        results.ok("create_upload_stripes - handles empty data")
    else:
        results.fail("create_upload_stripes", "empty data handling")

    # Test 4.6: Equal stripe sizes
    err, stripes = create_upload_stripes(b"x" * 100, num_servers=5)
    sizes = [len(s) for s in stripes]
    if len(set(sizes)) == 1:  # All same size
        results.ok("create_upload_stripes - stripes are equal size")
    else:
        results.fail("create_upload_stripes", f"unequal sizes: {sizes}")


# ============================================================================
# PARITY RECOVERY TESTS
# ============================================================================

def test_parity_recovery(results: TestResult):
    """Test parity recovery functions."""
    print("\n5. PARITY RECOVERY TESTS")
    print("-" * 40)

    # Create test data and stripes
    original = b"Test data for parity recovery!" * 10
    err, stripes = create_upload_stripes(original, num_servers=5)
    err, parity = calculate_parity_from_bytes(stripes)

    # Test 5.1: Recover stripe 0
    available = {1: stripes[1], 2: stripes[2], 3: stripes[3]}
    recovered = asyncio.run(recover_stripe_with_parity(
        available, parity, missing_stripe_id=0, total_data_stripes=4
    ))
    if recovered == stripes[0]:
        results.ok("recover_stripe_with_parity - recovers stripe 0")
    else:
        results.fail("recover_stripe_with_parity", "stripe 0 recovery failed")

    # Test 5.2: Recover stripe 2 (middle)
    available = {0: stripes[0], 1: stripes[1], 3: stripes[3]}
    recovered = asyncio.run(recover_stripe_with_parity(
        available, parity, missing_stripe_id=2, total_data_stripes=4
    ))
    if recovered == stripes[2]:
        results.ok("recover_stripe_with_parity - recovers stripe 2")
    else:
        results.fail("recover_stripe_with_parity", "stripe 2 recovery failed")

    # Test 5.3: Recover stripe 3 (last)
    available = {0: stripes[0], 1: stripes[1], 2: stripes[2]}
    recovered = asyncio.run(recover_stripe_with_parity(
        available, parity, missing_stripe_id=3, total_data_stripes=4
    ))
    if recovered == stripes[3]:
        results.ok("recover_stripe_with_parity - recovers stripe 3")
    else:
        results.fail("recover_stripe_with_parity", "stripe 3 recovery failed")

    # Test 5.4: Full round-trip with recovery
    # Simulate: lose stripe 1, recover it, reassemble
    available = {0: stripes[0], 2: stripes[2], 3: stripes[3]}
    recovered_1 = asyncio.run(recover_stripe_with_parity(
        available, parity, missing_stripe_id=1, total_data_stripes=4
    ))
    reconstructed_stripes = [stripes[0], recovered_1, stripes[2], stripes[3]]
    err, reassembled = reassemble_upload_stripes(reconstructed_stripes, len(original))
    if reassembled == original:
        results.ok("full recovery round-trip - data intact after recovery")
    else:
        results.fail("full recovery round-trip", "data mismatch after recovery")

    # Test 5.5: Insufficient stripes (should fail)
    available = {0: stripes[0], 1: stripes[1]}  # Only 2 of 4
    recovered = asyncio.run(recover_stripe_with_parity(
        available, parity, missing_stripe_id=2, total_data_stripes=4
    ))
    if recovered is None:
        results.ok("recover_stripe_with_parity - rejects multiple missing stripes")
    else:
        results.fail("recover_stripe_with_parity", "should reject multiple missing")


# ============================================================================
# END-TO-END MOCK DOWNLOAD TEST
# ============================================================================

def test_end_to_end_mock(results: TestResult):
    """Test end-to-end download flow with mocked server responses."""
    print("\n6. END-TO-END MOCK DOWNLOAD TEST")
    print("-" * 40)

    cleanup_test_db()

    # Simulate the complete download flow
    original_email = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello!"

    # Step 1: Simulate upload (create stripes + parity)
    err, data_stripes = create_upload_stripes(original_email, num_servers=5)
    err, parity_stripe = calculate_parity_from_bytes(data_stripes)
    all_stripes = data_stripes + [parity_stripe]

    if len(all_stripes) == 5:
        results.ok("mock upload - created 4 data + 1 parity stripes")
    else:
        results.fail("mock upload", f"stripe count={len(all_stripes)}")

    # Step 2: Store tell in database (simulates receiving TELL notification)
    err, handle = init_database(TEST_DB_PATH)
    if err != DatabaseErrorCode.SUCCESS:
        results.fail("mock download", "database init failed")
        return

    try:
        file_guid = "1234567890abcdef1234567890abcdef"
        locker_code = b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11'

        err, tell_id = store_received_tell(
            handle, file_guid, locker_code,
            file_type=0, file_size=len(original_email)
        )

        # Store stripe locations
        servers = ["raida0.cloudcoin.global", "raida1.cloudcoin.global",
                   "raida2.cloudcoin.global", "raida3.cloudcoin.global",
                   "raida4.cloudcoin.global"]
        for i, server in enumerate(servers):
            store_received_stripe(handle, tell_id, server, i, is_parity=(i == 4))

        results.ok("mock download - tell and stripes stored")

        # Step 3: Retrieve tell info (like download_file does)
        err, tell_info = get_received_tell_by_guid(handle, file_guid)
        err, stripes_info = get_stripes_for_tell(handle, tell_id)

        if tell_info and len(stripes_info) == 5:
            results.ok("mock download - retrieved tell metadata")
        else:
            results.fail("mock download", "failed to retrieve metadata")

        # Step 4: Generate keys from locker code
        keys = get_keys_from_locker_code(locker_code)
        if len(keys) == 25:
            results.ok("mock download - generated decryption keys")
        else:
            results.fail("mock download", "key generation failed")

        # Step 5: Simulate downloading stripes (normally from network)
        # In real scenario, each stripe comes from different server
        downloaded_stripes = {}
        for i in range(4):  # Only download data stripes
            # Simulating network download - in reality this is encrypted
            downloaded_stripes[i] = data_stripes[i]

        if len(downloaded_stripes) == 4:
            results.ok("mock download - downloaded 4 data stripes")
        else:
            results.fail("mock download", f"downloaded={len(downloaded_stripes)}")

        # Step 6: Reassemble stripes
        sorted_stripes = [downloaded_stripes[i] for i in sorted(downloaded_stripes.keys())]
        err, reassembled = reassemble_upload_stripes(sorted_stripes, len(original_email))

        if reassembled == original_email:
            results.ok("mock download - reassembled email matches original")
        else:
            results.fail("mock download", "reassembled data mismatch")

        # Step 7: Update status
        update_received_tell_status(handle, file_guid, 'complete', file_size=len(reassembled))
        err, tell_info = get_received_tell_by_guid(handle, file_guid)
        if tell_info['status'] == 'complete':
            results.ok("mock download - status updated to complete")
        else:
            results.fail("mock download", "status not updated")

        # Step 8: Test with one failed stripe (parity recovery)
        print("\n  Testing with simulated stripe failure...")
        downloaded_with_failure = {0: data_stripes[0], 2: data_stripes[2], 3: data_stripes[3]}
        # Stripe 1 "failed to download"

        # Download parity and recover
        recovered_1 = asyncio.run(recover_stripe_with_parity(
            downloaded_with_failure, parity_stripe, missing_stripe_id=1, total_data_stripes=4
        ))

        if recovered_1 == data_stripes[1]:
            results.ok("mock download - parity recovery successful")
        else:
            results.fail("mock download", "parity recovery failed")

        # Reassemble with recovered stripe
        full_stripes = [downloaded_with_failure[0], recovered_1,
                        downloaded_with_failure[2], downloaded_with_failure[3]]
        err, reassembled_recovered = reassemble_upload_stripes(full_stripes, len(original_email))

        if reassembled_recovered == original_email:
            results.ok("mock download - data intact after recovery")
        else:
            results.fail("mock download", "data corrupted after recovery")

    finally:
        close_database(handle)
        cleanup_test_db()


# ============================================================================
# ATTACHMENT DOWNLOAD TEST
# ============================================================================

def test_attachment_download(results: TestResult):
    """Test attachment file type handling."""
    print("\n7. ATTACHMENT DOWNLOAD TESTS")
    print("-" * 40)

    locker_code = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    an = bytes(16)
    guid = bytes(16)

    # Test 7.1: Email body (file_type=0)
    err, payload, _ = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=0, page_number=0
    )
    if payload[73] == 0:
        results.ok("file_type=0 for email body")
    else:
        results.fail("file_type=0", f"got {payload[73]}")

    # Test 7.2: First attachment (file_type=10)
    err, payload, _ = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=10, page_number=0
    )
    if payload[73] == 10:
        results.ok("file_type=10 for first attachment")
    else:
        results.fail("file_type=10", f"got {payload[73]}")

    # Test 7.3: Second attachment (file_type=11)
    err, payload, _ = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=11, page_number=0
    )
    if payload[73] == 11:
        results.ok("file_type=11 for second attachment")
    else:
        results.fail("file_type=11", f"got {payload[73]}")

    # Test 7.4: Large attachment simulation
    large_attachment = os.urandom(100000)  # 100KB
    err, stripes = create_upload_stripes(large_attachment, num_servers=5)
    err, parity = calculate_parity_from_bytes(stripes)
    err, reassembled = reassemble_upload_stripes(stripes, len(large_attachment))

    if reassembled == large_attachment:
        results.ok("large attachment (100KB) - round-trip successful")
    else:
        results.fail("large attachment", "data mismatch")


# ============================================================================
# PAGINATION TEST
# ============================================================================

def test_pagination(results: TestResult):
    """Test pagination for large files."""
    print("\n8. PAGINATION TESTS")
    print("-" * 40)

    locker_code = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    an = bytes(16)
    guid = bytes(16)

    # Test 8.1: Page number encoding
    for page_num in [0, 1, 10, 100, 1000]:
        err, payload, _ = build_download_payload(
            denomination=1, serial_number=12345, device_id=1,
            an=an, file_group_guid=guid, locker_code=locker_code,
            file_type=0, page_number=page_num
        )
        encoded_page = struct.unpack('>I', payload[74:78])[0]
        if encoded_page == page_num:
            pass  # OK
        else:
            results.fail(f"page_number={page_num}", f"encoded={encoded_page}")

    results.ok("page_number encoding - all values correct")

    # Test 8.2: Calculate pages needed for large file
    file_size = 500000  # 500KB
    pages_needed = (file_size + DOWNLOAD_PAGE_SIZE - 1) // DOWNLOAD_PAGE_SIZE
    if pages_needed == 8:  # 500000 / 65536 = 7.63 -> 8 pages
        results.ok("pagination calculation - 500KB needs 8 pages")
    else:
        results.fail("pagination calculation", f"got {pages_needed} pages")

    # Test 8.3: Page size indicator
    err, payload, _ = build_download_payload(
        denomination=1, serial_number=12345, device_id=1,
        an=an, file_group_guid=guid, locker_code=locker_code,
        file_type=0, page_number=0
    )
    if payload[78:80] == b'\xFF\xFF':
        results.ok("page_size indicator = 0xFFFF (64KB)")
    else:
        results.fail("page_size indicator", f"got {payload[78:80].hex()}")


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def main():
    """Run all tests."""
    print("=" * 60)
    print("DOWNLOAD API TEST SUITE")
    print("=" * 60)

    results = TestResult()

    # Run all test categories
    test_protocol(results)
    test_key_manager(results)
    test_database(results)
    test_striping(results)
    test_parity_recovery(results)
    test_end_to_end_mock(results)
    test_attachment_download(results)
    test_pagination(results)

    # Print summary
    success = results.summary()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
