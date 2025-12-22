"""
test_protocol_fixes.py - Verify Device ID and offset fixes in protocol.py

This test verifies the fixes from the bug reports:
- Bug #2: Device ID should be 8-bit (1 byte) not 16-bit (2 bytes)
- Bug #3: AN should be at offset 32-47, not 33-48

Run with: python -m pytest tests/test_protocol_fixes.py -v
Or standalone: python tests/test_protocol_fixes.py
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def test_ping_body_size():
    """PING body should be 50 bytes (was 51 before fix)."""
    from protocol import build_ping_body

    body = build_ping_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,  # Test with non-zero device
        an=bytes(16)
    )

    assert len(body) == 50, f"PING body should be 50 bytes, got {len(body)}"
    print(f"PASS: PING body size = {len(body)} bytes")


def test_ping_device_id_offset():
    """Device ID should be at offset 31 (1 byte)."""
    from protocol import build_ping_body

    test_device_id = 0xAB  # Distinctive value
    body = build_ping_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=test_device_id,
        an=bytes(16)
    )

    # Device ID should be exactly at offset 31
    assert body[31] == test_device_id, \
        f"Device ID at offset 31 should be {test_device_id:#x}, got {body[31]:#x}"

    # Verify it's NOT spilling into offset 32 (which is now AN start)
    # If old 16-bit packing was used, offset 32 would have part of device_id
    print(f"PASS: Device ID at offset 31 = {body[31]:#x}")


def test_ping_an_offset():
    """AN should be at offset 32-47 (not 33-48)."""
    from protocol import build_ping_body

    # Use distinctive AN pattern
    test_an = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])

    body = build_ping_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,
        an=test_an
    )

    # AN should be at bytes 32-47
    extracted_an = body[32:48]
    assert extracted_an == test_an, \
        f"AN at offset 32-47 should match. Got: {extracted_an.hex()}"

    print(f"PASS: AN at offset 32-47 = {extracted_an.hex()}")


def test_ping_terminator_offset():
    """Terminator should be at offset 48-49."""
    from protocol import build_ping_body, TERMINATOR

    body = build_ping_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,
        an=bytes(16)
    )

    terminator = body[48:50]
    assert terminator == TERMINATOR, \
        f"Terminator at 48-49 should be {TERMINATOR.hex()}, got {terminator.hex()}"

    print(f"PASS: Terminator at offset 48-49 = {terminator.hex()}")


def test_peek_body_size():
    """PEEK body should be 54 bytes (was 55 before fix)."""
    from protocol import build_peek_body

    body = build_peek_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,
        an=bytes(16),
        since_timestamp=1234567890
    )

    assert len(body) == 54, f"PEEK body should be 54 bytes, got {len(body)}"
    print(f"PASS: PEEK body size = {len(body)} bytes")


def test_peek_device_id_offset():
    """PEEK Device ID should also be at offset 31 (1 byte)."""
    from protocol import build_peek_body

    test_device_id = 0xCD
    body = build_peek_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=test_device_id,
        an=bytes(16),
        since_timestamp=0
    )

    assert body[31] == test_device_id, \
        f"Device ID at offset 31 should be {test_device_id:#x}, got {body[31]:#x}"

    print(f"PASS: PEEK Device ID at offset 31 = {body[31]:#x}")


def test_peek_timestamp_offset():
    """PEEK timestamp should be at offset 48-51."""
    from protocol import build_peek_body
    import struct

    test_timestamp = 0xDEADBEEF
    body = build_peek_body(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,
        an=bytes(16),
        since_timestamp=test_timestamp
    )

    # Extract timestamp from offset 48-51 (big-endian)
    extracted_ts = struct.unpack('>I', body[48:52])[0]
    assert extracted_ts == test_timestamp, \
        f"Timestamp at offset 48-51 should be {test_timestamp:#x}, got {extracted_ts:#x}"

    print(f"PASS: PEEK timestamp at offset 48-51 = {extracted_ts:#x}")


def test_device_id_generation():
    """Device ID should be generated as 8-bit (0-255)."""
    import tempfile
    import os

    # Create temp state file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        from device_id import get_or_create_device_id

        # Generate multiple device IDs and verify they're all 8-bit
        for _ in range(10):
            # Remove temp file to force regeneration
            if os.path.exists(temp_path):
                os.remove(temp_path)

            device_id, is_new = get_or_create_device_id(temp_path)

            assert 0 <= device_id <= 255, \
                f"Device ID should be 0-255, got {device_id}"

        print(f"PASS: Device ID generation produces 8-bit values (0-255)")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_upload_payload_offsets():
    """Upload payload should have correct Device ID and subsequent offsets."""
    from protocol import build_upload_payload

    test_device_id = 0xEF
    test_an = bytes([0x11] * 16)
    test_guid = bytes([0x22] * 16)
    test_locker = bytes([0x33] * 8)
    test_data = b"test stripe data"

    err, payload, challenge = build_upload_payload(
        denomination=1,
        serial_number=0x12345678,
        device_id=test_device_id,
        an=test_an,
        file_group_guid=test_guid,
        locker_code=test_locker,
        storage_duration=2,
        stripe_data=test_data
    )

    # Check Device ID at offset 31 (1 byte)
    assert payload[31] == test_device_id, \
        f"Device ID at offset 31 should be {test_device_id:#x}"

    # Check AN at offset 32-47
    assert payload[32:48] == test_an, \
        f"AN at offset 32-47 should match"

    # Check GUID at offset 48-63
    assert payload[48:64] == test_guid, \
        f"GUID at offset 48-63 should match"

    # Check locker code at offset 64-71
    assert payload[64:72] == test_locker, \
        f"Locker at offset 64-71 should match"

    print("PASS: Upload payload has correct offsets after Device ID fix")


def test_download_payload_size():
    """Download payload should be 83 bytes (was 84 before fix)."""
    from protocol import build_download_payload

    err, payload, challenge = build_download_payload(
        denomination=1,
        serial_number=0x12345678,
        device_id=0x0A,
        an=bytes(16),
        file_group_guid=bytes(16),
        locker_code=bytes(8),
        file_type=1
    )

    assert len(payload) == 83, f"Download payload should be 83 bytes, got {len(payload)}"
    print(f"PASS: Download payload size = {len(payload)} bytes")


def run_all_tests():
    """Run all tests and report results."""
    tests = [
        test_ping_body_size,
        test_ping_device_id_offset,
        test_ping_an_offset,
        test_ping_terminator_offset,
        test_peek_body_size,
        test_peek_device_id_offset,
        test_peek_timestamp_offset,
        test_device_id_generation,
        test_upload_payload_offsets,
        test_download_payload_size,
    ]

    print("=" * 60)
    print("Protocol Fixes Test Suite")
    print("=" * 60)
    print()

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__}: {type(e).__name__}: {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
