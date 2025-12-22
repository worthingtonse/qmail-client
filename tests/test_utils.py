"""
test_utils.py - Shared Test Utilities and Fixtures

This module provides common utilities, mock objects, and fixtures
used across all test files in the QMail Client test suite.

Author: Claude Opus 4.5
Date: 2025-12-18
"""

import os
import sys
import tempfile
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))


# ============================================================================
# MOCK CLASSES
# ============================================================================

@dataclass
class MockIdentity:
    """Mock identity configuration for tests."""
    coin_type: int = 0x0006
    denomination: int = 1
    serial_number: int = 12345678
    device_id: int = 1
    an: bytes = field(default_factory=lambda: bytes(16))
    authenticity_number: str = "00112233445566778899aabbccddeeff"


@dataclass
class MockRecipient:
    """Mock recipient for tests."""
    address: str = "0006.1.12345678"
    first_name: str = "Test"
    last_name: str = "User"
    beacon_id: str = "raida11"


@dataclass
class MockRequest:
    """Mock SendEmailRequest for tests."""
    email_file: bytes = b'Test email content for testing purposes'
    searchable_text: str = "Test email"
    subject: str = "Test Subject"
    subsubject: str = ""
    to_recipients: List = field(default_factory=list)
    cc_recipients: List = field(default_factory=list)
    bcc_recipients: List = field(default_factory=list)
    attachment_paths: List = field(default_factory=list)
    storage_weeks: int = 8
    index_attachments: bool = False


@dataclass
class MockUploadResult:
    """Mock upload result for tests."""
    success: bool = True
    server_id: str = "raida0"
    stripe_index: int = 0
    response_time_ms: int = 50
    status_code: int = 250
    error_message: str = ""


@dataclass
class MockServerConfig:
    """Mock server configuration for tests."""
    server_id: str = "raida0"
    ip_address: str = "raida0.cloudcoin.global"
    port: int = 19000
    server_index: int = 0
    is_available: bool = True


@dataclass
class MockDatabaseHandle:
    """Mock database handle for tests."""
    connection: object = None
    logger: object = None
    db_path: str = ""


@dataclass
class MockCloudCoinHandle:
    """Mock CloudCoin handle for tests."""
    data_dir: str = ""
    logger: object = None


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_mock_identity(
    denomination: int = 1,
    serial_number: int = 12345678,
    device_id: int = 1
) -> MockIdentity:
    """Create a mock identity with custom values."""
    return MockIdentity(
        denomination=denomination,
        serial_number=serial_number,
        device_id=device_id,
        an=os.urandom(16)
    )


def create_mock_request(
    to_recipients: List[str] = None,
    cc_recipients: List[str] = None,
    bcc_recipients: List[str] = None,
    email_content: bytes = None
) -> MockRequest:
    """Create a mock SendEmailRequest with custom recipients."""
    req = MockRequest()

    if to_recipients:
        req.to_recipients = [MockRecipient(address=addr) for addr in to_recipients]
    else:
        req.to_recipients = [MockRecipient()]

    if cc_recipients:
        req.cc_recipients = [MockRecipient(address=addr) for addr in cc_recipients]

    if bcc_recipients:
        req.bcc_recipients = [MockRecipient(address=addr) for addr in bcc_recipients]

    if email_content:
        req.email_file = email_content

    return req


def create_mock_upload_results(count: int = 5) -> List[MockUploadResult]:
    """Create mock upload results for stripe uploads."""
    results = []
    for i in range(count):
        results.append(MockUploadResult(
            success=True,
            server_id=f"raida{i}",
            stripe_index=i,
            response_time_ms=50 + i * 10,
            status_code=250
        ))
    return results


def create_mock_servers(count: int = 5) -> List[MockServerConfig]:
    """Create mock server configurations."""
    servers = []
    for i in range(count):
        servers.append(MockServerConfig(
            server_id=f"raida{i}",
            ip_address=f"raida{i}.cloudcoin.global",
            port=19000,
            server_index=i
        ))
    return servers


# ============================================================================
# TEMPORARY DATABASE
# ============================================================================

def create_temp_database() -> Tuple[str, object]:
    """
    Create a temporary SQLite database for testing.

    Returns:
        Tuple of (db_path, db_handle)
    """
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)

    try:
        from database import init_database
        err, handle = init_database(db_path)
        return db_path, handle
    except ImportError:
        # Return path only if database module not available
        return db_path, None


def cleanup_temp_database(db_path: str, handle: object = None):
    """Clean up temporary database."""
    if handle and hasattr(handle, 'connection') and handle.connection:
        try:
            handle.connection.close()
        except:
            pass

    if db_path and os.path.exists(db_path):
        try:
            os.remove(db_path)
        except:
            pass


# ============================================================================
# MOCK RESPONSE BUILDERS
# ============================================================================

def build_mock_upload_response(
    status: int = 250,
    challenge: bytes = None,
    raida_id: int = 0
) -> bytes:
    """
    Build a mock upload response packet.

    Args:
        status: Status code (250=success, 166=payment required, etc.)
        challenge: Expected challenge bytes (for echo)
        raida_id: RAIDA ID to include

    Returns:
        Mock response bytes (32+ bytes)
    """
    response = bytearray(32)

    # Basic header fields
    response[0] = 0x00  # Bitfield
    response[1] = 0x00  # Split
    response[2] = raida_id  # RAIDA ID
    response[3] = 0x00  # Shard
    response[4] = 0x06  # Command Group
    response[5] = status  # Status code
    response[6:8] = b'\x00\x01'  # WEST ID

    # Challenge echo (bytes 16-32)
    if challenge and len(challenge) >= 16:
        response[16:32] = challenge[:16]

    return bytes(response)


def build_mock_tell_response(
    status: int = 250,
    challenge: bytes = None,
    raida_id: int = 11
) -> bytes:
    """
    Build a mock Tell response packet.

    Args:
        status: Status code (250=success, 166=payment required, etc.)
        challenge: Expected challenge bytes (for echo)
        raida_id: Beacon RAIDA ID

    Returns:
        Mock response bytes (32+ bytes)
    """
    response = bytearray(32)

    # Basic header fields
    response[0] = 0x00  # Bitfield
    response[1] = 0x00  # Split
    response[2] = raida_id  # RAIDA ID
    response[3] = 0x00  # Shard
    response[4] = 0x06  # Command Group
    response[5] = status  # Status code
    response[6:8] = b'\x00\x01'  # WEST ID

    # Challenge echo (bytes 16-32)
    if challenge and len(challenge) >= 16:
        response[16:32] = challenge[:16]

    return bytes(response)


# ============================================================================
# PROTOCOL TEST HELPERS
# ============================================================================

def generate_test_locker_code() -> bytes:
    """Generate a random 8-byte locker code for testing."""
    return os.urandom(8)


def generate_test_file_group_guid() -> bytes:
    """Generate a random 16-byte file group GUID for testing."""
    return os.urandom(16)


def generate_test_an() -> bytes:
    """Generate a random 16-byte AN for testing."""
    return os.urandom(16)


def generate_test_locker_key() -> bytes:
    """Generate a random 16-byte locker payment key for testing."""
    return os.urandom(16)


def verify_challenge_format(challenge: bytes) -> bool:
    """
    Verify that a challenge has correct format (12 random + 4 CRC).

    Args:
        challenge: 16-byte challenge

    Returns:
        True if format is valid
    """
    if not challenge or len(challenge) != 16:
        return False

    # Extract components
    random_bytes = challenge[:12]
    crc_bytes = challenge[12:16]

    # Calculate expected CRC
    import zlib
    expected_crc = zlib.crc32(random_bytes) & 0xFFFFFFFF
    actual_crc = struct.unpack('>I', crc_bytes)[0]

    return expected_crc == actual_crc


def extract_challenge_from_payload(payload: bytes) -> bytes:
    """Extract challenge bytes from payload (first 16 bytes)."""
    if payload and len(payload) >= 16:
        return payload[:16]
    return b''


# ============================================================================
# ASSERTION HELPERS
# ============================================================================

def assert_header_valid(header: bytes, expected_cmd: int = 61, expected_group: int = 6):
    """
    Assert that a protocol header is valid.

    Args:
        header: 32-byte header
        expected_cmd: Expected command code
        expected_group: Expected command group
    """
    assert header is not None, "Header is None"
    assert len(header) == 32, f"Header wrong size: {len(header)} != 32"
    assert header[4] == expected_group, f"Wrong command group: {header[4]} != {expected_group}"
    assert header[5] == expected_cmd, f"Wrong command code: {header[5]} != {expected_cmd}"


def assert_payload_valid(payload: bytes, min_size: int = 88):
    """
    Assert that a payload is valid.

    Args:
        payload: Payload bytes
        min_size: Minimum expected size
    """
    assert payload is not None, "Payload is None"
    assert len(payload) >= min_size, f"Payload too small: {len(payload)} < {min_size}"
    # Check 16-byte alignment (for AES)
    assert len(payload) % 16 == 0, f"Payload not 16-byte aligned: {len(payload)}"


def assert_terminator_present(data: bytes):
    """Assert that terminator bytes are present at end."""
    assert data is not None, "Data is None"
    assert len(data) >= 2, "Data too short for terminator"
    assert data[-2:] == b'\x3e\x3e', f"Wrong terminator: {data[-2:].hex()}"


# ============================================================================
# LOGGING MOCK
# ============================================================================

class MockLogger:
    """Mock logger that captures log messages for verification."""

    def __init__(self):
        self.messages = []
        self.errors = []
        self.warnings = []
        self.debug_messages = []

    def clear(self):
        """Clear all captured messages."""
        self.messages.clear()
        self.errors.clear()
        self.warnings.clear()
        self.debug_messages.clear()


def create_mock_logger() -> MockLogger:
    """Create a mock logger for tests."""
    return MockLogger()


# Stub logging functions that work with MockLogger
def mock_log_error(handle, context, msg, reason=None):
    if handle and hasattr(handle, 'errors'):
        handle.errors.append((context, msg, reason))

def mock_log_warning(handle, context, msg):
    if handle and hasattr(handle, 'warnings'):
        handle.warnings.append((context, msg))

def mock_log_debug(handle, context, msg):
    if handle and hasattr(handle, 'debug_messages'):
        handle.debug_messages.append((context, msg))

def mock_log_info(handle, context, msg):
    if handle and hasattr(handle, 'messages'):
        handle.messages.append((context, msg))


# ============================================================================
# MAIN (for testing this module)
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("test_utils.py - Self Test")
    print("=" * 60)

    # Test mock creation
    print("\n1. Testing mock creation...")
    identity = create_mock_identity()
    assert identity.denomination == 1
    assert len(identity.an) == 16
    print("   MockIdentity: OK")

    request = create_mock_request(to_recipients=["0006.1.11111111", "0006.1.22222222"])
    assert len(request.to_recipients) == 2
    print("   MockRequest: OK")

    results = create_mock_upload_results(5)
    assert len(results) == 5
    assert results[0].stripe_index == 0
    print("   MockUploadResults: OK")

    servers = create_mock_servers(5)
    assert len(servers) == 5
    print("   MockServers: OK")

    # Test response builders
    print("\n2. Testing response builders...")
    challenge = os.urandom(16)
    response = build_mock_upload_response(250, challenge)
    assert len(response) == 32
    assert response[5] == 250
    assert response[16:32] == challenge
    print("   build_mock_upload_response: OK")

    response = build_mock_tell_response(166, challenge, raida_id=11)
    assert response[5] == 166
    assert response[2] == 11
    print("   build_mock_tell_response: OK")

    # Test helpers
    print("\n3. Testing helpers...")
    locker = generate_test_locker_code()
    assert len(locker) == 8
    print("   generate_test_locker_code: OK")

    guid = generate_test_file_group_guid()
    assert len(guid) == 16
    print("   generate_test_file_group_guid: OK")

    print("\n" + "=" * 60)
    print("All test_utils self-tests passed!")
    print("=" * 60)
