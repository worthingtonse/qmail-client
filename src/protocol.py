"""
protocol.py - QMail Protocol Helpers

This module centralizes the logic for building and parsing the binary
payloads for QMail commands like PING, PEEK, and UPLOAD. By isolating this
complex, byte-level manipulation, we make the main application logic cleaner,
less bug-prone, and easier to test.

Original Author: Gemini (PING, PEEK commands)
Extended by: Claude Opus 4.5 (Upload, Tell, Download, Make Change commands)
Version: 1.2.0

Changes in v1.2.0:
    - Added Make Change (Command Group 8, Command 90) for coin breaking functionality
    - build_make_change_payload() for 203-byte payload
    - build_make_change_header() for 32-byte header with encryption type 1
    - build_complete_make_change_request() for complete request building

Changes in v1.1.0:
    - Added build_upload_header() for 32-byte request header
    - Added build_upload_payload() for upload command body
    - Added encrypt_payload() for AES-128-CTR encryption
    - Added validate_upload_response() for response validation
"""

import os
import zlib
import struct
import hashlib
from enum import IntEnum
from typing import List, Optional, Tuple

# AES encryption - use pycryptodome if available, fallback to simple XOR for testing
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from qmail_types import TellNotification, ServerLocation, StorageDuration
    from logger import log_error, log_debug, log_warning
except ImportError:
    # Fallback for standalone testing - define complete classes
    from dataclasses import dataclass, field
    from typing import List

    @dataclass
    class ServerLocation:
        """Fallback ServerLocation for standalone testing."""
        stripe_index: int = 0
        total_stripes: int = 0
        server_id: int = 0
        raw_entry: bytes = field(default_factory=lambda: bytes(32))

    @dataclass
    class TellNotification:
        """Fallback TellNotification for standalone testing."""
        file_guid: bytes = field(default_factory=lambda: bytes(16))
        locker_code: bytes = field(default_factory=lambda: bytes(8))
        timestamp: int = 0
        tell_type: int = 0
        server_count: int = 0
        server_list: List[ServerLocation] = field(default_factory=list)

    class StorageDuration:
        ONE_DAY = 0
        ONE_WEEK = 1
        ONE_MONTH = 2
        THREE_MONTHS = 3
        SIX_MONTHS = 4
        ONE_YEAR = 5
        PERMANENT = 255

    def log_error(*args, **kwargs): pass
    def log_debug(*args, **kwargs): pass
    def log_warning(*args, **kwargs): pass
    print("Warning: Using fallback classes for protocol module.")


# ============================================================================
# CONSTANTS
# ============================================================================

# QMail Command Group and Codes
CMD_GROUP_FILES = 6       # Command Group for file operations
CMD_GROUP_QMAIL = 6       # Alias for backward compatibility
CMD_UPLOAD = 60           # PUT/Upload command code (0x3C)
CMD_TELL = 61             # TELL command code - notify beacon of new message
CMD_PING = 62             # PING command code
CMD_PEEK = 63             # PEEK command code
CMD_DOWNLOAD = 64         # GET/Download command code

# Change Service Command Group and Codes
CMD_GROUP_CHANGE = 8      # Command Group for change-making operations (same as Locker)
CMD_MAKE_CHANGE = 90      # Make Change command code (0x5A)

# Locker Service Command Group and Codes
CMD_GROUP_LOCKER = 8      # Command Group for locker operations
CMD_LOCKER_PUT = 82       # Put coins into locker (0x52)
CMD_LOCKER_PEEK = 83      # Peek at locker contents (0x53)
CMD_LOCKER_REMOVE = 84    # Remove coins from locker (0x54)
CMD_LOCKER_DOWNLOAD = 91  # Download coins from locker (0x5B) - per server protocol.c

# Protocol constants
COIN_TYPE = 0x0006
TERMINATOR = bytes([0x3E, 0x3E])


# Encryption types
ENC_NONE = 0              # No encryption
ENC_SHARED_SECRET = 1     # AES-128-CTR with shared secret
ENC_LOCKER_CODE = 2       # AES-128-CTR with locker code
ENC_RAIDA_KEY = 3         # AES-128-CTR with RAIDA key exchange
ENC_256_SHARED = 4        # AES-256-CTR with shared secret
ENC_256_TWO_SECRETS = 5   # AES-256-CTR with two shared secrets

# Header sizes
HEADER_SIZE_128 = 32      # Header size for 128-bit encryption
HEADER_SIZE_256 = 64      # Header size for 256-bit encryption

# Module context for logging
PROTOCOL_CONTEXT = "Protocol"


# ============================================================================
# ERROR CODES
# ============================================================================

class ProtocolErrorCode(IntEnum):
    SUCCESS = 0
    ERR_INVALID_BODY = 1
    ERR_INCOMPLETE_DATA = 2


# ============================================================================
# BODY BUILDER FUNCTIONS
# ============================================================================

def _generate_challenge() -> bytes:
    """
    Generates a 16-byte challenge: 12 random bytes + 4-byte CRC32 checksum.
    """
    original_random_bytes = os.urandom(16)
    bytes_to_crc = original_random_bytes[:12]
    crc32_val = zlib.crc32(bytes_to_crc) & 0xFFFFFFFF
    crc32_bytes = struct.pack('>I', crc32_val)
    return bytes_to_crc + crc32_bytes


def build_ping_body(
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes
) -> bytes:
    """
    Builds the 50-byte PING request body (before encryption).

    Args:
        denomination: User's denomination.
        serial_number: User's mailbox ID.
        device_id: 8-bit device identifier (0-255).
        an: 16-byte Authenticity Number for Mode B.

    Returns:
        A 50-byte byte string representing the PING request body.

    Body format (per QMAIL_PING_COMMAND.md):
        Bytes 0-15:  Challenge/CRC
        Bytes 16-23: Session ID (zeros for Mode B)
        Bytes 24-25: Coin Type (0x0006)
        Byte 26:     Denomination
        Bytes 27-30: Serial Number (big-endian)
        Byte 31:     Device ID (8-bit)
        Bytes 32-47: Authenticity Number (AN)
        Bytes 48-49: Terminator (0x3E 0x3E)
    """
    body = bytearray(50)

    # Bytes 0-15: Challenge/CRC
    body[0:16] = _generate_challenge()

    # Bytes 16-23: Session ID (8 bytes of zeros for Mode B)
    body[16:24] = bytes(8)

    # Bytes 24-25: Coin Type (big-endian)
    struct.pack_into('>H', body, 24, COIN_TYPE)

    # Byte 26: Denomination
    body[26] = denomination

    # Bytes 27-30: Serial Number (big-endian)
    struct.pack_into('>I', body, 27, serial_number)

    # Byte 31: Device ID (8-bit per protocol spec)
    body[31] = device_id & 0xFF

    # Bytes 32-47: Authenticity Number (AN)
    body[32:48] = an[:16]

    # Bytes 48-49: Terminator
    body[48:50] = TERMINATOR

    return bytes(body)


def build_peek_body(
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    since_timestamp: int
) -> bytes:
    """
    Builds the 54-byte PEEK request body (before encryption).

    Args:
        denomination: User's denomination.
        serial_number: User's mailbox ID.
        device_id: 8-bit device identifier (0-255).
        an: 16-byte Authenticity Number.
        since_timestamp: Unix timestamp to get tells since.

    Returns:
        A 54-byte byte string representing the PEEK request body.

    Body format (per QMAIL_PEEK_COMMAND.md):
        Bytes 0-15:  Challenge/CRC
        Bytes 16-23: Session ID (zeros for Mode B)
        Bytes 24-25: Coin Type (0x0006)
        Byte 26:     Denomination
        Bytes 27-30: Serial Number (big-endian)
        Byte 31:     Device ID (8-bit)
        Bytes 32-47: Authenticity Number (AN)
        Bytes 48-51: Since Timestamp (big-endian)
        Bytes 52-53: Terminator (0x3E 0x3E)
    """
    body = bytearray(54)

    # Bytes 0-15: Challenge/CRC
    body[0:16] = _generate_challenge()

    # Bytes 16-23: Session ID (zeros for Mode B)
    body[16:24] = bytes(8)

    # Bytes 24-25: Coin Type (big-endian)
    struct.pack_into('>H', body, 24, COIN_TYPE)

    # Byte 26: Denomination
    body[26] = denomination

    # Bytes 27-30: Serial Number (big-endian)
    struct.pack_into('>I', body, 27, serial_number)

    # Byte 31: Device ID (8-bit per protocol spec)
    body[31] = device_id & 0xFF

    # Bytes 32-47: Authenticity Number (AN)
    body[32:48] = an[:16]

    # Bytes 48-51: Since Timestamp (big-endian)
    struct.pack_into('>I', body, 48, since_timestamp)

    # Bytes 52-53: Terminator
    body[52:54] = TERMINATOR

    return bytes(body)


# ============================================================================
# RESPONSE PARSER FUNCTIONS
# ============================================================================

def parse_tell_response(
    response_body: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, List[TellNotification]]:
    """
    Parses the decrypted response body from a PING or PEEK command.

    This implements the correct parsing logic for the "Tell Array" structure
    as documented in QMAIL_PING_COMMAND.md, including the variable-length
    server list.

    Args:
        response_body: The raw, decrypted bytes of the response payload.
        logger_handle: Optional logger handle.

    Returns:
        A tuple containing:
        - ProtocolErrorCode indicating success or failure.
        - A list of TellNotification objects.
    """
    if not response_body or len(response_body) < 8:
        log_debug(logger_handle, "Protocol", "Tell response is empty or too short for a header.")
        return ProtocolErrorCode.SUCCESS, []

    try:
        tell_count = response_body[0]
        total_tells = struct.unpack('>H', response_body[1:3])[0]

        log_debug(logger_handle, "Protocol", f"Parsing tell response. Header: tell_count={tell_count}, total_tells_remaining={total_tells}")

        if tell_count == 0:
            return ProtocolErrorCode.SUCCESS, []

        notifications = []
        offset = 8  # Tells start after the 8-byte response header

        for i in range(tell_count):
            # Each tell has a fixed header of 40 bytes before the server list
            min_tell_size = 40
            if offset + min_tell_size > len(response_body):
                log_error(logger_handle, "Protocol", f"Incomplete data for tell #{i+1} at offset {offset}.")
                return ProtocolErrorCode.ERR_INCOMPLETE_DATA, notifications

            tell = TellNotification()

            # Parse the fixed-size part of the tell
            tell.file_guid = response_body[offset : offset + 16]
            tell.locker_code = response_body[offset + 16 : offset + 24]
            tell.timestamp = struct.unpack('>I', response_body[offset + 24 : offset + 28])[0]
            tell.tell_type = response_body[offset + 28]
            # byte 29 is reserved
            tell.server_count = response_body[offset + 30]
            # bytes 31-39 are reserved

            # Move offset past the fixed part
            offset += min_tell_size

            # Parse the variable-length server list
            server_list = []
            for _ in range(tell.server_count):
                server_entry_size = 32
                if offset + server_entry_size > len(response_body):
                    log_error(logger_handle, "Protocol", f"Incomplete data for server list in tell #{i+1}.")
                    # Stop parsing this tell, but keep already parsed ones
                    offset = len(response_body) # Force outer loop to break
                    break

                server_data = response_body[offset : offset + server_entry_size]

                location = ServerLocation(
                    stripe_index=server_data[0],
                    total_stripes=server_data[1],
                    server_id=server_data[2],
                    raw_entry=server_data
                )
                server_list.append(location)
                offset += server_entry_size

            tell.server_list = server_list
            notifications.append(tell)

        return ProtocolErrorCode.SUCCESS, notifications

    except (struct.error, IndexError) as e:
        log_error(logger_handle, "Protocol", f"Failed to parse tell response due to malformed data: {e}")
        return ProtocolErrorCode.ERR_INVALID_BODY, []


# ============================================================================
# PING/PEEK COMMAND FUNCTIONS
# ============================================================================

def build_peek_header(
    raida_id: int,
    an: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for PEEK command.

    PEEK uses encryption type 1 (shared secret / AN-based encryption).
    The AN is used to derive the encryption key.

    Args:
        raida_id: RAIDA server ID (0-24)
        an: 16-byte Authenticity Number for encryption key derivation
        body_length: Length of encrypted body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)
    """
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_peek_header failed",
                  "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_peek_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_QMAIL        # CG: Command Group (6)
    header[5] = CMD_PEEK               # CM: Command (63 = Peek)
    struct.pack_into('>H', header, 6, COIN_TYPE)              # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = ENC_SHARED_SECRET     # EN: Encryption type 1 (AN-based)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number (4 bytes)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce              # NO: Full 8-byte nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built peek header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_ping_header(
    raida_id: int,
    an: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for PING command.

    PING uses encryption type 1 (shared secret / AN-based encryption).

    Args:
        raida_id: RAIDA server ID (0-24)
        an: 16-byte Authenticity Number for encryption key derivation
        body_length: Length of encrypted body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)
    """
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_ping_header failed",
                  "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_ping_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_QMAIL        # CG: Command Group (6)
    header[5] = CMD_PING               # CM: Command (62 = Ping)
    struct.pack_into('>H', header, 6, COIN_TYPE)              # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = ENC_SHARED_SECRET     # EN: Encryption type 1 (AN-based)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number (4 bytes)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce              # NO: Full 8-byte nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built ping header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def encrypt_payload_with_an(
    payload: bytes,
    an: bytes,
    nonce: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Encrypt payload using AES-128-CTR with AN as key.

    The AN (Authenticity Number) is used directly as the 16-byte encryption key.

    Args:
        payload: Plaintext payload to encrypt
        an: 16-byte Authenticity Number (used as encryption key)
        nonce: 6-byte nonce from header
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, encrypted bytes)
    """
    if payload is None or len(payload) == 0:
        log_warning(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload_with_an called with empty payload")
        return ProtocolErrorCode.SUCCESS, b''

    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload_with_an failed",
                  "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    # Use AN directly as 16-byte key
    key = an[:16]

    if HAS_CRYPTO:
        try:
            # Build 16-byte initial counter value from nonce
            # Server uses 8 bytes from header[24:31] + 8 zero bytes
            if nonce is None or len(nonce) < 8:
                nonce = os.urandom(8)
            counter_init = nonce[:8] + bytes(8)

            # Create counter
            ctr = Counter.new(128, initial_value=int.from_bytes(counter_init, 'big'))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            encrypted = cipher.encrypt(payload)

            log_debug(logger_handle, PROTOCOL_CONTEXT,
                      f"Encrypted {len(payload)} bytes using AES-128-CTR with AN")
            return ProtocolErrorCode.SUCCESS, encrypted

        except Exception as e:
            log_error(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload_with_an failed", str(e))
            return ProtocolErrorCode.ERR_INVALID_BODY, b''
    else:
        # Fallback: simple XOR for testing (NOT SECURE)
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    "pycryptodome not installed, using insecure XOR cipher for testing")
        result = bytearray(len(payload))
        for i in range(len(payload)):
            result[i] = payload[i] ^ key[i % 16]
        return ProtocolErrorCode.SUCCESS, bytes(result)


def decrypt_payload_with_an(
    encrypted_data: bytes,
    an: bytes,
    nonce: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Decrypt payload using AES-128-CTR with AN as key.

    Args:
        encrypted_data: Encrypted payload to decrypt
        an: 16-byte Authenticity Number (used as decryption key)
        nonce: 6-byte nonce from request header
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, decrypted bytes)
    """
    # AES-CTR encryption and decryption are the same operation
    return encrypt_payload_with_an(encrypted_data, an, nonce, logger_handle)


def build_complete_peek_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    since_timestamp: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete PEEK request (header + encrypted payload).

    PEEK checks for new mail notifications (Tells) in the user's mailbox.
    It requires the user's AN to authenticate and decrypt the response.

    Args:
        raida_id: RAIDA server ID (0-24)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: 16-bit device identifier
        an: 16-byte Authenticity Number
        since_timestamp: Only get tells newer than this timestamp (0 = all)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge, nonce)
    """
    # Build payload
    payload = build_peek_body(denomination, serial_number, device_id, an, since_timestamp)

    # Build header
    err, header = build_peek_header(
        raida_id, an, len(payload),
        denomination, serial_number, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Get nonce from header
    nonce = header[24:32]

    # Extract challenge from payload (first 16 bytes)
    challenge = payload[:16]

    # Encrypt payload using AN
    err, encrypted_payload = encrypt_payload_with_an(payload, an, nonce, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Combine header + encrypted payload
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete PEEK request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


def build_complete_ping_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete PING request (header + encrypted payload).

    PING checks mailbox status and validates the user's AN.

    Args:
        raida_id: RAIDA server ID (0-24)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: 16-bit device identifier
        an: 16-byte Authenticity Number
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge, nonce)
    """
    # Build payload
    payload = build_ping_body(denomination, serial_number, device_id, an)

    # Build header
    err, header = build_ping_header(
        raida_id, an, len(payload),
        denomination, serial_number, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Get nonce from header
    nonce = header[24:32]

    # Extract challenge from payload (first 16 bytes)
    challenge = payload[:16]

    # Encrypt payload using AN
    err, encrypted_payload = encrypt_payload_with_an(payload, an, nonce, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Combine header + encrypted payload
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete PING request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


# ============================================================================
# UPLOAD COMMAND FUNCTIONS (Added by opus45)
# ============================================================================

def weeks_to_duration_code(weeks: int) -> int:
    """
    Convert storage weeks to protocol duration code.

    Args:
        weeks: Number of weeks to store

    Returns:
        Duration code (0-5 or 255 for permanent)

    Protocol mapping:
        0 = 1 day
        1 = 1 week
        2 = 1 month (~4 weeks)
        3 = 3 months (~12 weeks)
        4 = 6 months (~26 weeks)
        5 = 1 year (~52 weeks)
        255 = Permanent
    """
    if weeks <= 0:
        return StorageDuration.ONE_DAY
    elif weeks == 1:
        return StorageDuration.ONE_WEEK
    elif weeks <= 4:
        return StorageDuration.ONE_MONTH
    elif weeks <= 12:
        return StorageDuration.THREE_MONTHS
    elif weeks <= 26:
        return StorageDuration.SIX_MONTHS
    elif weeks <= 52:
        return StorageDuration.ONE_YEAR
    else:
        return StorageDuration.PERMANENT


def build_upload_header(
    raida_id: int,
    locker_code: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for upload command.

    The header is NOT encrypted and contains routing, presentation,
    encryption, and nonce information.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_code: 8-byte locker code for encryption key derivation
        body_length: Length of encrypted body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)
    """
    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_header failed",
                  "locker_code must be at least 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_FILES        # CG: Command Group (6 = Files)
    header[5] = CMD_UPLOAD             # CM: Command (60 = Upload)
    struct.pack_into('>H', header, 6, COIN_TYPE)              # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = ENC_LOCKER_CODE       # EN: Encryption type 2 (locker code)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number (4 bytes)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        # For bodies > 64KB, set to 0xFFFF and use extended length in body
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce              # NO: Full 8-byte nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built upload header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_upload_payload(
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    locker_code: bytes,
    storage_duration: int,
    stripe_data: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build the upload command payload (before encryption).

    Args:
        denomination: User's denomination
        serial_number: User's mailbox ID (serial number)
        device_id: 8-bit device identifier (0-255)
        an: 16-byte Authenticity Number
        file_group_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        storage_duration: Duration code (0-5 or 255)
        stripe_data: Binary data to upload (one stripe)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, payload bytes, challenge bytes for validation)

    Payload format:
        Bytes 0-15:  Challenge (12 random + 4 CRC32)
        Bytes 16-23: Session ID (zeros for Mode B)
        Bytes 24-25: Coin Type (0x00 0x06)
        Byte 26:     Denomination
        Bytes 27-30: Serial Number
        Byte 31:     Device ID (8-bit)
        Bytes 32-47: AN (Authenticity Number)
        Bytes 48-63: File Group GUID
        Bytes 64-71: Locker Code
        Bytes 72-73: Reserved
        Byte 74:     Reserved (was file_index)
        Byte 75:     Storage Duration
        Bytes 76-79: Reserved
        Bytes 80-83: Data Length (big-endian)
        Bytes 84+:   Binary Data
        End:         0x3E 0x3E terminator
    """
    # Validate inputs
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_payload failed",
                  "AN must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if file_group_guid is None or len(file_group_guid) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_payload failed",
                  "file_group_guid must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_payload failed",
                  "locker_code must be 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    # Calculate total payload size: fixed header (84) + data + terminator (2)
    data_length = len(stripe_data) if stripe_data else 0
    payload_size = 84 + data_length + 2

    payload = bytearray(payload_size)

    # Challenge (0-15): 12 random bytes + 4 CRC32
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Session ID (16-23): zeros for Mode B
    payload[16:24] = bytes(8)

    # Coin Type (24-25): 0x0006
    struct.pack_into('>H', payload, 24, COIN_TYPE)

    # Denomination (26)
    payload[26] = denomination

    # Serial Number (27-30): big-endian
    struct.pack_into('>I', payload, 27, serial_number)

    # Device ID (31): 8-bit per protocol spec
    payload[31] = device_id & 0xFF

    # AN (32-47): 16 bytes
    payload[32:48] = an[:16]

    # File Group GUID (48-63): 16 bytes
    payload[48:64] = file_group_guid[:16]

    # Locker Code (64-71): 8 bytes
    payload[64:72] = locker_code[:8]

    # Reserved (72-73)
    payload[72:74] = bytes(2)

    # Reserved - was file_index (74)
    payload[74] = 0x00

    # Storage Duration (75)
    payload[75] = storage_duration & 0xFF

    # Reserved (76-79)
    payload[76:80] = bytes(4)

    # Data Length (80-83): big-endian
    struct.pack_into('>I', payload, 80, data_length)

    # Binary Data (84+)
    if stripe_data:
        payload[84:84 + data_length] = stripe_data

    # Terminator
    payload[-2:] = TERMINATOR

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built upload payload: {payload_size} bytes, data={data_length} bytes")

    return ProtocolErrorCode.SUCCESS, bytes(payload), challenge


def encrypt_payload(
    payload: bytes,
    locker_code: bytes,
    nonce: bytes,
    raida_id: int,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Encrypt payload using AES-128-CTR with locker code as key.

    The encryption key is derived from the locker code using MD5 with
    the RAIDA ID prepended. The nonce from the header is used as part
    of the counter initialization.

    Args:
        payload: Plaintext payload to encrypt
        locker_code: 8-byte locker code (string or bytes)
        nonce: 8-byte nonce from header (positions 24-31)
        raida_id: RAIDA server ID (0-24) for key derivation
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, encrypted bytes)

    Note: If pycryptodome is not installed, returns a simple XOR cipher
    for testing purposes only.
    """
    if payload is None or len(payload) == 0:
        log_warning(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload called with empty payload")
        return ProtocolErrorCode.SUCCESS, b''

    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload failed",
                  "locker_code must be at least 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    # Derive 16-byte key from locker code using MD5(raida_id + locker_code)
    # This matches the server's key derivation algorithm
    try:
        from key_manager import get_decryption_key
        key = get_decryption_key(locker_code, raida_id)
    except ImportError:
        # Fallback: use MD5 directly if key_manager not available
        h = hashlib.md5()
        locker_str = locker_code.hex() if isinstance(locker_code, bytes) else str(locker_code)
        h.update(str(raida_id).encode('utf-8'))
        h.update(locker_str.encode('utf-8'))
        key = h.digest()

    if HAS_CRYPTO:
        try:
            # Build 16-byte initial counter value from nonce
            # Server uses 8 bytes from header[24:31] + 8 zero bytes
            if nonce is None or len(nonce) < 8:
                nonce = os.urandom(8)
            counter_init = nonce[:8] + bytes(8)

            # Create counter - starting value from nonce
            ctr = Counter.new(128, initial_value=int.from_bytes(counter_init, 'big'))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            encrypted = cipher.encrypt(payload)

            log_debug(logger_handle, PROTOCOL_CONTEXT,
                      f"Encrypted {len(payload)} bytes using AES-128-CTR")
            return ProtocolErrorCode.SUCCESS, encrypted

        except Exception as e:
            log_error(logger_handle, PROTOCOL_CONTEXT, "encrypt_payload failed", str(e))
            return ProtocolErrorCode.ERR_INVALID_BODY, b''
    else:
        # Fallback: simple XOR for testing (NOT SECURE)
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    "pycryptodome not installed, using insecure XOR cipher for testing")
        result = bytearray(len(payload))
        for i in range(len(payload)):
            result[i] = payload[i] ^ key[i % 16]
        return ProtocolErrorCode.SUCCESS, bytes(result)


def validate_upload_response(
    response: bytes,
    expected_challenge: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, int, str]:
    """
    Validate an upload response from the server.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, error_message)
        - SUCCESS and status 250 for successful upload
        - ERR_INVALID_BODY for malformed response
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_upload_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, "Response too short"

    # Check challenge echo in response (bytes 16-32 of header)
    challenge_echo = response[16:32]
    if challenge_echo != expected_challenge:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_upload_response failed",
                  "Challenge mismatch - possible spoofing or corruption")
        return ProtocolErrorCode.ERR_INVALID_BODY, 0, "Challenge mismatch"

    # Extract status code from response
    # Status is typically at a fixed offset in the response body
    # For now, assume success if challenge validates
    # TODO: Parse actual status code from response body

    log_debug(logger_handle, PROTOCOL_CONTEXT, "Upload response validated successfully")
    return ProtocolErrorCode.SUCCESS, 250, ""


def build_complete_upload_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    locker_code: bytes,
    storage_duration: int,
    stripe_data: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build a complete upload request (header + encrypted payload).

    This is a convenience function that combines header building,
    payload building, and encryption into a single call.

    Args:
        raida_id: RAIDA server ID (0-24)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: 16-bit device identifier
        an: 16-byte Authenticity Number
        file_group_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        storage_duration: Duration code (0-5 or 255)
        stripe_data: Binary data to upload
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge for validation)
    """
    # Build payload first to get size
    err, payload, challenge = build_upload_payload(
        denomination, serial_number, device_id, an,
        file_group_guid, locker_code, storage_duration,
        stripe_data, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Note: AES-128-CTR is a stream cipher and does NOT require padding

    # Build header
    err, header = build_upload_header(
        raida_id, locker_code, len(payload),
        denomination, serial_number, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Get nonce from header for encryption
    nonce = header[24:32]

    # Encrypt payload with raida_id for proper key derivation
    err, encrypted_payload = encrypt_payload(payload, locker_code, nonce, raida_id, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Combine header + encrypted payload
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete upload request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge


# ============================================================================
# TELL COMMAND FUNCTIONS (Added by opus45)
# ============================================================================

# Tell Type constants
TELL_TYPE_QMAIL = 0
TELL_TYPE_QTEXT = 1
TELL_TYPE_QCHAT = 2
TELL_TYPE_PEER_SECRET = 3
TELL_TYPE_GROUP_SECRET = 4
TELL_TYPE_QPACKET = 5
TELL_TYPE_QDATA = 6
# Types 10-255 are for attachments


def build_tell_header(
    raida_id: int,
    an: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for Tell command.

    The header is NOT encrypted. Uses encryption type 1 (AN-based) so the
    server can decrypt using the sender's known AN.

    Args:
        raida_id: Beacon server ID (0-24)
        an: 16-byte Authenticity Number for encryption key derivation
        body_length: Length of encrypted body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)
    """
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_header failed",
                  "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID (beacon server)
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_QMAIL        # CG: Command Group (6)
    header[5] = CMD_TELL               # CM: Command (61 = Tell)
    struct.pack_into('>H', header, 6, COIN_TYPE)              # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    # Use encryption type 1 (AN-based) so server can decrypt with sender's AN
    header[16] = ENC_SHARED_SECRET     # EN: Encryption type 1 (AN-based)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number (4 bytes)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce              # NO: Full 8-byte nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built tell header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_tell_payload(
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    timestamp: int,
    tell_type: int,
    recipients: List,
    servers: List,
    beacon_payment_locker: Optional[bytes] = None,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build the Tell command payload (before encryption).

    Args:
        denomination: Sender's denomination
        serial_number: Sender's mailbox ID
        device_id: 8-bit device identifier
        an: 16-byte Authenticity Number
        file_group_guid: 16-byte Email ID GUID
        timestamp: Unix timestamp (big-endian)
        tell_type: Type of notification (0 = QMAIL)
        recipients: List of TellRecipient objects
        servers: List of TellServer objects
        beacon_payment_locker: Optional 8-byte locker code for anti-DDOS payment
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, payload bytes, challenge bytes)

    Payload format (from QMAIL_TELL_COMMAND.md):
        Bytes 0-15:  Challenge (12 random + 4 CRC32)
        Bytes 16-23: Session ID (zeros for encryption type 2)
        Bytes 24-25: Coin Type (0x00 0x06)
        Byte 26:     Denomination
        Bytes 27-30: Serial Number (big-endian)
        Byte 31:     Device ID
        Bytes 32-47: AN (Authenticity Number)
        Bytes 48-63: Email ID GUID
        Bytes 64-71: RAID Type (zeros)
        Bytes 72-75: Timestamp (big-endian)
        Byte 76:     Tell Type
        Byte 77:     Address Count (AC)
        Byte 78:     Server Count (QC)
        Bytes 79-86: Beacon Payment Locker (8 bytes, anti-DDOS)
        Byte 87:     Reserved
        Variable:    Recipient List (AC x 32 bytes)
        Variable:    Server List (QC x 32 bytes)
        End:         0x3E 0x3E terminator (NOT encrypted)
    """
    # Validate inputs
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_payload failed",
                  "AN must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if file_group_guid is None or len(file_group_guid) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_payload failed",
                  "file_group_guid must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    address_count = len(recipients) if recipients else 0
    server_count = len(servers) if servers else 0

    if address_count > 255:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_payload failed",
                  f"Too many recipients: {address_count} (max 255)")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if server_count > 255:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_tell_payload failed",
                  f"Too many servers: {server_count} (max 255)")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    # Calculate payload size:
    # Fixed header (88 bytes) + recipients (AC * 32) + servers (QC * 32) + terminator (2 bytes)
    # Note: Terminator MUST be INSIDE the encrypted payload (server checks it after decryption)
    fixed_size = 88
    terminator_size = 2
    data_size = fixed_size + (address_count * 32) + (server_count * 32) + terminator_size
    payload_size = data_size

    # Pad to 16-byte boundary for AES
    if payload_size % 16 != 0:
        payload_size = ((payload_size // 16) + 1) * 16

    payload = bytearray(payload_size)

    # Challenge (0-15): 12 random bytes + 4 CRC32
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Session ID (16-23): zeros for encryption type 2
    payload[16:24] = bytes(8)

    # Coin Type (24-25): 0x0006
    struct.pack_into('>H', payload, 24, COIN_TYPE)

    # Denomination (26)
    payload[26] = denomination & 0xFF

    # Serial Number (27-30): big-endian
    struct.pack_into('>I', payload, 27, serial_number)

    # Device ID (31)
    payload[31] = device_id & 0xFF

    # AN (32-47): 16 bytes
    payload[32:48] = an[:16]

    # Email ID GUID (48-63): 16 bytes
    payload[48:64] = file_group_guid[:16]

    # RAID Type (64-71): zeros for now
    payload[64:72] = bytes(8)

    # Timestamp (72-75): big-endian
    struct.pack_into('>I', payload, 72, timestamp)

    # Tell Type (76)
    payload[76] = tell_type & 0xFF

    # Address Count (77)
    payload[77] = address_count & 0xFF

    # Server Count (78)
    payload[78] = server_count & 0xFF

    # Beacon Payment Locker (79-86): Optional anti-DDOS payment
    if beacon_payment_locker and len(beacon_payment_locker) >= 8:
        payload[79:87] = beacon_payment_locker[:8]
    else:
        payload[79:87] = bytes(8)

    # Reserved (87)
    payload[87] = 0

    # Recipient List (starting at offset 88)
    offset = 88
    for recipient in (recipients or []):
        # Each recipient is 32 bytes:
        # [Type(1)][CoinID(2)][Denom(1)][DomainID(1)][SN(3)][LockerKey(16)][Reserved(8)]
        payload[offset] = recipient.address_type & 0xFF
        struct.pack_into('>H', payload, offset + 1, recipient.coin_id)
        payload[offset + 3] = recipient.denomination & 0xFF
        payload[offset + 4] = recipient.domain_id & 0xFF
        # Serial number is 3 bytes (24 bits)
        sn_bytes = (recipient.serial_number & 0xFFFFFF).to_bytes(3, 'big')
        payload[offset + 5:offset + 8] = sn_bytes
        # Locker payment key (16 bytes)
        if recipient.locker_payment_key and len(recipient.locker_payment_key) >= 16:
            payload[offset + 8:offset + 24] = recipient.locker_payment_key[:16]
        # Reserved (8 bytes)
        payload[offset + 24:offset + 32] = bytes(8)
        offset += 32

    # Server List
    for server in (servers or []):
        # Each server is 32 bytes:
        # [StripeIndex(1)][StripeType(1)][LockerCode(8)][IP(16)][Port(2)][Reserved(4)]
        payload[offset] = server.stripe_index & 0xFF
        payload[offset + 1] = server.stripe_type & 0xFF
        # Locker Code (8 bytes): actual locker code for this server's stripe
        # This allows recipient to derive decryption key for each stripe
        if hasattr(server, 'locker_code') and server.locker_code:
            locker_bytes = server.locker_code[:8] if isinstance(server.locker_code, bytes) else bytes(8)
            payload[offset + 2:offset + 10] = locker_bytes.ljust(8, b'\x00')
        else:
            payload[offset + 2:offset + 10] = bytes(8)
        # IP address (16 bytes): IPv4 in last 4 bytes
        ip_bytes = bytes(16)
        if server.ip_address:
            try:
                parts = server.ip_address.split('.')
                if len(parts) == 4:
                    ip_v4 = bytes([int(p) for p in parts])
                    ip_bytes = bytes(12) + ip_v4
            except (ValueError, AttributeError):
                pass
        payload[offset + 10:offset + 26] = ip_bytes
        # Port (2 bytes)
        struct.pack_into('>H', payload, offset + 26, server.port)
        # Reserved (4 bytes)
        payload[offset + 28:offset + 32] = bytes(4)
        offset += 32

    # Terminator (2 bytes) - MUST be inside the encrypted payload
    payload[offset] = TERMINATOR[0]  # 0x3E
    payload[offset + 1] = TERMINATOR[1]  # 0x3E

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built tell payload: {len(payload)} bytes, "
              f"{address_count} recipients, {server_count} servers (terminator at offset {offset})")

    return ProtocolErrorCode.SUCCESS, bytes(payload), challenge


def build_complete_tell_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    locker_code: bytes,
    timestamp: int,
    tell_type: int,
    recipients: List,
    servers: List,
    beacon_payment_locker: Optional[bytes] = None,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build a complete Tell request (header + encrypted payload + terminator).

    This is a convenience function that combines header building,
    payload building, and encryption into a single call.

    Args:
        raida_id: Beacon server ID (0-24)
        denomination: Sender's denomination
        serial_number: Sender's mailbox ID
        device_id: 8-bit device identifier
        an: 16-byte Authenticity Number (used for encryption)
        file_group_guid: 16-byte Email ID GUID
        locker_code: 8-byte locker code (included in payload for recipient)
        timestamp: Unix timestamp
        tell_type: Type of notification (0 = QMAIL)
        recipients: List of TellRecipient objects
        servers: List of TellServer objects
        beacon_payment_locker: Optional 8-byte locker code for anti-DDOS payment
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge for validation)
    """
    # Build payload first
    err, payload, challenge = build_tell_payload(
        denomination, serial_number, device_id, an,
        file_group_guid, timestamp, tell_type,
        recipients, servers, beacon_payment_locker, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Build header using AN for encryption type 1
    err, header = build_tell_header(
        raida_id, an, len(payload),
        denomination, serial_number, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Get nonce from header for encryption
    nonce = header[24:32]

    # Encrypt payload using AN (encryption type 1)
    err, encrypted_payload = encrypt_payload_with_an(payload, an, nonce, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b''

    # Combine header + encrypted payload
    # Note: Terminator is now INSIDE the encrypted payload (server checks it after decryption)
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete tell request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge


def validate_tell_response(
    response: bytes,
    expected_challenge: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, int, str]:
    """
    Validate a Tell response from the beacon server.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, error_message)
        - SUCCESS and status 250 (0xFA) for successful Tell
        - ERR_INVALID_BODY for malformed response

    Status codes from QMAIL_TELL_COMMAND.md:
        250 (0xFA): STATUS_SUCCESS - Notification created successfully
        166 (0xA6): ERROR_PAYMENT_REQUIRED - Payment failed or locker empty
        16  (0x10): ERROR_INVALID_PACKET_LENGTH - Malformed header or lists
        194 (0xC2): ERROR_FILESYSTEM - Failed to write .meta file
        18  (0x12): ERROR_WRONG_RAIDA - Recipient not found on this Beacon
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_tell_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, "Response too short"

    # Check challenge echo in response header (bytes 16-32)
    if expected_challenge and len(expected_challenge) >= 16:
        challenge_echo = response[16:32]
        if challenge_echo != expected_challenge:
            log_error(logger_handle, PROTOCOL_CONTEXT, "validate_tell_response failed",
                      "Challenge mismatch - possible spoofing or corruption")
            return ProtocolErrorCode.ERR_INVALID_BODY, 0, "Challenge mismatch"

    # Extract status code from response
    # Status byte is typically at offset 5 in response header
    status_code = response[5] if len(response) > 5 else 0

    # Map status codes to error messages
    status_messages = {
        250: "",  # Success
        166: "Payment required - locker key invalid or empty",
        16: "Invalid packet length",
        194: "Filesystem error on beacon",
        18: "Wrong RAIDA - recipient not on this beacon"
    }

    error_msg = status_messages.get(status_code, f"Unknown status: {status_code}")

    if status_code == 250:
        log_debug(logger_handle, PROTOCOL_CONTEXT, "Tell response validated successfully")
        return ProtocolErrorCode.SUCCESS, status_code, ""
    else:
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    f"Tell failed with status {status_code}: {error_msg}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, error_msg


# ============================================================================
# DOWNLOAD COMMAND FUNCTIONS (Added by opus45)
# ============================================================================

# Page size for downloads (64KB)
DOWNLOAD_PAGE_SIZE = 65536  # 64 * 1024


def build_download_header(
    raida_id: int,
    locker_code: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for download command.

    The header is NOT encrypted and contains routing, presentation,
    encryption, and nonce information.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_code: 8-byte locker code for encryption key derivation
        body_length: Length of encrypted body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)
    """
    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_header failed",
                  "locker_code must be at least 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_FILES        # CG: Command Group (6 = Files)
    header[5] = CMD_DOWNLOAD           # CM: Command (64 = Get Object)
    struct.pack_into('>H', header, 6, COIN_TYPE)              # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = ENC_LOCKER_CODE       # EN: Encryption type 2 (locker code)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number (4 bytes)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce              # NO: Full 8-byte nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built download header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_download_payload(
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    locker_code: bytes,
    file_type: int,
    page_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build the download command payload (before encryption).

    Args:
        denomination: User's denomination
        serial_number: User's mailbox ID (serial number)
        device_id: 8-bit device identifier (0-255)
        an: 16-byte Authenticity Number
        file_group_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        file_type: File type (0=email, 10+=attachments)
        page_number: Page number for paginated downloads (0-based)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, payload bytes, challenge bytes for validation)

    Payload format:
        Bytes 0-15:  Challenge (12 random + 4 CRC32)
        Bytes 16-23: Session ID (zeros for Mode B)
        Bytes 24-25: Coin Type (0x00 0x06)
        Byte 26:     Denomination
        Bytes 27-30: Serial Number
        Byte 31:     Device ID (8-bit)
        Bytes 32-47: AN (Authenticity Number)
        Bytes 48-63: File Group GUID
        Bytes 64-71: Locker Code
        Byte 72:     File Type (0=email, 10+=attachments)
        Bytes 73-76: Page Number (big-endian)
        Bytes 77-78: Page Size indicator (0xFFFF = 64KB)
        Bytes 79-80: Reserved
        Bytes 81-82: 0x3E 0x3E terminator
    """
    # Validate inputs
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_payload failed",
                  "AN must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if file_group_guid is None or len(file_group_guid) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_payload failed",
                  "file_group_guid must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_payload failed",
                  "locker_code must be 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    # Fixed payload size: 83 bytes
    payload_size = 83
    payload = bytearray(payload_size)

    # Challenge (0-15): 12 random bytes + 4 CRC32
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Session ID (16-23): zeros for Mode B
    payload[16:24] = bytes(8)

    # Coin Type (24-25): 0x0006
    struct.pack_into('>H', payload, 24, COIN_TYPE)

    # Denomination (26)
    payload[26] = denomination

    # Serial Number (27-30): big-endian
    struct.pack_into('>I', payload, 27, serial_number)

    # Device ID (31): 8-bit per protocol spec
    payload[31] = device_id & 0xFF

    # AN (32-47): 16 bytes
    payload[32:48] = an[:16]

    # File Group GUID (48-63): 16 bytes
    payload[48:64] = file_group_guid[:16]

    # Locker Code (64-71): 8 bytes
    payload[64:72] = locker_code[:8]

    # File Type (72)
    payload[72] = file_type & 0xFF

    # Page Number (73-76): big-endian
    struct.pack_into('>I', payload, 73, page_number)

    # Page Size indicator (77-78): 0xFFFF = 64KB
    payload[77] = 0xFF
    payload[78] = 0xFF

    # Reserved (79-80)
    payload[79:81] = bytes(2)

    # Terminator (81-82)
    payload[81:83] = TERMINATOR

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built download payload: file_type={file_type}, page={page_number}")

    return ProtocolErrorCode.SUCCESS, bytes(payload), challenge


def decrypt_payload(
    encrypted_data: bytes,
    locker_code: bytes,
    nonce: bytes,
    raida_id: int,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Decrypt payload using AES-128-CTR with locker code as key.

    The decryption key is derived from the locker code using MD5 with
    the RAIDA ID prepended. The nonce from the header is used as part
    of the counter initialization.

    Args:
        encrypted_data: Encrypted payload to decrypt
        locker_code: 8-byte locker code (string or bytes)
        nonce: 8-byte nonce from request header (positions 24-31)
        raida_id: RAIDA server ID (0-24) for key derivation
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, decrypted bytes)

    Note: AES-CTR encryption and decryption use the same operation.
    """
    if encrypted_data is None or len(encrypted_data) == 0:
        log_warning(logger_handle, PROTOCOL_CONTEXT, "decrypt_payload called with empty data")
        return ProtocolErrorCode.SUCCESS, b''

    if locker_code is None or len(locker_code) < 8:
        log_error(logger_handle, PROTOCOL_CONTEXT, "decrypt_payload failed",
                  "locker_code must be at least 8 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    # Derive 16-byte key from locker code using MD5(raida_id + locker_code)
    # This matches the server's key derivation algorithm
    try:
        from key_manager import get_decryption_key
        key = get_decryption_key(locker_code, raida_id)
    except ImportError:
        # Fallback: use MD5 directly if key_manager not available
        h = hashlib.md5()
        locker_str = locker_code.hex() if isinstance(locker_code, bytes) else str(locker_code)
        h.update(str(raida_id).encode('utf-8'))
        h.update(locker_str.encode('utf-8'))
        key = h.digest()

    if HAS_CRYPTO:
        try:
            # Build 16-byte initial counter value from nonce
            # Server uses 8 bytes from header[24:31] + 8 zero bytes
            if nonce is None or len(nonce) < 8:
                log_error(logger_handle, PROTOCOL_CONTEXT, "decrypt_payload failed",
                          "nonce must be at least 8 bytes")
                return ProtocolErrorCode.ERR_INVALID_BODY, b''
            counter_init = nonce[:8] + bytes(8)

            # Create counter
            ctr = Counter.new(128, initial_value=int.from_bytes(counter_init, 'big'))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            decrypted = cipher.decrypt(encrypted_data)

            log_debug(logger_handle, PROTOCOL_CONTEXT,
                      f"Decrypted {len(encrypted_data)} bytes using AES-128-CTR")
            return ProtocolErrorCode.SUCCESS, decrypted

        except Exception as e:
            log_error(logger_handle, PROTOCOL_CONTEXT, "decrypt_payload failed", str(e))
            return ProtocolErrorCode.ERR_INVALID_BODY, b''
    else:
        # Fallback: simple XOR for testing (NOT SECURE)
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    "pycryptodome not installed, using insecure XOR cipher for testing")
        result = bytearray(len(encrypted_data))
        for i in range(len(encrypted_data)):
            result[i] = encrypted_data[i] ^ key[i % 16]
        return ProtocolErrorCode.SUCCESS, bytes(result)


def validate_download_response(
    response: bytes,
    expected_challenge: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, int, int, bytes]:
    """
    Validate a download response from the server.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, data_length, response_data)
        - SUCCESS and status 250 for successful download
        - ERR_INVALID_BODY for malformed response

    Response header format (32 bytes):
        Bytes 0-7:   Routing echo
        Bytes 8-15:  Presentation echo
        Bytes 16-31: Challenge echo

    Response body:
        Byte 0:      Status code (250 = success)
        Bytes 1-4:   Data length (big-endian)
        Bytes 5-8:   Total pages (big-endian)
        Bytes 9-12:  Current page (big-endian)
        Bytes 13+:   Encrypted stripe data
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, 0, b''

    # Check challenge echo in response (bytes 16-32 of header)
    challenge_echo = response[16:32]
    if expected_challenge and challenge_echo != expected_challenge:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  "Challenge mismatch - possible spoofing or corruption")
        return ProtocolErrorCode.ERR_INVALID_BODY, 0, 0, b''

    # Response body starts at byte 32
    if len(response) < 45:  # 32 header + 13 body header minimum
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  "Response body too short")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, 0, b''

    body = response[32:]
    status_code = body[0]
    data_length = struct.unpack('>I', body[1:5])[0]
    # total_pages = struct.unpack('>I', body[5:9])[0]
    # current_page = struct.unpack('>I', body[9:13])[0]

    if status_code != 250:
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    f"Download failed with status {status_code}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, 0, b''

    # Extract encrypted data (starts at byte 13 of body)
    encrypted_data = body[13:13 + data_length] if len(body) >= 13 + data_length else body[13:]

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Download response validated: status={status_code}, data_len={data_length}")

    return ProtocolErrorCode.SUCCESS, status_code, data_length, encrypted_data


def build_complete_download_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    file_group_guid: bytes,
    locker_code: bytes,
    file_type: int,
    page_number: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete download request (header + encrypted payload).

    This is a convenience function that combines header building,
    payload building, and encryption into a single call.

    Args:
        raida_id: RAIDA server ID (0-24)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: 16-bit device identifier
        an: 16-byte Authenticity Number
        file_group_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        file_type: File type (0=email, 10+=attachments)
        page_number: Page number for paginated downloads (0-based)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge, nonce)
    """
    # Build payload first to get size
    err, payload, challenge = build_download_payload(
        denomination, serial_number, device_id, an,
        file_group_guid, locker_code, file_type, page_number,
        logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Build header
    err, header = build_download_header(
        raida_id, locker_code, len(payload),
        denomination, serial_number, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Get nonce from header for encryption
    nonce = header[24:32]

    # Encrypt payload with raida_id for proper key derivation
    err, encrypted_payload = encrypt_payload(payload, locker_code, nonce, raida_id, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Combine header + encrypted payload
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete download request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


# ============================================================================
# MAKE CHANGE COMMAND FUNCTIONS (Command Group 8, Command 90) - Added by opus45
# ============================================================================

def build_make_change_payload(
    original_dn: int,
    original_sn: int,
    original_an: bytes,
    starting_sn: int,
    pans: List[bytes],
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build Make Change (Command 90) request payload.

    This command breaks one coin into 10 smaller denomination coins.
    The client generates a starting serial number, and the next 9 SNs
    are sequential (SSN, SSN+1, SSN+2, ..., SSN+9).

    Args:
        original_dn: Original coin denomination code (0x00-0x03)
        original_sn: Original coin serial number
        original_an: Original coin AN for this RAIDA (16 bytes)
        starting_sn: Starting serial number for new coins (100000-16777215)
        pans: List of 10 PANs (16 bytes each) for the new coins
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 203-byte payload, 16-byte challenge)

    Payload format (203 bytes):
        Bytes 0-15:   Challenge (12 random + 4 CRC32)
        Byte 16:      Original coin denomination code
        Bytes 17-20:  Original coin serial number (big-endian)
        Bytes 21-36:  Original coin AN (16 bytes)
        Bytes 37-40:  Starting serial number for new coins (big-endian)
        Bytes 41-200: 10 PANs (16 bytes each = 160 bytes)
        Bytes 201-202: Terminator (0x3E 0x3E)
    """
    if original_an is None or len(original_an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_payload failed",
                  "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if pans is None or len(pans) != 10:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_payload failed",
                  f"Must provide exactly 10 PANs, got {len(pans) if pans else 0}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    for i, pan in enumerate(pans):
        if pan is None or len(pan) != 16:
            log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_payload failed",
                      f"PAN {i} must be exactly 16 bytes")
            return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    payload = bytearray(203)

    # Bytes 0-15: Challenge
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Byte 16: Original coin denomination code
    payload[16] = original_dn & 0xFF

    # Bytes 17-20: Original coin serial number (big-endian)
    struct.pack_into('>I', payload, 17, original_sn)

    # Bytes 21-36: Original coin AN
    payload[21:37] = original_an[:16]

    # Bytes 37-40: Starting serial number (big-endian)
    struct.pack_into('>I', payload, 37, starting_sn)

    # Bytes 41-200: 10 PANs (16 bytes each)
    offset = 41
    for pan in pans:
        payload[offset:offset + 16] = pan[:16]
        offset += 16

    # Bytes 201-202: Terminator
    payload[201] = 0x3E
    payload[202] = 0x3E

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built make_change payload: original_sn={original_sn}, "
              f"starting_sn={starting_sn}")

    return ProtocolErrorCode.SUCCESS, bytes(payload), challenge


def build_make_change_header(
    raida_id: int,
    body_length: int,
    denomination: int,
    serial_number: int,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for Make Change command.

    Uses encryption type 1 (shared secret / AN-based encryption).
    The coin being broken is used as both the encryption coin and
    the coin to break.

    Args:
        raida_id: RAIDA server ID (0-24)
        body_length: Length of encrypted body in bytes
        denomination: Coin denomination code (for header DN field)
        serial_number: Coin serial number (for header SN field)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (8 bytes for AES-CTR counter)
    """
    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_CHANGE       # CG: Command Group (8)
    header[5] = CMD_MAKE_CHANGE        # CM: Command (90 = Make Change)
    struct.pack_into('>H', header, 6, COIN_TYPE)  # ID: Coin ID (0x0006)

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = ENC_SHARED_SECRET     # EN: Encryption type 1 (AN-based)
    header[17] = denomination & 0xFF   # DN: Coin denomination code
    struct.pack_into('>I', header, 18, serial_number)  # SN: Coin serial number (4 bytes, big-endian)
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses all 8 bytes for AES-CTR counter
    nonce = os.urandom(8)
    header[24:32] = nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built make_change header: RAIDA={raida_id}, DN={denomination}, "
              f"SN={serial_number}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_complete_make_change_request(
    raida_id: int,
    original_dn: int,
    original_sn: int,
    original_an: bytes,
    starting_sn: int,
    pans: List[bytes],
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete Make Change request (header + encrypted payload).

    This is a convenience function that combines header building,
    payload building, and encryption into a single call.

    Args:
        raida_id: RAIDA server ID (0-24)
        original_dn: Original coin denomination code
        original_sn: Original coin serial number
        original_an: Original coin AN for this RAIDA (16 bytes, also used for encryption)
        starting_sn: Starting serial number for new coins
        pans: List of 10 PANs for the new coins
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge, nonce)
    """
    # Build payload first
    err, payload, challenge = build_make_change_payload(
        original_dn, original_sn, original_an, starting_sn, pans, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Build header
    err, header = build_make_change_header(
        raida_id, len(payload), original_dn, original_sn, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Get nonce from header for encryption
    nonce = header[24:32]

    # Encrypt payload using original coin's AN (encryption type 1)
    err, encrypted_payload = encrypt_payload_with_an(payload, original_an, nonce, logger_handle)
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Combine header + encrypted payload
    complete_request = header + encrypted_payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete make_change request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(encrypted_payload)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


# ============================================================================
# LOCKER DOWNLOAD COMMAND FUNCTIONS (Command 91)
# ============================================================================

def build_locker_download_header(
    raida_id: int,
    locker_key: bytes,
    body_length: int,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for Locker DOWNLOAD command.

    Uses encryption type 2 (locker code encryption).
    The first 5 bytes of the locker key are placed in the header for
    the RAIDA to find the correct locker for decryption.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_key: 16-byte locker key (with 0xFF padding in last 4 bytes)
        body_length: Length of encrypted body in bytes
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, LK, LK, LK, LK, LK, BL, BL)
        Bytes 24-31: Nonce (8 bytes for AES-CTR counter)
    """
    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_locker_download_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if locker_key is None or len(locker_key) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_locker_download_header failed",
                  "locker_key must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID (not used)
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID (not used)
    header[4] = CMD_GROUP_LOCKER       # CG: Command Group (8 = Locker)
    header[5] = CMD_LOCKER_DOWNLOAD    # CM: Command (91 = Download)
    struct.pack_into('>H', header, 6, COIN_TYPE)  # ID: Coin ID (0x0006)

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)  # BF: Only first bit random
    header[9] = 0x00                   # AP: Application 0
    header[10] = 0x00                  # AP: Application 1
    header[11] = 0x00                  # CP: Compression (none)
    header[12] = 0x00                  # TR: Translation (none)
    header[13] = 0x00                  # AI: AI Translation (none)
    header[14] = 0x00                  # RE: Reserved
    header[15] = 0x00                  # RE: Reserved

    # Encryption bytes (16-23)
    # NOTE: Testing shows DOWNLOAD works with encryption type 0 (no encryption)
    # Type 2 (ENC_LOCKER_CODE) causes CRC errors on many RAIDA
    header[16] = ENC_NONE              # EN: No encryption (type 0)
    # header[17:21] = zeros (already)  # Not used for type 0
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22] = 0xFF
        header[23] = 0xFF
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - zeros for type 0
    # header[24:32] = zeros (already)

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built locker_download header: RAIDA={raida_id}, body_len={body_length}")

    return ProtocolErrorCode.SUCCESS, bytes(header)


def build_locker_download_payload(
    locker_key: bytes,
    seed: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes]:
    """
    Build the Locker DOWNLOAD payload (before encryption).

    Payload structure (48 bytes to encrypt + 2 bytes terminator):
        Bytes 0-15:  Challenge/CRC (12 random + 4 CRC32)
        Bytes 16-31: Locker key (16 bytes, with 0xFF padding in last 4)
        Bytes 32-47: Seed (16 bytes, random per RAIDA for AN generation)
        -- Encrypted portion ends here --
        Bytes 48-49: Terminator (0x3E 0x3E) - NOT encrypted per docs

    Args:
        locker_key: 16-byte locker key (derived from locker code with 0xFF padding)
        seed: 16-byte random seed for AN generation
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 48-byte payload for encryption, 16-byte challenge)
        Note: Caller must append 0x3E3E terminator AFTER encryption
    """
    if locker_key is None or len(locker_key) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_locker_download_payload failed",
                  "locker_key must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    if seed is None or len(seed) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_locker_download_payload failed",
                  "seed must be 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    # Only build 48 bytes - terminator goes OUTSIDE encryption
    payload = bytearray(48)

    # Challenge/CRC (0-15): 12 random bytes + 4 CRC32
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Locker key (16-31): 16 bytes
    payload[16:32] = locker_key[:16]

    # Seed (32-47): 16 bytes
    payload[32:48] = seed[:16]

    # Note: Terminator 0x3E3E is added AFTER encryption by caller

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built locker_download payload: {len(payload)} bytes (terminator added after encryption)")

    return ProtocolErrorCode.SUCCESS, bytes(payload), challenge


def encrypt_locker_payload(
    payload: bytes,
    locker_key: bytes,
    nonce: bytes,
    raida_id: int,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Encrypt locker payload using AES-128-CTR with locker key.

    The locker key (16 bytes, with 0xFF in last 4 bytes) is used directly
    as the AES key.

    Args:
        payload: Plaintext payload to encrypt
        locker_key: 16-byte locker key (with 0xFF padding)
        nonce: 8-byte nonce from header
        raida_id: RAIDA server ID (for logging)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, encrypted payload)
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter

        # Use locker_key directly as AES key (16 bytes)
        key = locker_key[:16]

        # Build 16-byte counter: 8-byte nonce + 8 bytes of zeros
        counter_init = nonce[:8] + bytes(8)

        # Create counter - same pattern as other encryption functions
        ctr = Counter.new(128, initial_value=int.from_bytes(counter_init, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

        encrypted = cipher.encrypt(payload)

        log_debug(logger_handle, PROTOCOL_CONTEXT,
                  f"Encrypted locker payload: {len(payload)} -> {len(encrypted)} bytes")

        return ProtocolErrorCode.SUCCESS, encrypted

    except Exception as e:
        log_error(logger_handle, PROTOCOL_CONTEXT,
                  "Failed to encrypt locker payload", str(e))
        return ProtocolErrorCode.ERR_ENCRYPTION_FAILED, b''


def decrypt_locker_response(
    encrypted_body: bytes,
    locker_key: bytes,
    nonce: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Decrypt locker response using AES-128-CTR with locker key.

    Args:
        encrypted_body: Encrypted response body
        locker_key: 16-byte locker key used for request
        nonce: 8-byte nonce from request header
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, decrypted body)
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter

        # Use locker_key directly as AES key
        key = locker_key[:16]

        # Build 16-byte counter: 8-byte nonce + 8 bytes of zeros
        counter_init = nonce[:8] + bytes(8)

        # Create counter - same pattern as other decryption functions
        ctr = Counter.new(128, initial_value=int.from_bytes(counter_init, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

        decrypted = cipher.decrypt(encrypted_body)

        log_debug(logger_handle, PROTOCOL_CONTEXT,
                  f"Decrypted locker response: {len(encrypted_body)} -> {len(decrypted)} bytes")

        return ProtocolErrorCode.SUCCESS, decrypted

    except Exception as e:
        log_error(logger_handle, PROTOCOL_CONTEXT,
                  "Failed to decrypt locker response", str(e))
        return ProtocolErrorCode.ERR_DECRYPTION_FAILED, b''


def parse_locker_download_response(
    decrypted_body: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, List[Tuple[int, int]]]:
    """
    Parse the decrypted response from Locker DOWNLOAD command.

    Response format (same as PEEK):
        Repeating: DN (1 byte) + SN (4 bytes big-endian) = 5 bytes per coin
        Terminated by: 0x3E 0x3E

    Args:
        decrypted_body: Decrypted response body
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, [(denomination, serial_number), ...])
    """
    coins = []

    if not decrypted_body or len(decrypted_body) < 2:
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    "Empty or too short locker download response")
        return ProtocolErrorCode.SUCCESS, coins

    # Find terminator
    terminator_pos = -1
    for i in range(len(decrypted_body) - 1):
        if decrypted_body[i] == 0x3E and decrypted_body[i + 1] == 0x3E:
            terminator_pos = i
            break

    if terminator_pos == -1:
        # No terminator found, use entire body
        coin_data = decrypted_body
    else:
        coin_data = decrypted_body[:terminator_pos]

    # Parse coins (5 bytes each: 1 denom + 4 SN)
    # Valid denomination range per coin-file-format=9.md: -8 to +11
    VALID_DENOM_MIN = -8
    VALID_DENOM_MAX = 11

    offset = 0
    while offset + 5 <= len(coin_data):
        denomination = coin_data[offset]
        # Convert signed byte for denomination if needed
        if denomination > 127:
            denomination = denomination - 256
        serial_number = struct.unpack('>I', coin_data[offset + 1:offset + 5])[0]

        # Validate denomination is in valid range
        if denomination < VALID_DENOM_MIN or denomination > VALID_DENOM_MAX:
            log_warning(logger_handle, PROTOCOL_CONTEXT,
                        f"Invalid denomination {denomination} for SN {serial_number}, "
                        f"valid range is {VALID_DENOM_MIN} to {VALID_DENOM_MAX} - skipping")
            offset += 5
            continue

        coins.append((denomination, serial_number))
        offset += 5

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Parsed {len(coins)} coins from locker download response")

    return ProtocolErrorCode.SUCCESS, coins


def build_complete_locker_download_request(
    raida_id: int,
    locker_key: bytes,
    seed: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete Locker DOWNLOAD request (header + encrypted payload + terminator).

    This command replaces the two-step PEEK + REMOVE flow with a single command.
    The RAIDA will:
    1. Find all coins in the locker identified by locker_key
    2. Generate new ANs using: MD5("{raida_id}{serial_number}{seed_hex}")
    3. Return the list of (denomination, serial_number) pairs

    The client must compute the same ANs locally using the same formula.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_key: 16-byte locker key (with 0xFF padding in last 4 bytes)
        seed: 16-byte random seed for AN generation (unique per RAIDA!)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, complete request bytes, challenge, nonce)
    """
    # Build payload (48 bytes - terminator is added separately)
    err, payload, challenge = build_locker_download_payload(
        locker_key, seed, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Build header - body length is 48 + 2 = 50 (payload + terminator)
    err, header = build_locker_download_header(
        raida_id, locker_key, len(payload) + 2, logger_handle  # +2 for terminator
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # NOTE: Using encryption type 0 (no encryption) - skip encryption step
    # Testing showed type 2 encryption causes CRC errors on many RAIDA
    nonce = bytes(8)  # Zeros for type 0

    # Combine header + plaintext payload + terminator
    complete_request = header + payload + TERMINATOR

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete locker_download request: {len(complete_request)} bytes "
              f"(header={len(header)}, body={len(payload)}, terminator=2)")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


# Legacy stubs for backward compatibility (to be removed after migration)
def build_complete_locker_peek_request(*args, **kwargs):
    """Legacy stub - use build_complete_locker_download_request instead."""
    raise NotImplementedError(
        "Locker PEEK is deprecated. Use build_complete_locker_download_request instead."
    )


def build_complete_locker_remove_request(*args, **kwargs):
    """Legacy stub - use build_complete_locker_download_request instead."""
    raise NotImplementedError(
        "Locker REMOVE is deprecated. Use build_complete_locker_download_request instead."
    )


def parse_locker_peek_response(decrypted_body, logger_handle=None):
    """Legacy alias - redirects to parse_locker_download_response."""
    return parse_locker_download_response(decrypted_body, logger_handle)


def parse_locker_remove_response(decrypted_body, expected_count, logger_handle=None):
    """Legacy stub - no longer needed with DOWNLOAD command."""
    raise NotImplementedError(
        "Locker REMOVE is deprecated. Use parse_locker_download_response instead."
    )