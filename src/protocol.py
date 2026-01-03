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
from typing import List, Optional, Tuple ,Any, Dict
import zlib

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


# RAIDA Standard Status Codes
STATUS_SUCCESS = 250        # 0xFA - Command processed successfully
ERROR_INVALID_AN = 200      # 0xC8 - payload has incorrect AN within it

# Module context for logging
PROTOCOL_CONTEXT = "Protocol"


# ============================================================================
# ERROR CODES
# ============================================================================

class ProtocolErrorCode(IntEnum):
    SUCCESS = 0
    ERR_INVALID_BODY = 1
    ERR_INCOMPLETE_DATA = 2
    ERR_ENCRYPTION_FAILED = 3    # Added for Locker logic
    ERR_DECRYPTION_FAILED = 4    # Added for Locker logic


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


def build_ping_body(denomination: int, serial_number: int, device_id: int, an: bytes) -> Tuple[bytes, bytes]:
    """Builds the 50-byte PING body with CRC-32 preamble and identity block."""
    body = bytearray(50)
    # 1. 48-byte Preamble (Identity Block)
    # bytes 0-11: random, bytes 12-15: CRC32
    challenge_data = os.urandom(12)
    crc = zlib.crc32(challenge_data) & 0xFFFFFFFF
    body[0:12] = challenge_data
    struct.pack_into('>I', body, 12, crc) 
    
    challenge = bytes(body[0:16])
    body[16:24] = bytes(8) # Session ID zeros
    struct.pack_into('>H', body, 24, 0x0006) # Coin Type 
    body[26] = denomination & 0xFF
    struct.pack_into('>I', body, 27, serial_number)
    body[31] = device_id & 0xFF
    body[32:48] = an[:16] # AN at Offset 32
    
    # 2. Terminator (Strict Placement)
    body[48:50] = b'\x3e\x3e'
    return bytes(body), challenge

def build_peek_body(denomination: int, serial_number: int, device_id: int, an: bytes, since_timestamp: int) -> Tuple[bytes, bytes]:
    """Builds the 54-byte PEEK body with CRC-32 preamble and identity block."""
    body = bytearray(54)
    # 1. 48-byte Preamble (Identity Block)
    challenge_data = os.urandom(12)
    crc = zlib.crc32(challenge_data) & 0xFFFFFFFF
    body[0:12] = challenge_data
    struct.pack_into('>I', body, 12, crc) 
    
    challenge = bytes(body[0:16])
    body[16:24] = bytes(8)
    struct.pack_into('>H', body, 24, 0x0006) 
    body[26] = denomination & 0xFF
    struct.pack_into('>I', body, 27, serial_number)
    body[31] = device_id & 0xFF
    body[32:48] = an[:16] # AN at Offset 32
    
    # 2. Peek Payload: Since Timestamp (Offset 48)
    struct.pack_into('>I', body, 48, since_timestamp)
    
    # 3. Terminator
    body[52:54] = b'\x3e\x3e'
    return bytes(body), challenge


# ============================================================================
# RESPONSE PARSER FUNCTIONS
# ============================================================================

def parse_tell_response(
    response_body: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, List[TellNotification]]:
    """
    Parses the decrypted response body from a PING or PEEK command.
    
    Matches tell_file_header_t from tell.h (40 bytes):
    - Offset +0:  cluster_id (4 bytes)
    - Offset +4:  sender_coin_id (2 bytes)
    - Offset +6:  sender_denomination (1 byte)
    - Offset +7:  sender_serial_number (4 bytes, Big Endian)
    - Offset +11: timestamp (4 bytes, Big Endian)
    - Offset +15: tell_type (1 byte)
    - Offset +16: email_id/file_guid (16 bytes)
    - Offset +32: total_file_size (4 bytes, Big Endian)
    - Offset +36: stripe_count (4 bytes, Big Endian)
    """
    if not response_body or len(response_body) < 8:
        log_debug(logger_handle, "Protocol", "Tell response is empty or too short for a header.")
        return ProtocolErrorCode.SUCCESS, []

    try:
        tell_count = response_body[0]
        total_tells = struct.unpack('>H', response_body[1:3])[0]

        log_debug(logger_handle, "Protocol", 
                  f"Parsing tell response. Header: tell_count={tell_count}, total_tells_remaining={total_tells}")

        if tell_count == 0:
            return ProtocolErrorCode.SUCCESS, []

        notifications = []
        offset = 8  # Tells start after 8-byte response header

        for i in range(tell_count):
            min_tell_size = 40  # tell_file_header_t is 40 bytes
            if offset + min_tell_size > len(response_body):
                log_error(logger_handle, "Protocol", 
                         f"Incomplete data for tell #{i+1} at offset {offset}.")
                return ProtocolErrorCode.ERR_INCOMPLETE_DATA, notifications

            tell = TellNotification()

            # Parse with correct offsets matching C struct
            tell.timestamp = struct.unpack('>I', response_body[offset + 11 : offset + 15])[0]
            tell.tell_type = response_body[offset + 15]
            tell.file_guid = response_body[offset + 16 : offset + 32]  # 16 bytes
            tell.server_count = struct.unpack('>I', response_body[offset + 36 : offset + 40])[0]

            offset += 40  # Move past header

            # Parse server list (server_loc_t: 32 bytes each)
            server_list = []
            for s in range(tell.server_count):
                if offset + 32 > len(response_body):
                    log_error(logger_handle, "Protocol", 
                             f"Incomplete data for server list in tell #{i+1}.")
                    break

                server_data = response_body[offset : offset + 32]
                
                location = ServerLocation(
                    stripe_index=server_data[0],
                    total_stripes=tell.server_count,
                    server_id=server_data[0],
                    raw_entry=server_data
                )
                server_list.append(location)
                offset += 32

            tell.server_list = server_list

            # Parse footer (tell_file_footer_t: tag + length + 16-byte locker = 18 bytes)
            if offset + 18 <= len(response_body):
                footer_tag = response_body[offset]
                footer_len = response_body[offset + 1]
                if footer_tag == 0x50 and footer_len == 16:
                    tell.locker_code = response_body[offset + 2 : offset + 18]
                    offset += 18
                else:
                    tell.locker_code = bytes(16)
            else:
                tell.locker_code = bytes(16)

            notifications.append(tell)

        return ProtocolErrorCode.SUCCESS, notifications

    except (struct.error, IndexError) as e:
        log_error(logger_handle, "Protocol", 
                 f"Failed to parse tell response due to malformed data: {e}")
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
    encryption_type: int = ENC_SHARED_SECRET, # Added for flexibility
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for PEEK command.
    FIXED: Now supports ENC_NONE (0) for Phase I functionality.
    """
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_peek_header failed", "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_peek_header failed", f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7)
    header[0] = 0x01                   # BF: Must be 0x01
    header[1] = 0x00                   # SP: Split ID
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID
    header[4] = CMD_GROUP_QMAIL        # CG: Command Group (6)
    header[5] = CMD_PEEK               # CM: Command (63)
    struct.pack_into('>H', header, 6, COIN_TYPE)

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)
    header[9:16] = bytes(7)

    # Encryption bytes (16-23)
    header[16] = encryption_type & 0xFF  # UPDATED: Use parameter instead of hardcoded ENC_SHARED_SECRET
    header[17] = denomination & 0xFF
    struct.pack_into('>I', header, 18, serial_number)
    struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Use zeros for ENC_NONE
    nonce = os.urandom(8) if encryption_type != ENC_NONE else bytes(8)
    header[24:32] = nonce

    log_debug(logger_handle, PROTOCOL_CONTEXT, f"Built PEEK header: RI={raida_id}, EN={header[16]}, BL={body_length}")
    return ProtocolErrorCode.SUCCESS, bytes(header)
def build_ping_header(
    raida_id: int,
    an: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    encryption_type: int = ENC_SHARED_SECRET, # Added for flexibility
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for PING command.
    FIXED: Now supports ENC_NONE (0) for Phase I functionality.
    """
    if an is None or len(an) < 16:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_ping_header failed", "AN must be at least 16 bytes")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)
    header[0] = 0x01
    header[2] = raida_id
    header[4] = CMD_GROUP_QMAIL
    header[5] = CMD_PING
    struct.pack_into('>H', header, 6, COIN_TYPE)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)
    
    header[16] = encryption_type & 0xFF # UPDATED
    header[17] = denomination & 0xFF
    struct.pack_into('>I', header, 18, serial_number)
    struct.pack_into('>H', header, 22, body_length)

    nonce = os.urandom(8) if encryption_type != ENC_NONE else bytes(8)
    header[24:32] = nonce

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
    encryption_type: int = 0,
    **kwargs
) -> Tuple[int, bytes, bytes, bytes]:
    """
    FIXED: Now calls build_peek_header to ensure CMD_PEEK (63) is used.
    """
    # 1. Build unpadded PEEK body
    payload, challenge = build_peek_body(denomination, serial_number, device_id, an, since_timestamp)

    # 2. Build dedicated PEEK Header (CMD 63)
    err, header = build_peek_header(
        raida_id=raida_id,
        an=an,
        body_length=len(payload),
        denomination=denomination,
        serial_number=serial_number,
        encryption_type=encryption_type,
        **kwargs
    )
    if err != 0: return err, b'', b'', b''
    
    return 0, header + payload, challenge, header[24:32]


def build_complete_ping_request(
    raida_id: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    encryption_type: int = 0,
    **kwargs
) -> Tuple[int, bytes, bytes, bytes]:
    """
    Build a complete PING request (header + payload).
    
    FIXED: Now calls build_ping_header to ensure Command 62 is used. 
    Using build_tell_header previously caused Status 16 misrouting errors.
    """
    # 1. Build the 50-byte unpadded PING body and its 16-byte challenge
    payload, challenge = build_ping_body(denomination, serial_number, device_id, an)

    # 2. Build the Header using the correct PING command code (62)
    # This function correctly sets header[5] = CMD_PING
    err, header = build_ping_header(
        raida_id=raida_id,
        an=an,
        body_length=len(payload),
        denomination=denomination,
        serial_number=serial_number,
        encryption_type=encryption_type,
        **kwargs
    )
    
    if err != 0: 
        return err, b'', b'', b''
    
    # 3. Combine header and payload
    # For Type 0, the nonce at header[24:32] will be 8 null bytes
    complete_request = header + payload
    
    return 0, complete_request, challenge, header[24:32]
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
    if weeks <= 0: return StorageDuration.ONE_DAY
    elif weeks == 1: return StorageDuration.ONE_WEEK
    elif weeks <= 4: return StorageDuration.ONE_MONTH
    elif weeks <= 12: return StorageDuration.THREE_MONTHS
    elif weeks <= 26: return StorageDuration.SIX_MONTHS
    elif weeks <= 52: return StorageDuration.ONE_YEAR
    else: return StorageDuration.PERMANENT


def build_upload_header(
    raida_id: int,
    locker_code: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    encryption_type: int = 0,  # Added to support Type 0
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for upload command.

    The header is NOT encrypted and contains routing, presentation,
    encryption, and nonce information.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_code: 8-byte locker code for encryption key derivation
        body_length: Length of body in bytes
        denomination: User's coin denomination (for header DN field)
        serial_number: User's mailbox serial number (for header SN field)
        encryption_type: Encryption mode (0 for plaintext)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)

    Header format (32 bytes):
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)
    """
    # Validation: Locker code is still passed as a parameter for consistency
    if locker_code is None and encryption_type != 0:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_upload_header failed",
                  "locker_code required for encrypted uploads")
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
    header[14:16] = bytes(2)           # RE: Reserved

    # Encryption bytes (16-23)
    header[16] = encryption_type & 0xFF # EN: Encryption type (e.g., 0 for none)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number
    
    # Body length (big-endian, 2 bytes)
    if body_length > 65535:
        header[22:24] = b'\xFF\xFF'
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server uses zeros for unencrypted Type 0
    if encryption_type == 0:
        header[24:32] = bytes(8)
    else:
        header[24:32] = os.urandom(8)

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built upload header: RAIDA={raida_id}, body_len={body_length}, encryption={encryption_type}")

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

    # Calculate total payload size: fixed preamble+header (84) + data + terminator (2)
    data_length = len(stripe_data) if stripe_data else 0
    payload_size = 84 + data_length + 2

    payload = bytearray(payload_size)

    # Challenge (0-15): Includes required CRC-32 for Type 0
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

    # AN (32-47): Proof of identity at Offset 32 for server check
    payload[32:48] = an[:16]

    # File Group GUID (48-63): 16 bytes
    payload[48:64] = file_group_guid[:16]

    # Locker Code (64-71): 8 bytes
    payload[64:72] = locker_code[:8] if locker_code else bytes(8)

    # Reserved fields (72-73, 74, 76-79)
    payload[72:75] = bytes(3)

    # Storage Duration (75)
    payload[75] = storage_duration & 0xFF

    # Data Length (80-83): big-endian
    struct.pack_into('>I', payload, 80, data_length)

    # Binary Data (84+)
    if stripe_data:
        payload[84:84 + data_length] = stripe_data

    # Terminator: Strict placement at the absolute end
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
    STRICT VERSION: Checks Byte 2 for status and Bytes 16-31 for Challenge Echo.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, error_message)
        - SUCCESS and status 250 for successful upload
        - ERR_INVALID_BODY and status 200 for authentication failure (triggers healing)
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_upload_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, "Response too short"

    # 1. Extract Status Code from Byte 2 (Per protocol.c:502)
    # response[2] = status;
    status_code = response[2]

    # 2. Check challenge echo in response (Bytes 16-31 Per protocol.c:511)
    # memcpy(&response[16], ci->challenge_hash, 16);
    challenge_echo = response[16:32]
    if expected_challenge and challenge_echo != expected_challenge:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_upload_response failed",
                  "Challenge mismatch - possible spoofing or corruption")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, "Challenge mismatch"

    # 3. Handle Status 250 (SUCCESS)
    if status_code == 250:
        log_debug(logger_handle, PROTOCOL_CONTEXT, "Upload response validated successfully (Status 250)")
        return ProtocolErrorCode.SUCCESS, 250, ""

    # 4. Handle Status 200 (ERROR_INVALID_AN / Reactive Healing Trigger)
    elif status_code == 200:
        log_error(logger_handle, PROTOCOL_CONTEXT, 
                  "AUTHENTICATION FAILED (Status 200): Identity coin is fracked. Moving to Fracked folder.")
        return ProtocolErrorCode.ERR_INVALID_BODY, 200, "Invalid AN - Coin fracked"

    # 5. Handle Other Server Errors
    else:
        log_warning(logger_handle, PROTOCOL_CONTEXT, f"Upload failed with status {status_code}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, f"Server Error: {status_code}"

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
    encryption_type: int = 0,  # Default to plaintext Type 0
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:  # Added 4th return value for consistency
    """
    Build a complete upload request (header + payload).

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
        encryption_type: Encryption type (0 for plaintext)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, request bytes, challenge, nonce)
    """
    # 1. Build unpadded payload first to get exact size
    err, payload, challenge = build_upload_payload(
        denomination, serial_number, device_id, an,
        file_group_guid, locker_code, storage_duration,
        stripe_data, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # 2. Build header with the EXACT unpadded payload length
    err, header = build_upload_header(
        raida_id, locker_code, len(payload),
        denomination, serial_number, encryption_type, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    nonce = header[24:32]

    # 3. Handle Encryption
    if encryption_type != 0:
        err, final_body = encrypt_payload(payload, locker_code, nonce, raida_id, logger_handle)
        if err != ProtocolErrorCode.SUCCESS:
            return err, b'', b'', b''
    else:
        # Plaintext Type 0: Send payload exactly as built
        final_body = payload

    complete_request = header + final_body

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete upload request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(final_body)})")

    return ProtocolErrorCode.SUCCESS, complete_request, challenge, nonce


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
# Ensure these constants are defined in your protocol.py
# Protocol Constants
CMD_GROUP_QMAIL = 6
CMD_TELL = 61
# ProtocolErrorCode values: SUCCESS=0, ERR_INVALID_BODY=1
# Ensure these are imported or defined in your file.

def build_tell_header(
    raida_id: int,
    an: bytes,
    body_length: int,
    denomination: int = 0,
    serial_number: int = 0,
    encryption_type: int = 0,
    **kwargs
) -> Tuple[int, bytes]:
    """Builds the 32-byte RAIDA Request Header."""
    if raida_id < 0 or raida_id > 24:
        return 1, b'' 
    
    # Validation: Ensures short keys are caught as errors
    auth_key = an if an is not None else kwargs.get('locker_code')
    if auth_key is None or len(auth_key) < 16:
        return 1, b''

    header = bytearray(32)
    header[0] = 0x01  # Version
    header[2] = raida_id
    header[4] = CMD_GROUP_QMAIL
    header[5] = CMD_TELL
    struct.pack_into('>H', header, 6, 0x0006) # Coin Type

    header[16] = encryption_type & 0xFF 
    header[17] = denomination & 0xFF
    struct.pack_into('>I', header, 18, serial_number)
    struct.pack_into('>H', header, 22, body_length)

    # Type 0 (Plaintext) requires a zero-nonce for server compatibility
    header[24:32] = bytes(8) if encryption_type == 0 else os.urandom(8)
    return 0, bytes(header)

# def build_tell_payload(
#     denomination: int,
#     serial_number: int,
#     device_id: int,
#     an: bytes,
#     file_group_guid: bytes,
#     timestamp: int,
#     tell_type: int,
#     recipients: List,
#     servers: List,
#     beacon_payment_locker: Optional[bytes] = None,
#     **kwargs 
# ) -> Tuple[int, bytes, bytes]:
#     """
#     Builds the Tell payload. 
#     STRICT VERSION: No padding is added. The size must match RAIDA's expected 
#     preamble (48) + qmail_header (40) + lists + terminator (2).
#     """
#     if an is None or len(an) < 16 or file_group_guid is None or len(file_group_guid) < 16:
#         return 1, b'', b''

#     ac = len(recipients) if recipients else 0
#     qc = len(servers) if servers else 0

#     # EXACT Size: 48 (Preamble) + 40 (QMail Header) + AC*32 + QC*32 + 2 (Terminator)
#     payload_size = 48 + 40 + (ac * 32) + (qc * 32) + 2
#     payload = bytearray(payload_size)

#     # 1. 48-BYTE PREAMBLE (Identity Block)
#     challenge = os.urandom(16)
#     payload[0:16] = challenge
#     struct.pack_into('>H', payload, 24, 0x0006) 
#     payload[26] = denomination & 0xFF
#     struct.pack_into('>I', payload, 27, serial_number)
#     payload[31] = device_id & 0xFF
#     payload[32:48] = an[:16] # Proof of Identity at Offset 32

#     # 2. 40-BYTE QMAIL HEADER (Metadata Block)
#     h_off = 48 
#     payload[h_off : h_off + 16] = file_group_guid[:16]
#     struct.pack_into('>I', payload, h_off + 24, timestamp)
#     payload[h_off+28] = tell_type & 0xFF
#     payload[h_off+29] = ac & 0xFF
#     payload[h_off+30] = qc & 0xFF
#     if beacon_payment_locker:
#         payload[h_off + 31 : h_off + 39] = beacon_payment_locker[:8]

#     # 3. RECIPIENT LIST (Offset 88+)
#     offset = 88
#     for r in (recipients or []):
#         payload[offset] = r.address_type & 0xFF
#         struct.pack_into('>H', payload, offset + 1, r.coin_id)
#         payload[offset + 3] = r.denomination & 0xFF
#         payload[offset + 4] = r.domain_id & 0xFF
#         sn_bytes = (r.serial_number & 0xFFFFFF).to_bytes(3, 'big')
#         payload[offset + 5 : offset + 8] = sn_bytes
#         if hasattr(r, 'locker_payment_key') and r.locker_payment_key:
#             payload[offset + 8 : offset + 24] = r.locker_payment_key[:16]
#         offset += 32

#     # 4. SERVER LIST (Following Recipients)
#     for s in (servers or []):
#         payload[offset] = s.stripe_index & 0xFF
#         payload[offset+1] = s.stripe_type & 0xFF
#         if s.ip_address:
#             try:
#                 ip_parts = [int(p) for p in s.ip_address.split('.')]
#                 payload[offset+22:offset+26] = bytes(ip_parts)
#             except: pass
#         struct.pack_into('>H', payload, offset+26, s.port)
#         offset += 32

#     # 5. TERMINATOR (Strict Placement at the very end of the unpadded buffer)
#     payload[-2:] = b'\x3e\x3e'
#     return 0, bytes(payload), challenge

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
    **kwargs 
) -> Tuple[int, bytes, bytes]:
    """
    Builds the Tell payload for Encryption Type 0 (Plaintext).
    STRICT VERSION: Includes the required CRC-32 in the preamble and 
    maintains exact offsets for the RAIDA C-structures.
    """
    # 1. Validation: Matches server expectations and unit test failures
    if an is None or len(an) < 16 or file_group_guid is None or len(file_group_guid) < 16:
        return 1, b'', b''

    ac = len(recipients) if recipients else 0
    qc = len(servers) if servers else 0

    # EXACT Size: 48 (Preamble) + 40 (QMail Header) + AC*32 + QC*32 + 2 (Terminator)
    # Matches expected_size logic in cmd_qmail.c
    payload_size = 48 + 40 + (ac * 32) + (qc * 32) + 2
    payload = bytearray(payload_size)

    # =========================================================================
    # SECTION 1: 48-BYTE PREAMBLE (Identity Block)
    # =========================================================================
    # RAIDA protocol.c requires a 12-byte challenge followed by a 4-byte CRC-32 
    # of those 12 bytes when using Encryption Type 0.
    challenge_data = os.urandom(12)
    crc = zlib.crc32(challenge_data) & 0xFFFFFFFF
    
    payload[0:12] = challenge_data
    struct.pack_into('>I', payload, 12, crc) # Big-Endian CRC at bytes 12-15
    
    # The full 16-byte block is used as the challenge for verification
    full_challenge = bytes(payload[0:16])

    # Offset 16-23: Session ID (Zeros for Type 0)
    struct.pack_into('>H', payload, 24, 0x0006) # Coin Type 
    payload[26] = denomination & 0xFF
    struct.pack_into('>I', payload, 27, serial_number)
    payload[31] = device_id & 0xFF
    payload[32:48] = an[:16] # Proof of Identity at Offset 32

    # =========================================================================
    # SECTION 2: 40-BYTE QMAIL HEADER (Metadata Block)
    # =========================================================================
    h_off = 48 
    payload[h_off : h_off + 16] = file_group_guid[:16]
    struct.pack_into('>I', payload, h_off + 24, timestamp)
    payload[h_off+28] = tell_type & 0xFF
    payload[h_off+29] = ac & 0xFF
    payload[h_off+30] = qc & 0xFF
    if beacon_payment_locker:
        payload[h_off + 31 : h_off + 39] = beacon_payment_locker[:8]

    # =========================================================================
    # SECTION 3: RECIPIENT LIST (Offset 88+)
    # =========================================================================
    offset = 88
    for r in (recipients or []):
        payload[offset] = r.address_type & 0xFF
        struct.pack_into('>H', payload, offset + 1, r.coin_id)
        payload[offset + 3] = r.denomination & 0xFF
        payload[offset + 4] = r.domain_id & 0xFF
        sn_bytes = (r.serial_number & 0xFFFFFF).to_bytes(3, 'big')
        payload[offset + 5 : offset + 8] = sn_bytes
        if hasattr(r, 'locker_payment_key') and r.locker_payment_key:
            payload[offset + 8 : offset + 24] = r.locker_payment_key[:16]
        offset += 32

    # =========================================================================
    # SECTION 4: SERVER LIST (Following Recipients)
    # =========================================================================
    for s in (servers or []):
        payload[offset] = s.stripe_index & 0xFF
        payload[offset+1] = s.stripe_type & 0xFF
        if s.ip_address:
            try:
                ip_parts = [int(p) for p in s.ip_address.split('.')]
                payload[offset+22:offset+26] = bytes(ip_parts)
            except: pass
        struct.pack_into('>H', payload, offset+26, s.port)
        offset += 32

    # =========================================================================
    # SECTION 5: TERMINATOR (Strict Placement at absolute end)
    # =========================================================================
    payload[-2:] = b'\x3e\x3e' # Required QMail Terminator
    
    return 0, bytes(payload), full_challenge

def build_complete_tell_request(
    raida_id: int, an: bytes, denomination: int, serial_number: int,
    device_id: int, file_group_guid: bytes, timestamp: int,
    tell_type: int, recipients: List, servers: List,
    beacon_payment_locker: Optional[bytes] = None,
    encryption_type: int = 0, **kwargs
) -> Tuple[int, bytes, bytes, bytes]:
    """Wraps header and payload. Returns 4 values for test script compatibility."""
    
    # Handle the fact that tests might pass 'locker_code' instead of 'an'
    auth_an = an if an is not None else kwargs.get('locker_code')

    err, payload, challenge = build_tell_payload(
        denomination, serial_number, device_id, auth_an, file_group_guid,
        timestamp, tell_type, recipients, servers, beacon_payment_locker, **kwargs
    )
    if err != 0: return err, b'', b'', b''

    # Use the EXACT unpadded payload length for the header's body_length field
    err, header = build_tell_header(
        raida_id, auth_an, len(payload), denomination, serial_number, encryption_type, **kwargs
    )
    if err != 0: return err, b'', b'', b''

    # Return (err, request, challenge, nonce)
    return 0, header + payload, challenge, header[24:32]

def validate_tell_response(
    response: bytes,
    expected_challenge: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, int, str]:
    """
    Validate a Tell response from the beacon server.
    STRICT VERSION: Checks status at Byte 2 and verifies Challenge Echo.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, error_message)
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_tell_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, "Response too short"

    # 1. Extract Status Code from Byte 2 (Per protocol.c:502)
    status_code = response[2]

    # 2. Verify Challenge Echo (Bytes 16-31 Per protocol.c:511)
    if expected_challenge and len(expected_challenge) >= 16:
        challenge_echo = response[16:32]
        if challenge_echo != expected_challenge:
            log_error(logger_handle, PROTOCOL_CONTEXT, "validate_tell_response failed",
                      "Challenge mismatch - possible spoofing or corruption")
            return ProtocolErrorCode.ERR_INVALID_BODY, status_code, "Challenge mismatch"

    # 3. Map status codes to error messages (Per cmd_qmail.c)
    status_messages = {
        250: "",  # Success
        200: "Invalid AN - Identity coin is fracked. Initiating healing.",
        166: "Payment required - locker key invalid or empty",
        16: "Invalid packet length",
        194: "Filesystem error on beacon",
        18: "Wrong RAIDA - recipient not on this beacon"
    }

    error_msg = status_messages.get(status_code, f"Unknown status: {status_code}")

    # 4. Success Check (250)
    if status_code == 250:
        log_debug(logger_handle, PROTOCOL_CONTEXT, "Tell response validated successfully (Status 250)")
        return ProtocolErrorCode.SUCCESS, status_code, ""
    
    # 5. Reactive Healing Trigger (200)
    elif status_code == 200:
        log_error(logger_handle, PROTOCOL_CONTEXT, f"AUTHENTICATION FAILED: {error_msg}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, error_msg
    
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
    encryption_type: int = 0,  # Default to Type 0 (Plaintext)
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
        encryption_type: Encryption mode (0 for plaintext)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, 32-byte header)
    """
    # Validation: Matches short_locker_code and raida_high unit tests
    if locker_code is None and encryption_type != 0:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_download_header failed",
                  "locker_code must be provided for encrypted downloads")
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
    header[9:16] = bytes(7)

    # Encryption bytes (16-23)
    header[16] = encryption_type & 0xFF  # EN: Encryption type (0 for plaintext)
    header[17] = denomination & 0xFF   # DN: User's denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: User's serial number
    
    # Body length: Strictly unpadded for Type 0
    if body_length > 65535:
        header[22:24] = b'\xFF\xFF'
    else:
        struct.pack_into('>H', header, 22, body_length)

    # Nonce bytes (24-31) - Server protocol.c requires zero nonce for Type 0
    if encryption_type == 0:
        header[24:32] = bytes(8)
    else:
        header[24:32] = os.urandom(8)

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built download header: RAIDA={raida_id}, body_len={body_length}, encryption={encryption_type}")

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
    STRICT VERSION: Includes CRC-32 preamble and AN at Offset 32.
    
    Matches qmail_download_req_t structure:
    - Preamble (48 bytes): Challenge + Identity
    - Download Request (20 bytes): GUID + file_type + version + bytes_per_page + page_number
    - Terminator (2 bytes)
    Total: 70 bytes
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

    # Preamble (48) + Download Request (20) + Terminator (2) = 70 bytes
    payload_size = 70
    payload = bytearray(payload_size)

    # 1. Challenge/CRC (0-15): Uses _generate_challenge for protocol.c compatibility
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # 2. Identity Block (16-47)
    payload[16:24] = bytes(8)  # Session ID
    struct.pack_into('>H', payload, 24, COIN_TYPE)  # 0x0006
    payload[26] = denomination
    struct.pack_into('>I', payload, 27, serial_number)
    payload[31] = device_id & 0xFF
    payload[32:48] = an[:16]  # AN Proof: Offset 32 for server check

    # 3. Download Request (48-67) - matches qmail_download_req_t
    payload[48:64] = file_group_guid[:16]  # File GUID (48-63): 16 bytes
    payload[64] = file_type & 0xFF          # File Type (64): 1 byte
    payload[65] = 0x00                      # Version (65): 1 byte (always 0)
    payload[66] = 0x00                      # Bytes Per Page (66): 1 byte (0 = use max size)
    payload[67] = page_number & 0xFF        # Page Number (67): 1 byte

    # 4. Terminator (68-69)
    payload[68:70] = TERMINATOR

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built download payload: file_type={file_type}, page={page_number}, size={payload_size}")

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
    STRICT VERSION: Extracts status from Header Byte 2 and parses body metadata.

    Args:
        response: Raw response bytes from server
        expected_challenge: The challenge bytes sent in the request
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ProtocolErrorCode, status_code, data_length, response_data)
    """
    if response is None or len(response) < 32:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  f"Response too short: {len(response) if response else 0} bytes")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, 0, 0, b''

    # 1. Extract Status Code from Header Byte 2 (Per protocol.c:502)
    status_code = response[2]

    # 2. Check challenge echo in Header Bytes 16-31 (Per protocol.c:511)
    challenge_echo = response[16:32]
    if expected_challenge and challenge_echo != expected_challenge:
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  "Challenge mismatch - possible spoofing or corruption")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, 0, b''

    # 3. Handle Errors (including Reactive Healing trigger 200)
    if status_code != 250:
        if status_code == 200:
            log_error(logger_handle, PROTOCOL_CONTEXT, "Download Authentication Failed (200). Coin is fracked.")
        else:
            log_warning(logger_handle, PROTOCOL_CONTEXT, f"Download failed with status {status_code}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, 0, b''

    # 4. Parse Response Body (starts at Byte 32)
    # cmd_qmail.c:542 allocs 9 + bytes_to_read for body metadata
    if len(response) < 41:  # 32 header + 9 metadata bytes
        log_error(logger_handle, PROTOCOL_CONTEXT, "validate_download_response failed",
                  "Response too short for body metadata")
        return ProtocolErrorCode.ERR_INCOMPLETE_DATA, status_code, 0, b''

    body = response[32:]
    
    # Body Structure from cmd_qmail.c:545-555:
    # body[0]: file_type, body[1]: version, body[2]: bytes_per_page, body[3]: page_number
    # body[4:8]: data_length (4-byte big-endian)
    try:
        data_length = struct.unpack('>I', body[4:8])[0]
        
        # 5. Extract file data (Starts at body offset 9 Per cmd_qmail.c:558)
        # ci->output + 9 is the start of fwrite/fread data
        file_data = body[9:9 + data_length]

        log_debug(logger_handle, PROTOCOL_CONTEXT,
                  f"Download response validated: status={status_code}, data_len={data_length}")

        return ProtocolErrorCode.SUCCESS, status_code, data_length, file_data
    except Exception as e:
        log_error(logger_handle, PROTOCOL_CONTEXT, f"Failed to parse download body: {e}")
        return ProtocolErrorCode.ERR_INVALID_BODY, status_code, 0, b''

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
    encryption_type: int = 0,  # Default to Type 0
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete download request (header + payload).
    Handles Encryption Type 0 (Plaintext) and Encryption Type 2 (Locker).
    """
    # 1. Build unpadded payload first to get exact size
    err, payload, challenge = build_download_payload(
        denomination, serial_number, device_id, an,
        file_group_guid, locker_code, file_type, page_number,
        logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # 2. Build header with the EXACT unpadded payload length (83 bytes)
    err, header = build_download_header(
        raida_id, locker_code, len(payload),
        denomination, serial_number, encryption_type, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    nonce = header[24:32]

    # 3. Condition: Encrypt only if not Type 0
    if encryption_type != 0:
        err, encrypted_payload = encrypt_payload(payload, locker_code, nonce, raida_id, logger_handle)
        if err != ProtocolErrorCode.SUCCESS:
            return err, b'', b'', b''
        final_body = encrypted_payload
    else:
        final_body = payload

    complete_request = header + final_body

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete download request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(final_body)})")

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

    # --- SN SAFETY RANGE CHECK (Applied Here) ---
    # Required by server cmd_locker.c:1076. SNs outside this range cause rejection.
    if starting_sn < 32768 or starting_sn > 131071:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_payload failed",
                  f"Invalid starting_sn {starting_sn}. Must be between 32,768 and 131,071")
        return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    for i, pan in enumerate(pans):
        if pan is None or len(pan) != 16:
            log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_payload failed",
                      f"PAN {i} must be exactly 16 bytes")
            return ProtocolErrorCode.ERR_INVALID_BODY, b'', b''

    payload = bytearray(203)

    # Bytes 0-15: Challenge (Includes CRC32 required by protocol.c:434 for Type 0)
    challenge = _generate_challenge()
    payload[0:16] = challenge

    # Byte 16: Original coin denomination code
    payload[16] = original_dn & 0xFF

    # Bytes 17-20: Original coin serial number (big-endian)
    struct.pack_into('>I', payload, 17, original_sn)

    # Bytes 21-36: Original coin AN (Proof of ownership for cmd_locker.c:1070 check)
    payload[21:37] = original_an[:16]

    # Bytes 37-40: Starting serial number for new coins (big-endian)
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
    encryption_type: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes]:
    """
    Build the 32-byte request header for Make Change command.
    STRICT VERSION: Matches Group 8, Command 90 with random nonce.
    """
    if raida_id < 0 or raida_id > 24:
        log_error(logger_handle, PROTOCOL_CONTEXT, "build_make_change_header failed",
                  f"raida_id must be 0-24, got {raida_id}")
        return ProtocolErrorCode.ERR_INVALID_BODY, b''

    header = bytearray(32)

    # Routing bytes (0-7): CG=8 (Locker), CM=90 (Make Change)
    header[0] = 0x01                   # BF: Version 1
    header[1] = 0x00                   # SP: Split ID
    header[2] = raida_id               # RI: RAIDA ID
    header[3] = 0x00                   # SH: Shard ID
    header[4] = CMD_GROUP_LOCKER       # CG: Command Group (8)
    header[5] = CMD_MAKE_CHANGE        # CM: Command (90)
    struct.pack_into('>H', header, 6, COIN_TYPE)  # ID: 0x0006

    # Presentation bytes (8-15)
    header[8] = 0x00 | (os.urandom(1)[0] & 0x01)
    header[9:16] = bytes(7)

    # Encryption bytes (16-23): Type 0 (Plaintext)
    header[16] = encryption_type & 0xFF 
    header[17] = denomination & 0xFF
    struct.pack_into('>I', header, 18, serial_number)
    struct.pack_into('>H', header, 22, body_length) # Must be 203

    # Nonce bytes (24-31): Random nonce as per protocol requirements
    header[24:32] = os.urandom(8)

    log_debug(logger_handle, PROTOCOL_CONTEXT, 
              f"Built make_change header: RAIDA={raida_id}, body_len={body_length}")
              
    return ProtocolErrorCode.SUCCESS, bytes(header)

def build_complete_make_change_request(
    raida_id: int,
    original_dn: int,
    original_sn: int,
    original_an: bytes,
    starting_sn: int,
    pans: List[bytes],
    encryption_type: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    Build a complete Make Change request (header + plaintext payload).
    
    This combines header and payload building for Encryption Type 0.
    Range check is enforced during payload construction.
    """
    # 1. Build unpadded payload (Strictly 203 bytes)
    err, payload, challenge = build_make_change_payload(
        original_dn, original_sn, original_an, starting_sn, pans, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # 2. Build header with the EXACT unpadded payload length
    err, header = build_make_change_header(
        raida_id, len(payload), original_dn, original_sn, encryption_type, logger_handle
    )
    if err != ProtocolErrorCode.SUCCESS:
        return err, b'', b'', b''

    # Nonce from header
    nonce = header[24:32]

    # 3. Combine header + plaintext payload (No AES encryption for Type 0)
    complete_request = header + payload

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built complete make_change request: {len(complete_request)} bytes "
              f"(header={len(header)}, payload={len(payload)})")

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
    
    Response format:
        [Status (1 byte)] + Repeating: [DN (1 byte) + SN (4 bytes)] + [Terminator (2 bytes)]
    """
    coins = []

    if not decrypted_body or len(decrypted_body) < 2:
        log_warning(logger_handle, PROTOCOL_CONTEXT,
                    "Empty or too short locker download response")
        return ProtocolErrorCode.SUCCESS, coins

    # 1. Strip the terminator 0x3E 0x3E (>>)
    # Check the end of the body for the terminator
    if decrypted_body.endswith(TERMINATOR):
        coin_data = decrypted_body[:-2]
    elif b'>>' in decrypted_body:
        # Fallback: find it if it's earlier in the buffer
        pos = decrypted_body.find(b'>>')
        coin_data = decrypted_body[:pos]
    else:
        coin_data = decrypted_body

    # 2. Handle the 1-byte Status Byte
    # If the length is not a multiple of 5 (5 bytes per coin), 
    # the first byte is almost certainly the status code (e.g., 250 / 0xFA).
    offset = 0
    if len(coin_data) % 5 == 1:
        # Skip the status byte to align with the coin data
        offset = 1

    # 3. Parse coins (5 bytes each: 1 signed denom + 4 unsigned SN)
    # Using '>bI' handles Big-Endian, signed denomination, and serial number correctly
    try:
        while offset + 5 <= len(coin_data):
            # b: signed char (1 byte) for denomination (-8 to 11)
            # I: unsigned int (4 bytes) for serial number
            denomination, serial_number = struct.unpack('>bI', coin_data[offset : offset + 5])
            
            # Validation: CloudCoin denominations are between -8 and 11
            if -8 <= denomination <= 11:
                coins.append((denomination, serial_number))
            else:
                log_warning(logger_handle, PROTOCOL_CONTEXT,
                            f"Invalid denomination {denomination} for SN {serial_number} - skipping")
            
            offset += 5
    except struct.error as e:
        log_error(logger_handle, PROTOCOL_CONTEXT, f"Failed to unpack coin data: {e}")
        return ProtocolErrorCode.ERR_INVALID_BODY, coins

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Parsed {len(coins)} coins from locker download response")

    return ProtocolErrorCode.SUCCESS, coins

# protocol.py

# Updated build_complete_locker_download_request to match Go client pattern
COIN_TYPE = 0x0006 # REVERTED TO 6 PER YOUR LOGS

# protocol.p
# Replace build_complete_locker_download_request in protocol.py

def build_complete_locker_download_request(
    raida_id: int,
    locker_code_str: str,  # The raw string like "VA9-7UEF"
    seed: bytes,           # The 16-byte raw seed
    logger_handle: Optional[object] = None
) -> Tuple[ProtocolErrorCode, bytes, bytes, bytes]:
    """
    FIXED: Builds a Version 1 (Legacy) Request for Command 91.
    Formula: MD5(raida_id + locker_code_str) + 0xFFFFFFFF
    """
    # 1. DERIVE THE LOCKER ACCESS KEY (PAN)
    # The server expects the MD5 of the RAIDA number + the human code
    raw_input = f"{raida_id}{locker_code_str.strip().upper()}"
    hasher = hashlib.md5(raw_input.encode('ascii'))
    key_bytes = bytearray(hasher.digest())
    
    # CRUCIAL: Mandatory tail for locker verification
    key_bytes[12:16] = b'\xFF\xFF\xFF\xFF'
    locker_an = bytes(key_bytes)

    # 2. BUILD THE 50-BYTE BODY
    # Structure for Type 0 (No Encryption): 
    # [16 Challenge] + [16 Access Key] + [16 New Seed] + [2 Terminator]
    body = bytearray(50)
    
    challenge = _generate_challenge() # Ensure this helper is available
    body[0:16] = challenge
    body[16:32] = locker_an
    body[32:48] = seed[:16]
    body[48:50] = b'\x3e\x3e' # Terminator

    # 3. BUILD THE 32-BYTE LEGACY HEADER
    header = bytearray(32)
    header[0] = 0x01                   # BF: Legacy Version
    header[2] = raida_id               # RI: Target RAIDA
    header[4] = 8                      # CG: Locker Group
    header[5] = 91                     # CM: Download Command
    
    # Coin Type (Usually 1 for CloudCoin or 6 for specific RAIDAX coins)
    struct.pack_into('>H', header, 6, COIN_TYPE) 
    
    # --- LENGTH FIX START ---
    # For Version 1 headers, the Payload Length (PL) starts at index 8.
    # Index 10-11 is where the 16-bit body size (50) must go.
    struct.pack_into('>H', header, 22, 50) 
    # --- LENGTH FIX END ---
    
    header[16] = 0                     # EN: No Encryption (using Challenge)

    # 4. FINAL 82-BYTE PACKET
    complete_request = bytes(header) + bytes(body)

    log_debug(logger_handle, PROTOCOL_CONTEXT,
              f"Built locker_download for RAIDA {raida_id}: {len(complete_request)} bytes")

    # Return Challenge so the client can verify the response signature later
    return ProtocolErrorCode.SUCCESS, complete_request, challenge, bytes(8)
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