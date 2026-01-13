"""
heal_protocol.py - RAIDA Binary Protocol for Healing Operations

This module contains all protocol-level constants, message building,
and response parsing for RAIDA healing commands.

Author: Claude Opus 4.5
Version: 1.0.0
Date: 2025-12-26

Protocol Overview:
    - Request Header: 32 bytes
    - Response Header: 32 bytes (first 12 bytes contain status info)
    - Body: Variable length, terminated with 0x3E3E

Commands (Group 2 - Healing):
    - Get Ticket (40): Get proof of authentication from RAIDA
    - Get Ticket By Sum (41): Get ticket using checksum
    - Get Encryption Ticket (44): Get ticket for encryption setup
    - Fix Encryption (45): Establish shared secret with RAIDA
    - Validate Ticket (50): Verify a ticket is valid
    - Find (60): Check if AN or PAN is current (limbo resolution)
    - Fix (80): Repair password using tickets from other RAIDA
"""

import os
import struct
import zlib
import hashlib
from typing import List, Tuple, Dict, Optional, Any
from enum import IntEnum
from dataclasses import dataclass, field


# ============================================================================
# PROTOCOL CONSTANTS
# ============================================================================

# RAIDA Network Configuration
RAIDA_COUNT = 25
RAIDA_TIMEOUT = 300  # seconds per request

# Coin identifier for CloudCoin
COIN_ID = 0x0006

# Request/Response terminators
TERMINATOR = bytes([0x3E, 0x3E])

# Header sizes
REQUEST_HEADER_SIZE = 32
RESPONSE_HEADER_SIZE = 32

# AN (Authenticity Number) size
AN_SIZE = 16

# Command Groups
CMD_GROUP_HEALING = 2
# For Get Encryption Ticket (44) and Fix Encryption (45)
CMD_GROUP_KEY_EXCHANGE = 4

# Command Codes (Healing Group)
CMD_GET_TICKET = 40
CMD_GET_TICKET_BY_SUM = 41
CMD_GET_ENCRYPTION_TICKET = 44
CMD_FIX_ENCRYPTION = 45
CMD_VALIDATE_TICKET = 50
CMD_FIND = 60
CMD_FIX = 80

# Encryption Types
ENC_NONE = 0
ENC_SHARED_SECRET = 1
ENC_LOCKER_CODE = 2
ENC_RAIDA_KEY = 3
ENC_256_SHARED = 4
ENC_256_TWO_SECRETS = 5

# POWN Status Nibble Values (4 bits per RAIDA in file header)
# See docs/Heal/Specifications/pown-string-codes.md for full specification
# Only 0xF (fail) indicates certainty of lost shared secret
# 0xA (pass) indicates shared secret exists
# Other values are uncertain/maybes
POWN_UNTRIED = 0x0     # 'u' - Untried/Unknown, RAIDA not contacted
POWN_PASS = 0xA        # 'p' - Pass/Authentic, has shared secret
POWN_BROKE_ENC = 0xB   # 'b' - Broke Encryption Key, encryption key not authentic
POWN_NO_REPLY = 0xC    # 'n' - No Reply/Clock Timeout, RAIDA did not respond
POWN_DROPPED = 0xD     # 'd' - Dropped, network error unrelated to RAIDA
POWN_ERROR = 0xE       # 'e' - Error, RAIDA responded with error
POWN_FAIL = 0xF        # 'f' - Failed/Counterfeit, definitely lost shared secret

# Response Status Codes
STATUS_ALL_PASS = 241
STATUS_ALL_FAIL = 242
STATUS_MIXED = 243
STATUS_SUCCESS = 250
STATUS_FIND_NEITHER = 208
STATUS_FIND_ALL_AN = 209
STATUS_FIND_ALL_PAN = 210
STATUS_FIND_MIXED = 211

# Quorum requirements
QUORUM_REQUIRED = 13  # Need 13 of 25 to pass


# ============================================================================
# ERROR CODES
# ============================================================================

class HealErrorCode(IntEnum):
    """Error codes for healing operations."""
    SUCCESS = 0
    ERR_FILE_NOT_FOUND = 1
    ERR_INVALID_FILE = 2
    ERR_IO_ERROR = 3
    ERR_NETWORK_ERROR = 4
    ERR_NO_TICKETS = 5
    ERR_QUORUM_FAILED = 6
    ERR_ENCRYPTION_FAILED = 7
    ERR_INVALID_COIN = 8
    ERR_NO_FRACKED_COINS = 9
    ERR_ALL_RAIDA_DOWN = 10
    ERR_INSUFFICIENT_HELPERS = 11
    ERR_TICKET_FAILED = 12
    ERR_FIX_REJECTED = 13
    ERR_HASH_MISMATCH = 14
    ERR_INTERNAL = 99


class FixEncryptionError(IntEnum):
    """Specific error categories for Fix Encryption operations."""
    NONE = 0
    NO_COINS_AVAILABLE = 1
    INSUFFICIENT_HELPERS = 2
    TICKET_FAILED = 3
    FIX_FAILED = 4
    NETWORK_TIMEOUT = 5
    PROTOCOL_ERROR = 6
    RAIDA_OFFLINE = 7
    PARTIAL_SUCCESS = 8
    HASH_MISMATCH = 9


# ============================================================================
# DATA STRUCTURES FOR FIX ENCRYPTION
# ============================================================================

@dataclass
class EncryptedKeyPart:
    """
    Represents an encrypted key part from a helper RAIDA.

    Used in the Fix Encryption protocol where helper RAIDA encrypt
    portions of the AN that needs to be synced to a broken RAIDA.

    Attributes:
        helper_raida_id: RAIDA that provided this encrypted key part
        denomination: Denomination of the coin being fixed
        serial_number: Serial number of the coin being fixed
        encrypted_key_part: 16-byte encrypted key part
        original_key_part: Original 8-byte key part (for verification)
        nonce: 8-byte nonce used in the Get Encryption Ticket request
               (spec suggests CMD 45 should use matching nonces)
        split_id: 0 for first half of AN (bytes 0-7), 1 for second half (bytes 8-15)
    """
    helper_raida_id: int = 0
    denomination: int = 0
    serial_number: int = 0
    encrypted_key_part: bytes = field(default_factory=lambda: bytes(16))
    original_key_part: bytes = field(default_factory=lambda: bytes(8))
    nonce: bytes = field(default_factory=lambda: bytes(8))
    # 0 for key_part_0 (AN bytes 0-7), 1 for key_part_1 (AN bytes 8-15)
    split_id: int = 0


@dataclass
class FixEncryptionResult:
    """
    Result of a fix encryption operation.

    Provides detailed information about what succeeded and failed
    during the fix encryption process.

    Attributes:
        success: True if all targeted RAIDA were fixed
        fixed_raida: List of RAIDA IDs that were successfully fixed
        failed_raida: List of RAIDA IDs that failed to fix
        errors: Per-RAIDA error details
        total_broken: Number of RAIDA that were broken before fix
        total_fixed: Number of RAIDA successfully fixed
    """
    success: bool = False
    fixed_raida: List[int] = field(default_factory=list)
    failed_raida: List[int] = field(default_factory=list)
    errors: Dict[int, FixEncryptionError] = field(default_factory=dict)
    total_broken: int = 0
    total_fixed: int = 0


# Response status for Fix Encryption
STATUS_KEY_ACCEPTED = 0x01
STATUS_KEY_REJECTED = 0x00


# ============================================================================
# POWN ENCODING/DECODING
# ============================================================================

def pown_char_to_nibble(char: str) -> int:
    """
    Convert POWN character to 4-bit nibble value.

    Args:
        char: Single character ('p', 'f', 'u', 'e', 'n', 'b', 'd')

    Returns:
        Nibble value (0x0-0xF)
    """
    char = char.lower()
    if char == 'u':
        return POWN_UNTRIED   # 0x0
    elif char == 'p':
        return POWN_PASS      # 0xA
    elif char == 'b':
        return POWN_BROKE_ENC  # 0xB
    elif char == 'n':
        return POWN_NO_REPLY  # 0xC
    elif char == 'd':
        return POWN_DROPPED   # 0xD
    elif char == 'e':
        return POWN_ERROR     # 0xE
    elif char == 'f':
        return POWN_FAIL      # 0xF
    else:
        return POWN_UNTRIED


def nibble_to_pown_char(nibble: int) -> str:
    """
    Convert 4-bit nibble to POWN character.

    Only 0xF (fail) indicates certainty of lost shared secret.
    0xA (pass) indicates shared secret exists.
    Other values are uncertain/maybes.

    Args:
        nibble: Nibble value (0x0-0xF)

    Returns:
        POWN character
    """
    if nibble == POWN_UNTRIED:    # 0x0
        return 'u'
    elif nibble == POWN_PASS:     # 0xA
        return 'p'
    elif nibble == POWN_BROKE_ENC:  # 0xB
        return 'b'
    elif nibble == POWN_NO_REPLY:   # 0xC
        return 'n'
    elif nibble == POWN_DROPPED:    # 0xD
        return 'd'
    elif nibble == POWN_ERROR:      # 0xE
        return 'e'
    elif nibble == POWN_FAIL:       # 0xF
        return 'f'
    else:
        return 'u'  # Unknown/uncertain


def encode_pown_bytes(pown_string: str) -> bytes:
    """
    Encode 25-character POWN string to 13 bytes.

    Each nibble (4 bits) represents one RAIDA result.
    Last nibble is padding marker (0x9).

    Args:
        pown_string: 25-character POWN string

    Returns:
        13-byte encoded POWN
    """
    if len(pown_string) < RAIDA_COUNT:
        pown_string = pown_string.ljust(RAIDA_COUNT, 'u')

    pown_bytes = bytearray(13)

    for i in range(RAIDA_COUNT):
        nibble = pown_char_to_nibble(pown_string[i])
        byte_idx = i // 2
        if i % 2 == 0:
            pown_bytes[byte_idx] = (nibble << 4) & 0xF0
        else:
            pown_bytes[byte_idx] |= nibble & 0x0F

    # Set padding marker in last byte's low nibble
    pown_bytes[12] = (pown_bytes[12] & 0xF0) | 0x09

    return bytes(pown_bytes)


def decode_pown_bytes(pown_bytes: bytes) -> str:
    """
    Decode 13 bytes to 25-character POWN string.

    Args:
        pown_bytes: 13-byte encoded POWN

    Returns:
        25-character POWN string
    """
    if len(pown_bytes) < 13:
        return 'u' * RAIDA_COUNT

    pown_chars = []
    for i in range(RAIDA_COUNT):
        byte_idx = i // 2
        if i % 2 == 0:
            nibble = (pown_bytes[byte_idx] >> 4) & 0x0F
        else:
            nibble = pown_bytes[byte_idx] & 0x0F
        pown_chars.append(nibble_to_pown_char(nibble))

    return ''.join(pown_chars)


# ============================================================================
# CHALLENGE AND PASSWORD GENERATION
# ============================================================================

def generate_challenge() -> bytes:
    """
    Generate 16-byte challenge: 12 random bytes + 4-byte CRC32.

    Returns:
        16-byte challenge for request body
    """
    random_bytes = os.urandom(12)
    crc32_val = zlib.crc32(random_bytes) & 0xFFFFFFFF
    crc32_bytes = struct.pack('>I', crc32_val)
    return random_bytes + crc32_bytes


def generate_pg() -> bytes:
    """
    Generate 16-byte PG (Password Generator) for Fix command.

    The PG is used along with denomination and serial number
    to generate the new AN via MD5 hash.

    Returns:
        16-byte random PG value
    """
    return os.urandom(16)


def calculate_new_an(raida_id: int, denomination: int, serial_number: int, pg: bytes) -> bytes:
    """
    Calculate new AN using MD5 hash.

    Formula: MD5(raida_id + denomination + serial_number + pg)

    Args:
        raida_id: RAIDA server ID (0-24)
        denomination: Coin denomination code
        serial_number: Coin serial number
        pg: 16-byte password generator

    Returns:
        16-byte new AN
    """
    data = bytearray(22)
    data[0] = raida_id
    data[1] = denomination & 0xFF
    struct.pack_into('>I', data, 2, serial_number)
    data[6:22] = pg

    return hashlib.md5(bytes(data)).digest()


# ============================================================================
# REQUEST HEADER BUILDING
# ============================================================================

def build_request_header(
    raida_id: int,
    command_group: int,
    command_code: int,
    body_length: int,
    encryption_type: int = ENC_NONE,
    denomination: int = 0,
    serial_number: int = 0
) -> bytes:
    """
    Build a 32-byte request header.

    Header format:
        Bytes 0-7:   Routing (BF, SP, RI, SH, CG, CM, ID, ID)
        Bytes 8-15:  Presentation (BF, AP, AP, CP, TR, AI, RE, RE)
        Bytes 16-23: Encryption (EN, DN, SN, SN, SN, SN, BL, BL)
        Bytes 24-31: Nonce (NO, NO, NO, NO, NO, NO, EC, EC)

    Args:
        raida_id: Target RAIDA server ID (0-24)
        command_group: Command group code
        command_code: Command code
        body_length: Length of request body in bytes
        encryption_type: Encryption type (0 = none)
        denomination: For encryption key reference
        serial_number: For encryption key reference

    Returns:
        32-byte request header
    """
    header = bytearray(REQUEST_HEADER_SIZE)

    # Routing bytes (0-7)
    header[0] = 0x01                    # BF: Bitfield
    header[1] = 0x00                    # SP: Split ID
    header[2] = raida_id                # RI: RAIDA ID
    header[3] = 0x00                    # SH: Shard ID
    header[4] = command_group           # CG: Command Group
    header[5] = command_code            # CM: Command Code
    struct.pack_into('>H', header, 6, COIN_ID)  # ID: Coin ID

    # Presentation bytes (8-15)
    header[8] = os.urandom(1)[0] & 0x01  # BF with random bit
    # Bytes 9-15 are zeros (reserved)

    # Encryption bytes (16-23)
    header[16] = encryption_type        # EN: Encryption type
    header[17] = denomination & 0xFF    # DN: Denomination
    struct.pack_into('>I', header, 18, serial_number)  # SN: Serial number
    struct.pack_into('>H', header, 22, body_length)    # BL: Body length

    # Nonce bytes (24-31)
    nonce = os.urandom(8)
    header[24:32] = nonce

    return bytes(header)


# ============================================================================
# RESPONSE HEADER PARSING
# ============================================================================

def parse_response_header(response: bytes) -> Tuple[int, int, int, int]:
    """
    Parse a 32-byte response header.

    Response header format:
        Byte 0: RAIDA ID
        Byte 1: Shard ID
        Byte 2: Status code
        Byte 3: Command group echo
        Bytes 4-5: UDP frame (not used in TCP)
        Bytes 6-7: Echo
        Byte 8: Reserved
        Bytes 9-11: Body size (24-bit big-endian)

    Args:
        response: Raw response bytes (at least 32 bytes)

    Returns:
        Tuple of (raida_id, status, command_group, body_size)
    """
    if len(response) < RESPONSE_HEADER_SIZE:
        return -1, 0, 0, 0

    raida_id = response[0]
    status = response[2]
    command_group = response[3]
    body_size = (response[9] << 16) | (response[10] << 8) | response[11]

    return raida_id, status, command_group, body_size


# ============================================================================
# REQUEST BODY BUILDERS
# ============================================================================

def build_get_ticket_body(coins: List[Tuple[int, int, bytes]]) -> bytes:
    """
    Build request body for Get-Ticket command (multiple coins).

    Body format:
        - 16 bytes: Challenge
        - For each coin:
            - 1 byte: Denomination
            - 4 bytes: Serial number (big-endian)
            - 16 bytes: AN
        - 2 bytes: Terminator

    Args:
        coins: List of tuples, where each tuple is (denomination, serial_number, an)

    Returns:
        Request body bytes
    """
    body = bytearray()
    body.extend(generate_challenge())
    for denomination, serial_number, an in coins:
        body.append(denomination & 0xFF)
        body.extend(struct.pack('>I', serial_number))
        body.extend(an[:AN_SIZE])
    body.extend(TERMINATOR)
    return bytes(body)


def build_get_ticket_body_single(denomination: int, serial_number: int, an: bytes) -> bytes:
    """
    Deprecated: Use build_get_ticket_body for multiple coins.
    Build request body for Get-Ticket command (single coin).

    Body format:
        - 16 bytes: Challenge
        - 1 byte: Denomination
        - 4 bytes: Serial number (big-endian)
        - 16 bytes: AN
        - 2 bytes: Terminator

    Args:
        denomination: Coin denomination
        serial_number: Coin serial number
        an: 16-byte Authenticity Number

    Returns:
        Request body bytes (39 bytes)
    """
    return build_get_ticket_body([(denomination, serial_number, an)])


def build_find_body(coins: List[Tuple[int, int, bytes, bytes]]) -> bytes:
    """
    Build request body for Find command (multiple coins, limbo resolution).

    Body format:
        - 16 bytes: Challenge
        - For each coin:
            - 1 byte: Denomination
            - 4 bytes: Serial number (big-endian)
            - 16 bytes: AN (current)
            - 16 bytes: PAN (proposed)
        - 2 bytes: Terminator

    Args:
        coins: List of tuples, where each tuple is (denomination, serial_number, an, pan)

    Returns:
        Request body bytes
    """
    body = bytearray()
    body.extend(generate_challenge())
    for denomination, serial_number, an, pan in coins:
        body.append(denomination & 0xFF)
        body.extend(struct.pack('>I', serial_number))
        body.extend(an[:AN_SIZE])
        body.extend(pan[:AN_SIZE])
    body.extend(TERMINATOR)
    return bytes(body)


def build_find_body_single(denomination: int, serial_number: int, an: bytes, pan: bytes) -> bytes:
    """
    Deprecated: Use build_find_body for multiple coins.
    Build request body for Find command (single coin, limbo resolution).

    Body format:
        - 16 bytes: Challenge
        - 1 byte: Denomination
        - 4 bytes: Serial number (big-endian)
        - 16 bytes: AN (current)
        - 16 bytes: PAN (proposed)
        - 2 bytes: Terminator

    Args:
        denomination: Coin denomination
        serial_number: Coin serial number
        an: 16-byte current AN
        pan: 16-byte proposed AN

    Returns:
        Request body bytes (55 bytes)
    """
    return build_find_body([(denomination, serial_number, an, pan)])


def build_fix_body(
    coins: List[Tuple[int, int]],
    pg: bytes,
    tickets: List[int]
) -> bytes:
    """
    Build request body for Fix command (multiple coins).

    Body format:
        - 16 bytes: Challenge
        - For each coin:
            - 1 byte: Denomination
            - 4 bytes: Serial number (big-endian)
        - 16 bytes: PG (Password Generator)
        - 100 bytes: 25 tickets (4 bytes each, big-endian)
        - 2 bytes: Terminator

    Args:
        coins: List of tuples, where each tuple is (denomination, serial_number)
        pg: 16-byte password generator
        tickets: List of 25 ticket IDs (0 if no ticket from that RAIDA)

    Returns:
        Request body bytes
    """
    body = bytearray()
    body.extend(generate_challenge())
    for denomination, serial_number in coins:
        body.append(denomination & 0xFF)
        body.extend(struct.pack('>I', serial_number))

    body.extend(pg[:16])

    # 25 tickets (4 bytes each)
    for i in range(RAIDA_COUNT):
        if i < len(tickets):
            body.extend(struct.pack('>I', tickets[i]))
        else:
            body.extend(bytes(4))

    body.extend(TERMINATOR)
    return bytes(body)


def build_fix_body_single(
    denomination: int,
    serial_number: int,
    pg: bytes,
    tickets: List[int]
) -> bytes:
    """
    Deprecated: Use build_fix_body for multiple coins.
    Build request body for Fix command (single coin).

    Body format:
        - 16 bytes: Challenge
        - 1 byte: Denomination
        - 4 bytes: Serial number (big-endian)
        - 16 bytes: PG (Password Generator)
        - 100 bytes: 25 tickets (4 bytes each, big-endian)
        - 2 bytes: Terminator

    Args:
        denomination: Coin denomination
        serial_number: Coin serial number
        pg: 16-byte password generator
        tickets: List of 25 ticket IDs (0 if no ticket from that RAIDA)

    Returns:
        Request body bytes (139 bytes)
    """
    return build_fix_body([(denomination, serial_number)], pg, tickets)


# ============================================================================
# RESPONSE PARSERS
# ============================================================================

def parse_get_ticket_response(
    response: bytes,
    num_coins: int = 1
) -> Tuple[HealErrorCode, int, List[bool]]:
    """
    Parse Get-Ticket response.

    Response format:
        - 32 bytes: Response header
        - If mixed: ceil(num_coins/8) bytes of pass/fail bits
        - 4 bytes: Ticket ID

    Args:
        response: Raw response bytes
        num_coins: Number of coins in request

    Returns:
        Tuple of (error_code, ticket_id, list of pass/fail per coin)
    """
    if len(response) < RESPONSE_HEADER_SIZE:
        return HealErrorCode.ERR_NETWORK_ERROR, 0, []

    raida_id, status, cmd_group, body_size = parse_response_header(response)
    body = response[RESPONSE_HEADER_SIZE:]

    results = [False] * num_coins
    ticket_id = 0

    if status == STATUS_ALL_PASS:
        results = [True] * num_coins
        if len(body) >= 4:
            ticket_id = struct.unpack('>I', body[:4])[0]
    elif status == STATUS_ALL_FAIL:
        results = [False] * num_coins
    elif status == STATUS_MIXED:
        bits_needed = (num_coins + 7) // 8
        if len(body) >= bits_needed + 4:
            for i in range(num_coins):
                byte_idx = i // 8
                bit_idx = i % 8
                if body[byte_idx] & (1 << bit_idx):
                    results[i] = True
            ticket_id = struct.unpack('>I', body[bits_needed:bits_needed+4])[0]
    else:
        return HealErrorCode.ERR_NETWORK_ERROR, 0, results

    return HealErrorCode.SUCCESS, ticket_id, results


def parse_find_response(
    response: bytes,
    num_coins: int = 1
) -> Tuple[HealErrorCode, List[str]]:
    """
    Parse Find response.

    Response format:
        - 32 bytes: Response header
        - If mixed: num_coins bytes (0x1=AN, 0x2=PAN, 0x0=neither)

    Args:
        response: Raw response bytes
        num_coins: Number of coins in request

    Returns:
        Tuple of (error_code, list of results per coin: 'an'/'pan'/'neither')
    """
    if len(response) < RESPONSE_HEADER_SIZE:
        return HealErrorCode.ERR_NETWORK_ERROR, []

    raida_id, status, cmd_group, body_size = parse_response_header(response)
    results = ['neither'] * num_coins

    if status == STATUS_FIND_ALL_AN:
        results = ['an'] * num_coins
    elif status == STATUS_FIND_ALL_PAN:
        results = ['pan'] * num_coins
    elif status == STATUS_FIND_NEITHER:
        results = ['neither'] * num_coins
    elif status == STATUS_FIND_MIXED:
        body = response[RESPONSE_HEADER_SIZE:]
        for i in range(min(num_coins, len(body))):
            if body[i] == 0x1:
                results[i] = 'an'
            elif body[i] == 0x2:
                results[i] = 'pan'
            else:
                results[i] = 'neither'
    else:
        return HealErrorCode.ERR_NETWORK_ERROR, results

    return HealErrorCode.SUCCESS, results


def parse_fix_response(
    response: bytes,
    num_coins: int = 1
) -> Tuple[HealErrorCode, List[bool]]:
    """
    Parse Fix response.

    Response format:
        - 32 bytes: Response header
        - If mixed: ceil(num_coins/8) bytes of pass/fail bits

    Args:
        response: Raw response bytes
        num_coins: Number of coins in request

    Returns:
        Tuple of (error_code, list of pass/fail per coin)
    """
    if len(response) < RESPONSE_HEADER_SIZE:
        return HealErrorCode.ERR_NETWORK_ERROR, []

    raida_id, status, cmd_group, body_size = parse_response_header(response)
    results = [False] * num_coins

    if status == STATUS_ALL_PASS:
        results = [True] * num_coins
    elif status == STATUS_ALL_FAIL:
        results = [False] * num_coins
    elif status == STATUS_MIXED:
        body = response[RESPONSE_HEADER_SIZE:]
        bits_needed = (num_coins + 7) // 8
        for i in range(num_coins):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(body) and body[byte_idx] & (1 << bit_idx):
                results[i] = True
    else:
        return HealErrorCode.ERR_NETWORK_ERROR, results

    return HealErrorCode.SUCCESS, results


# ============================================================================
# SELF-TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("heal_protocol.py - Self Tests")
    print("=" * 60)

    # Test 1: POWN encoding/decoding
    print("\n1. Testing POWN encoding/decoding...")
    test_pown = "pppppppppppppfffffeeennnu"
    encoded = encode_pown_bytes(test_pown)
    decoded = decode_pown_bytes(encoded)
    assert decoded == test_pown, f"POWN mismatch: {decoded} != {test_pown}"
    print(f"   PASS: {test_pown} -> {encoded.hex()} -> {decoded}")

    # Test 2: Challenge generation
    print("\n2. Testing challenge generation...")
    challenge = generate_challenge()
    assert len(challenge) == 16
    crc_calc = zlib.crc32(challenge[:12]) & 0xFFFFFFFF
    crc_in_challenge = struct.unpack('>I', challenge[12:16])[0]
    assert crc_calc == crc_in_challenge, "CRC mismatch"
    print(f"   PASS: Challenge {challenge.hex()}")

    # Test 3: Request header
    print("\n3. Testing request header building...")
    header = build_request_header(5, CMD_GROUP_HEALING, CMD_GET_TICKET, 100)
    assert len(header) == 32
    assert header[2] == 5  # RAIDA ID
    assert header[4] == CMD_GROUP_HEALING
    assert header[5] == CMD_GET_TICKET
    print(f"   PASS: Header {header.hex()}")

    # Test 4: New AN calculation
    print("\n4. Testing new AN calculation...")
    pg = bytes(16)
    new_an = calculate_new_an(0, 1, 12345678, pg)
    assert len(new_an) == 16
    print(f"   PASS: New AN {new_an.hex()}")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
