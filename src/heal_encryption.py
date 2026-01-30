"""
heal_encryption.py - Encryption Health Check and Fix for RAIDA

This module handles encryption status checking and shared secret
establishment with RAIDA servers.

Author: Claude Opus 4.5
Version: 1.1.0
Date: 2025-01-30

Encryption Overview:
    - RAIDA communication can be encrypted using shared secrets
    - A "shared secret" is a coin AN known to both client and RAIDA
    - If no shared secret exists, encryption must be established first
    - The Fix Encryption process uses tickets from working RAIDA

Commands Used:
    - Get Encryption Ticket (44): Get encrypted ticket from working RAIDA
    - Fix Encryption (45): Establish shared secret with broken RAIDA


"""

import os
import time
import threading
import logging
from typing import List, Tuple, Optional, Any
from dataclasses import dataclass, field

# Import from heal modules
try:
    from heal_protocol import (
        RAIDA_COUNT, HealErrorCode, QUORUM_REQUIRED, AN_SIZE,
        CMD_GROUP_KEY_EXCHANGE, CMD_GET_ENCRYPTION_TICKET, CMD_FIX_ENCRYPTION,
        ENC_SHARED_SECRET, ENC_NONE,
        build_request_header, parse_response_header,
        generate_challenge, TERMINATOR,
        EncryptedKeyPart, FixEncryptionResult, FixEncryptionError,
        STATUS_KEY_ACCEPTED, STATUS_KEY_REJECTED
    )
except ImportError as e:
    print(f"Failed to import heal_protocol: {e}")
    raise

try:
    from heal_file_io import (
        CloudCoinBin, load_coins_from_folder, write_coin_file,
        FOLDER_BANK, FOLDER_FRACKED
    )
except ImportError as e:
    print(f"Failed to import heal_file_io: {e}")
    raise
try:
    from heal_network import send_request, get_raida_endpoint
except ImportError as e:
    print(f"Failed to import heal_network: {e}")
    raise

# For concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import struct
import hashlib

# Import wallet structure initialization
try:
    from wallet_structure import initialize_wallet_structure
except ImportError as e:
    print(f"Failed to import wallet_structure: {e}")
    raise


# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger("heal_encryption")


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class EncryptionHealth:
    """
    Tracks encryption status for each RAIDA.

    Some RAIDA may not have valid shared secrets with the client,
    requiring the encryption fix process before secure healing.

    Attributes:
        is_broken: List of 25 bools - True if RAIDA has no shared secret
        is_persistently_broken: List of 25 bools - True if fix attempts failed
        failure_count: Number of consecutive fix failures per RAIDA
        last_attempt_time: Unix timestamp of last fix attempt per RAIDA
        cooldown_seconds: Time to wait before retry after failure
    """
    is_broken: List[bool] = field(default_factory=lambda: [False] * RAIDA_COUNT)
    is_persistently_broken: List[bool] = field(default_factory=lambda: [False] * RAIDA_COUNT)
    failure_count: List[int] = field(default_factory=lambda: [0] * RAIDA_COUNT)
    last_attempt_time: List[float] = field(default_factory=lambda: [0.0] * RAIDA_COUNT)
    cooldown_seconds: int = 1800  # 30 minutes

    def get_broken_raida(self) -> List[int]:
        """Return list of RAIDA IDs that need encryption fix."""
        return [i for i in range(RAIDA_COUNT)
                if self.is_broken[i] and not self.is_persistently_broken[i]]

    def get_working_raida(self) -> List[int]:
        """Return list of RAIDA IDs with working encryption."""
        return [i for i in range(RAIDA_COUNT) if not self.is_broken[i]]

    def mark_fixed(self, raida_id: int) -> None:
        """Mark a RAIDA as having working encryption."""
        if 0 <= raida_id < RAIDA_COUNT:
            self.is_broken[raida_id] = False
            self.failure_count[raida_id] = 0

    def mark_failed(self, raida_id: int, max_failures: int = 3) -> None:
        """Mark a fix attempt as failed."""
        if 0 <= raida_id < RAIDA_COUNT:
            self.failure_count[raida_id] += 1
            self.last_attempt_time[raida_id] = time.time()
            if self.failure_count[raida_id] >= max_failures:
                self.is_persistently_broken[raida_id] = True

    def can_retry(self, raida_id: int) -> bool:
        """Check if enough time has passed to retry a failed RAIDA."""
        if 0 <= raida_id < RAIDA_COUNT:
            if self.is_persistently_broken[raida_id]:
                return False
            elapsed = time.time() - self.last_attempt_time[raida_id]
            return elapsed >= self.cooldown_seconds
        return False

    def mark_attempt(self, raida_id: int) -> None:
        """Record attempt time for cooldown tracking."""
        if 0 <= raida_id < RAIDA_COUNT:
            self.last_attempt_time[raida_id] = time.time()

    def reset_failure(self, raida_id: int) -> None:
        """Reset failure state after successful fix."""
        if 0 <= raida_id < RAIDA_COUNT:
            self.failure_count[raida_id] = 0
            self.is_persistently_broken[raida_id] = False


# ============================================================================
# SHARED SECRET DISCOVERY
# ============================================================================

def find_shared_secrets(coins: List[CloudCoinBin]) -> List[Optional[CloudCoinBin]]:
    """
    Find a coin that can serve as shared secret for each RAIDA.

    A coin provides a shared secret for a RAIDA if it is authenticated
    there (pown[raida_id] == 'p').

    Args:
        coins: List of coins from Bank folder

    Returns:
        List of 25 CloudCoinBin or None (one per RAIDA)
    """
    shared_secrets: List[Optional[CloudCoinBin]] = [None] * RAIDA_COUNT

    for coin in coins:
        for raida_id in range(RAIDA_COUNT):
            if shared_secrets[raida_id] is None and coin.pown[raida_id] == 'p':
                shared_secrets[raida_id] = coin

    return shared_secrets


def check_encryption(wallet_path: str) -> Tuple[HealErrorCode, EncryptionHealth]:
    """
    Check encryption status with all RAIDA.

    Determines which RAIDA have valid shared secrets (coins that are
    authenticated on both client and RAIDA).

    A "shared secret" is a coin AN that:
    - The client knows (has in Bank or Fracked folder)
    - The RAIDA knows (coin is authenticated there, pown == 'p')

    Without shared secrets, encrypted communication is not possible,
    and requests must be sent in clear text (less secure).

    Logic:
    1. Check Bank folder - if ANY coins exist, all 25 RAIDA have shared secrets
       (Bank coins must have all 25 RAIDA passing, so encryption cannot be lost)
    2. Only if Bank is empty, check Fracked folder for shared secrets
    3. A RAIDA is only "broken" if NO coin has a pass ('p') for that RAIDA

    Args:
        wallet_path: Path to wallet folder

    Returns:
        Tuple of (error_code, EncryptionHealth status)
    """
    logger.info("Checking encryption status...")

    health = EncryptionHealth()

    # Step 1: Check Bank folder first
    bank_path = os.path.join(wallet_path, FOLDER_BANK)
    bank_coins = load_coins_from_folder(bank_path) if os.path.isdir(bank_path) else []

    if bank_coins:
        # If we have ANY Bank coins, encryption is NOT lost for any RAIDA
        # Bank coins are only there if they pass all 25 RAIDA
        logger.info(f"  Found {len(bank_coins)} Bank coins")
        logger.info("  -> No lost encryption detected")
        return HealErrorCode.SUCCESS, health

    # Step 2: Bank is empty, check Fracked folder
    logger.info("  Bank is empty, checking Fracked folder...")
    fracked_path = os.path.join(wallet_path, FOLDER_FRACKED)
    fracked_coins = load_coins_from_folder(fracked_path) if os.path.isdir(fracked_path) else []

    if not fracked_coins:
        # No coins at all - mark all RAIDA as broken
        logger.warning("  No coins found in wallet!")
        for i in range(RAIDA_COUNT):
            health.is_broken[i] = True
        return HealErrorCode.SUCCESS, health

    # Step 3: Find shared secrets from Fracked coins
    logger.info(f"  Found {len(fracked_coins)} Fracked coins")
    shared_secrets = find_shared_secrets(fracked_coins)

    # Step 4: Identify which RAIDA have NO passing coins (truly broken encryption)
    broken_count = 0
    for raida_id in range(RAIDA_COUNT):
        if shared_secrets[raida_id] is None:
            health.is_broken[raida_id] = True
            broken_count += 1

    if broken_count > 0:
        broken_list = health.get_broken_raida()
        logger.info(f"  Encryption broken on {broken_count} RAIDA: {broken_list}")
        logger.info("     These RAIDA are fracked on ALL coins - encryption fix required")
    else:
        logger.info("  All RAIDA have at least one passing coin - encryption OK")

    return HealErrorCode.SUCCESS, health


# ============================================================================
# KEY PART SPLITTING
# ============================================================================

def split_an_into_key_parts(an: bytes) -> Tuple[bytes, bytes]:
    """
    Split a 16-byte AN into two 8-byte key parts.

    The Fix Encryption protocol requires sending the AN in two halves,
    each encrypted separately by different helper RAIDA.

    Args:
        an: 16-byte Authenticity Number

    Returns:
        Tuple of (part_0: bytes[0:8], part_1: bytes[8:16])
    """
    if len(an) < 16:
        an = an.ljust(16, b'\x00')
    return an[:8], an[8:16]


# ============================================================================
# ID KEY SELECTION
# ============================================================================

# ID Key denomination - ID keys used for RAIDA-to-RAIDA encryption
ID_KEY_DN = 1  # ID keys have denomination 1

def select_id_key_sn(raida_id: int) -> int:
    """
    Select an ID key serial number for a specific RAIDA.

    ID Key ranges per RAIDA (from RAIDA design):
        RAIDA 0:  0-999
        RAIDA 1:  1000-1999
        ...
        RAIDA 24: 24000-24999

    These ID keys are used for encrypted communication between RAIDA servers.
    The client tells the helper RAIDA which ID key to use when encrypting
    the key part for the broken RAIDA.

    Args:
        raida_id: Target RAIDA ID (0-24)

    Returns:
        Serial number in the RAIDA's ID key range
    """
    base_sn = raida_id * 1000
    # Pick a random key in the range for load distribution
    return base_sn + random.randint(0, 999)


# ============================================================================
# ENCRYPTION FIX PROTOCOL - REQUEST BODY BUILDERS
# ============================================================================

def build_get_encryption_ticket_body(
    broken_raida_id: int,
    key_part: bytes,
    fracked_coin: CloudCoinBin
) -> Tuple[bytes, bytes]:
    """
    Build request body for Get Encryption Ticket command (CMD 44).

    Body format (32 bytes total):
        - Challenge: 16 bytes (12 random + 4 CRC32)
        - Broken RAIDA ID: 1 byte (which RAIDA we're encrypting for)
        - Coin DN: 1 byte (denomination of coin being fixed)
        - Coin SN: 4 bytes (serial number, big-endian)
        - Key Part: 8 bytes (half of fracked coin's AN for broken RAIDA)
        - Terminator: 2 bytes (0x3E3E)

    Args:
        broken_raida_id: The broken RAIDA we're trying to fix
        key_part: 8-byte half of fracked coin's AN
        fracked_coin: The coin we're fixing

    Returns:
        Tuple of (request_body: bytes, challenge: bytes)
    """
    body = bytearray()

    # Challenge (16 bytes)
    challenge = generate_challenge()
    body.extend(challenge)

    # Broken RAIDA ID (1 byte)
    body.append(broken_raida_id & 0xFF)

    # Coin DN (1 byte)
    body.append(fracked_coin.denomination & 0xFF)

    # Coin SN (4 bytes, big-endian)
    body.extend(struct.pack('>I', fracked_coin.serial_number))

    # Key Part (8 bytes)
    body.extend(key_part[:8])

    # Terminator
    body.extend(TERMINATOR)

    return bytes(body), challenge


def build_fix_encryption_body(
    fracked_coin: CloudCoinBin,
    key_parts: List[EncryptedKeyPart]
) -> Tuple[bytes, bytes]:
    """
    Build request body for Fix Encryption command (CMD 45).

    Body format:
        - Challenge: 16 bytes
        - Coin DN: 1 byte
        - Coin SN: 4 bytes (big-endian)
        - Num Tickets: 1 byte
        For each ticket (19 bytes each):
            - Helper RAIDA ID: 1 byte
            - Split ID: 1 byte (0 for AN[0:7], 1 for AN[8:15])
            - Key Selector: 1 byte (ignored by server, uses hardcoded key)
            - Encrypted Key Part: 16 bytes
        - Terminator: 2 bytes (0x3E3E)

    NOTE: This request is UNENCRYPTED (Type 0).
    NOTE: Server uses HARDCODED_TEST_KEY for decryption, key_selector is ignored.

    Args:
        fracked_coin: The coin we're fixing
        key_parts: List of encrypted key parts from helper RAIDA

    Returns:
        Tuple of (request_body: bytes, challenge: bytes)
    """
    body = bytearray()

    # Challenge (16 bytes)
    challenge = generate_challenge()
    body.extend(challenge)

    # Coin DN (1 byte)
    body.append(fracked_coin.denomination & 0xFF)

    # Coin SN (4 bytes, big-endian)
    body.extend(struct.pack('>I', fracked_coin.serial_number))

    # Num Tickets (1 byte)
    body.append(len(key_parts) & 0xFF)

    # Each ticket (19 bytes): 1 helper_id + 1 split_id + 1 key_selector + 16 encrypted
    for kp in key_parts:
        # Helper RAIDA ID (1 byte)
        body.append(kp.helper_raida_id & 0xFF)

        # Split ID (1 byte)
        body.append(kp.split_id & 0x01)

        # Key Selector (1 byte) - server ignores this, uses hardcoded key
        body.append(0x00)

        # Encrypted Key Part (16 bytes)
        body.extend(kp.encrypted_key_part[:16])

    # Terminator
    body.extend(TERMINATOR)

    return bytes(body), challenge


# ============================================================================
# ENCRYPTION FIX PROTOCOL - RESPONSE PARSERS
# ============================================================================

def parse_get_encryption_ticket_response(
    response: bytes
) -> Tuple[HealErrorCode, bytes]:
    """
    Parse response from Get Encryption Ticket command (CMD 44).

    Response format (from server cmd_key_exchange.c):
        - Header: 32 bytes
        - Encrypted key part: 16 bytes (NO terminator!)

    The server encrypts the following 16-byte block:
        [0-7]   = key_part (8 bytes)
        [8]     = coin_den (1 byte)
        [9-12]  = coin_sn (4 bytes)
        [13]    = random (1 byte)
        [14-15] = 0xEE 0xEE marker

    Args:
        response: Raw response bytes

    Returns:
        Tuple of (error_code, 16-byte encrypted key part)
    """
    # Server returns 32-byte header + 16-byte encrypted body (no terminator)
    if len(response) < 48:
        logger.debug(f"Response too short: {len(response)} bytes (need 48)")
        return HealErrorCode.ERR_NETWORK_ERROR, bytes(16)

    raida_id, status, cmd_group, body_size = parse_response_header(response)

    # Check for success status (0 = NO_ERROR in server, 1 = success, 250 = STATUS_SUCCESS)
    if status not in (0, 1, 250):
        logger.debug(f"Get Encryption Ticket failed with status: {status}")
        return HealErrorCode.ERR_ENCRYPTION_FAILED, bytes(16)

    # Extract body (should be exactly 16 bytes)
    body = response[32:]

    if len(body) < 16:
        logger.debug(f"Body too short: {len(body)} bytes (need 16)")
        return HealErrorCode.ERR_NETWORK_ERROR, bytes(16)

    # Extract encrypted key part (first 16 bytes of body)
    # NOTE: Server does NOT send terminator in CMD 44 response!
    encrypted_key_part = body[:16]

    logger.debug(f"Got encrypted ticket: {encrypted_key_part.hex()}")
    return HealErrorCode.SUCCESS, encrypted_key_part


def parse_fix_encryption_response(
    response: bytes,
    expected_key_parts: int
) -> Tuple[HealErrorCode, List[bool]]:
    """
    Parse response from Fix Encryption command (CMD 45).

    Response format (from server cmd_key_exchange.c):
        - Header: 32 bytes
        - Acceptance statuses: N bytes (0x00=rejected, 0x01=accepted per ticket)
        NO hash, NO terminator in body

    Server validates each ticket by:
        1. Decrypting with HARDCODED_TEST_KEY and HARDCODED_TEST_NONCE
        2. Checking bytes [14-15] are 0xEE 0xEE marker
        3. Comparing embedded DN/SN with request DN/SN

    Args:
        response: Raw response bytes
        expected_key_parts: Number of key parts sent in request

    Returns:
        Tuple of (error_code, list of acceptance statuses)
    """
    if len(response) < 32:
        return HealErrorCode.ERR_NETWORK_ERROR, []

    raida_id, status, cmd_group, body_size = parse_response_header(response)

    # Check for success status
    if status not in (0, 1, 250):
        logger.debug(f"Fix Encryption command failed with status: {status}")
        return HealErrorCode.ERR_ENCRYPTION_FAILED, []

    # Extract body
    body = response[32:]

    if len(body) < expected_key_parts:
        logger.debug(f"Body too short for {expected_key_parts} status bytes")
        return HealErrorCode.ERR_NETWORK_ERROR, []

    # Parse acceptance statuses
    accepted = []
    for i in range(expected_key_parts):
        is_accepted = (body[i] == 0x01)
        accepted.append(is_accepted)
        logger.debug(f"  Ticket {i}: {'ACCEPTED' if is_accepted else 'REJECTED'} (0x{body[i]:02X})")

    return HealErrorCode.SUCCESS, accepted


def verify_fix_success(accepted_statuses: List[bool]) -> bool:
    """
    Verify that the fix encryption operation was successful.

    For a fix to be considered successful, ALL key parts must be accepted.
    This is because the AN is split into two halves, and both must be
    stored correctly for the coin to be usable.

    Args:
        accepted_statuses: List of acceptance statuses from server

    Returns:
        True if all key parts were accepted
    """
    if not accepted_statuses:
        logger.debug("No acceptance statuses received")
        return False

    if not all(accepted_statuses):
        logger.debug(f"Not all key parts accepted: {accepted_statuses}")
        return False

    logger.debug(f"All {len(accepted_statuses)} key parts accepted")
    return True


# ============================================================================
# ENCRYPTION FIX PROTOCOL - MAIN FUNCTIONS
# ============================================================================

def get_encryption_ticket(
    helper_raida_id: int,
    broken_raida_id: int,
    key_part: bytes,
    fracked_coin: CloudCoinBin,
    shared_nonce: bytes = None,
    split_id: int = 0
) -> Tuple[HealErrorCode, EncryptedKeyPart]:
    """
    Get encrypted ticket from a helper RAIDA.

    Process:
    1. Build Get Encryption Ticket request body
    2. Build header with NO encryption (Type 0)
    3. Send UNENCRYPTED request to helper RAIDA
    4. Server encrypts key_part using HARDCODED_TEST_KEY
    5. Parse response to extract encrypted key part

    NOTE: Client does NOT perform any encryption. Server uses hardcoded
    test key for inter-RAIDA encryption during debugging.

    Args:
        helper_raida_id: RAIDA that will encrypt for us
        broken_raida_id: Broken RAIDA we're fixing
        key_part: 8-byte key part (half of fracked coin's AN)
        fracked_coin: The coin we're fixing
        shared_nonce: Not used (kept for compatibility)
        split_id: 0 for AN bytes 0-7, 1 for AN bytes 8-15

    Returns:
        Tuple of (error_code, EncryptedKeyPart with 16-byte encrypted key)
    """
    result = EncryptedKeyPart(
        helper_raida_id=helper_raida_id,
        denomination=fracked_coin.denomination,
        serial_number=fracked_coin.serial_number,
        original_key_part=key_part,
        split_id=split_id
    )

    # Build request body
    body, challenge = build_get_encryption_ticket_body(
        broken_raida_id,
        key_part,
        fracked_coin
    )

    logger.debug(f"CMD 44 body ({len(body)} bytes): {body.hex()}")

    # Build header with NO encryption (Type 0)
    header = build_request_header(
        raida_id=helper_raida_id,
        command_group=CMD_GROUP_KEY_EXCHANGE,
        command_code=CMD_GET_ENCRYPTION_TICKET,
        body_length=len(body),
        encryption_type=ENC_NONE
    )

    logger.debug(f"CMD 44 header ({len(header)} bytes): {header.hex()}")

    request = header + body
    err, response = send_request(helper_raida_id, request)

    if err != HealErrorCode.SUCCESS:
        logger.debug(f"Network error getting ticket from RAIDA{helper_raida_id}: {err}")
        return err, result

    logger.debug(f"CMD 44 response ({len(response)} bytes): {response[:64].hex() if response else 'empty'}")

    # Parse response
    err, encrypted_key_part = parse_get_encryption_ticket_response(response)

    if err != HealErrorCode.SUCCESS:
        if len(response) >= 32:
            r_raida, r_status, r_cg, r_body = parse_response_header(response)
            logger.debug(f"Response header: raida={r_raida}, status={r_status}, cg={r_cg}, body={r_body}")
        logger.debug(f"Failed to parse ticket from RAIDA{helper_raida_id}: {err}")
        return err, result

    result.encrypted_key_part = encrypted_key_part
    logger.debug(f"Got encrypted key part from RAIDA{helper_raida_id}: {encrypted_key_part.hex()}")

    return HealErrorCode.SUCCESS, result


def fix_encryption_on_raida(
    broken_raida_id: int,
    fracked_coin: CloudCoinBin,
    encrypted_key_parts: List[EncryptedKeyPart]
) -> Tuple[HealErrorCode, bool]:
    """
    Fix encryption on a broken RAIDA using encrypted key parts.

    Process:
    1. Build Fix Encryption request body (UNENCRYPTED)
    2. Build header with encryption type = 0
    3. Send UNENCRYPTED request to broken RAIDA
    4. Server decrypts tickets using HARDCODED_TEST_KEY
    5. Check response body for acceptance status (0x01 = accepted per ticket)

    Server-side validation (per cmd_key_exchange.c):
        - Decrypts each ticket using HARDCODED_TEST_KEY + HARDCODED_TEST_NONCE
        - Checks bytes [14-15] are 0xEE 0xEE marker
        - Compares embedded DN/SN with cleartext DN/SN
        - Writes 8-byte key_part to coin record if valid
        - Returns 0x01 (accepted) or 0x00 (rejected) per ticket

    Args:
        broken_raida_id: RAIDA ID that needs encryption fix
        fracked_coin: Coin to establish as shared secret
        encrypted_key_parts: List of encrypted key parts from helper RAIDA

    Returns:
        Tuple of (HealErrorCode, success: bool)
    """
    if len(encrypted_key_parts) < 2:
        logger.error(f"Need at least 2 key parts, got {len(encrypted_key_parts)}")
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, False

    # Build request body (unencrypted)
    body, challenge = build_fix_encryption_body(fracked_coin, encrypted_key_parts)

    logger.debug(f"CMD 45 body ({len(body)} bytes): {body.hex()}")

    # Build header with NO encryption
    header = build_request_header(
        raida_id=broken_raida_id,
        command_group=CMD_GROUP_KEY_EXCHANGE,
        command_code=CMD_FIX_ENCRYPTION,
        body_length=len(body),
        encryption_type=ENC_NONE
    )

    logger.debug(f"CMD 45 header ({len(header)} bytes): {header.hex()}")

    request = header + body
    err, response = send_request(broken_raida_id, request)

    if err != HealErrorCode.SUCCESS:
        logger.debug(f"Network error sending fix to RAIDA{broken_raida_id}: {err}")
        return err, False

    logger.debug(f"CMD 45 response ({len(response)} bytes): {response[:64].hex() if response else 'empty'}")

    # Parse response
    err, accepted = parse_fix_encryption_response(response, len(encrypted_key_parts))

    if err != HealErrorCode.SUCCESS:
        logger.debug(f"Failed to parse fix response from RAIDA{broken_raida_id}: {err}")
        return err, False

    # Check if all key parts were accepted
    success = verify_fix_success(accepted)

    if success:
        logger.info(f"Fix Encryption SUCCESS on RAIDA{broken_raida_id}")
    else:
        logger.warning(f"Fix Encryption FAILED on RAIDA{broken_raida_id}: {accepted}")

    return HealErrorCode.SUCCESS if success else HealErrorCode.ERR_ENCRYPTION_FAILED, success


# ============================================================================
# PARALLEL TICKET RETRIEVAL
# ============================================================================

def select_helper_raida(
    broken_raida_id: int,
    working_raida: List[int],
    count: int = 2
) -> List[int]:
    """
    Select helper RAIDA to get encryption tickets from.

    Strategy:
    - Need at least 2 helpers (one for each AN half)
    - Exclude the broken RAIDA
    - Prefer RAIDA that are "close" in ID (faster network)

    Args:
        broken_raida_id: RAIDA we're trying to fix
        working_raida: List of RAIDA IDs with working encryption
        count: Number of helpers to select

    Returns:
        List of helper RAIDA IDs
    """
    available = [r for r in working_raida if r != broken_raida_id]

    if len(available) < count:
        logger.warning(f"Not enough helpers: need {count}, have {len(available)}")
        return available

    # Simple selection: random sample
    return random.sample(available, count)


def get_encryption_tickets_parallel(
    broken_raida_id: int,
    fracked_coin: CloudCoinBin,
    helper_raida_ids: List[int],
    max_workers: int = 4
) -> Tuple[HealErrorCode, List[EncryptedKeyPart]]:
    """
    Get encryption tickets from multiple helpers in parallel.

    Process:
    1. Split the fracked coin's AN into two 8-byte key parts
    2. Send key_part_0 to half of helpers, key_part_1 to other half
    3. Collect encrypted tickets from all helpers
    4. Return the encrypted key parts

    Args:
        broken_raida_id: RAIDA we're trying to fix
        fracked_coin: Coin we're fixing
        helper_raida_ids: List of helper RAIDA IDs
        max_workers: Max parallel threads

    Returns:
        Tuple of (error_code, list of EncryptedKeyPart)
    """
    if len(helper_raida_ids) < 2:
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, []

    # Get AN for the broken RAIDA
    an = fracked_coin.get_an_for_raida(broken_raida_id)
    if not an or len(an) < 16:
        logger.error(f"No AN available for RAIDA{broken_raida_id}")
        return HealErrorCode.ERR_INVALID_COIN, []

    # Split AN into two halves
    key_part_0, key_part_1 = split_an_into_key_parts(an)

    logger.debug(f"AN for RAIDA{broken_raida_id}: {an.hex()}")
    logger.debug(f"  key_part_0: {key_part_0.hex()}")
    logger.debug(f"  key_part_1: {key_part_1.hex()}")

    # We need at least one ticket for each key part
    encrypted_parts: List[EncryptedKeyPart] = []
    got_part_0 = False
    got_part_1 = False

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []

        # Submit tasks: alternate between key_part_0 and key_part_1
        for i, helper_id in enumerate(helper_raida_ids):
            if i % 2 == 0:
                # Get ticket for key_part_0
                future = executor.submit(
                    get_encryption_ticket,
                    helper_id,
                    broken_raida_id,
                    key_part_0,
                    fracked_coin,
                    None,
                    0  # split_id = 0
                )
            else:
                # Get ticket for key_part_1
                future = executor.submit(
                    get_encryption_ticket,
                    helper_id,
                    broken_raida_id,
                    key_part_1,
                    fracked_coin,
                    None,
                    1  # split_id = 1
                )
            futures.append((future, helper_id, i % 2))

        # Collect results
        for future, helper_id, split_id in futures:
            try:
                err, key_part = future.result(timeout=10)
                if err == HealErrorCode.SUCCESS:
                    encrypted_parts.append(key_part)
                    if split_id == 0:
                        got_part_0 = True
                        logger.debug(f"Got key_part_0 ticket from RAIDA{helper_id}")
                    else:
                        got_part_1 = True
                        logger.debug(f"Got key_part_1 ticket from RAIDA{helper_id}")
            except Exception as e:
                logger.debug(f"Failed to get ticket from RAIDA{helper_id}: {e}")

    # Check if we have both halves
    if not got_part_0 or not got_part_1:
        logger.warning(f"Missing key parts: part_0={got_part_0}, part_1={got_part_1}")
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, encrypted_parts

    return HealErrorCode.SUCCESS, encrypted_parts


# ============================================================================
# HIGH-LEVEL FIX ENCRYPTION ORCHESTRATION
# ============================================================================

def fix_single_raida_encryption(
    broken_raida_id: int,
    fracked_coin: CloudCoinBin,
    health: EncryptionHealth
) -> Tuple[HealErrorCode, bool]:
    """
    Fix encryption for a single broken RAIDA.

    Complete process:
    1. Find working RAIDA (helpers)
    2. Select 2+ helpers for ticket retrieval
    3. Get encrypted tickets from helpers (parallel)
    4. Send encrypted tickets to broken RAIDA (CMD 45)
    5. Verify acceptance

    Args:
        broken_raida_id: RAIDA ID to fix
        fracked_coin: Coin to use for shared secret
        health: Current encryption health status

    Returns:
        Tuple of (error_code, success: bool)
    """
    logger.info(f"Fixing encryption for RAIDA{broken_raida_id}")

    # Get working RAIDA
    working = health.get_working_raida()
    if len(working) < 2:
        logger.error(f"Not enough working RAIDA: {len(working)} (need 2+)")
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, False

    # Select helpers
    helpers = select_helper_raida(broken_raida_id, working, count=4)
    if len(helpers) < 2:
        logger.error(f"Could not select enough helpers: {helpers}")
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, False

    logger.info(f"  Using helpers: {helpers}")

    # Get encrypted tickets
    err, encrypted_parts = get_encryption_tickets_parallel(
        broken_raida_id,
        fracked_coin,
        helpers
    )

    if err != HealErrorCode.SUCCESS or len(encrypted_parts) < 2:
        logger.warning(f"Failed to get enough tickets: {err}, got {len(encrypted_parts)}")
        return HealErrorCode.ERR_INSUFFICIENT_HELPERS, False

    # Send fix request to broken RAIDA
    err, success = fix_encryption_on_raida(
        broken_raida_id,
        fracked_coin,
        encrypted_parts
    )

    return err, success


def fix_encryption(
    wallet_path: str,
    health: EncryptionHealth,
    fix_coin: CloudCoinBin = None
) -> FixEncryptionResult:
    """
    Fix encryption for all broken RAIDA.

    Process:
    1. Get list of broken RAIDA from health status
    2. Find a coin that can be used as shared secret
    3. For each broken RAIDA:
       a. Select helper RAIDA (working RAIDA)
       b. Get encrypted tickets from helpers (CMD 44)
       c. Send fix request to broken RAIDA (CMD 45)
       d. Update health status based on result

    Args:
        wallet_path: Path to wallet folder
        health: Current encryption health status
        fix_coin: Optional coin to use for fixing (uses first fracked if not provided)

    Returns:
        FixEncryptionResult with detailed results
    """
    result = FixEncryptionResult()
    broken_list = health.get_broken_raida()

    result.total_broken = len(broken_list)

    if not broken_list:
        logger.info("No broken RAIDA to fix")
        result.success = True
        return result

    logger.info("\n" + "=" * 60)
    logger.info(f"FIX ENCRYPTION: {len(broken_list)} RAIDA need fixing")
    logger.info(f"Broken RAIDA: {broken_list}")
    logger.info("=" * 60)

    # Find a coin to use for fixing
    if fix_coin is None:
        fracked_path = os.path.join(wallet_path, FOLDER_FRACKED)
        fracked_coins = load_coins_from_folder(fracked_path) if os.path.isdir(fracked_path) else []

        if not fracked_coins:
            logger.error("No fracked coins available for fix encryption")
            result.success = False
            return result

        # Use first fracked coin
        fix_coin = fracked_coins[0]

    logger.info(f"Using coin SN={fix_coin.serial_number} for fix encryption")
    logger.info(f"Coin POWN: {fix_coin.pown}")

    # Fix each broken RAIDA
    for broken_id in broken_list:
        logger.info(f"\n--- Fixing RAIDA{broken_id} ---")

        err, success = fix_single_raida_encryption(
            broken_id,
            fix_coin,
            health
        )

        if success:
            health.mark_fixed(broken_id)
            result.fixed_raida.append(broken_id)
            result.total_fixed += 1
            # Update coin's POWN to reflect successful fix
            fix_coin.update_pown_char(broken_id, 'p')
            logger.info(f"  SUCCESS: RAIDA{broken_id} encryption fixed!")
            logger.info(f"  Updated POWN: {fix_coin.pown}")
        else:
            health.mark_failed(broken_id)
            result.failed_raida.append(broken_id)
            if err == HealErrorCode.ERR_HASH_MISMATCH:
                result.errors[broken_id] = FixEncryptionError.HASH_MISMATCH
            else:
                result.errors[broken_id] = FixEncryptionError.FIX_FAILED
            logger.warning(f"  FAILED: RAIDA{broken_id} - {err}")

    # Save the updated coin if any fixes were made
    if result.total_fixed > 0 and fix_coin is not None:
        err = write_coin_file(fix_coin.file_path, fix_coin)
        if err == HealErrorCode.SUCCESS:
            logger.info(f"Saved updated coin: {fix_coin.file_path}")
            logger.info(f"New POWN: {fix_coin.pown}")
        else:
            logger.error(f"Failed to save updated coin: {err}")

    # Determine overall success
    result.success = len(result.failed_raida) == 0

    logger.info("\n" + "=" * 60)
    logger.info(f"FIX ENCRYPTION COMPLETE: {result.total_fixed}/{result.total_broken} fixed")
    if result.failed_raida:
        logger.info(f"Failed RAIDA: {result.failed_raida}")
    logger.info("=" * 60)

    return result


def verify_fix_results(
    wallet_path: str,
    health_before: EncryptionHealth
) -> Tuple[EncryptionHealth, dict]:
    """
    Verify fix encryption results by re-checking encryption status.

    Args:
        wallet_path: Path to wallet
        health_before: EncryptionHealth before fix attempt

    Returns:
        Tuple of (new EncryptionHealth, comparison dict)
    """
    # Re-run check_encryption
    err, health_after = check_encryption(wallet_path)

    comparison = {
        'broken_before': health_before.get_broken_raida(),
        'broken_after': health_after.get_broken_raida(),
        'fixed': [],
        'still_broken': [],
        'newly_broken': []
    }

    broken_before = set(health_before.get_broken_raida())
    broken_after = set(health_after.get_broken_raida())

    comparison['fixed'] = list(broken_before - broken_after)
    comparison['still_broken'] = list(broken_before & broken_after)
    comparison['newly_broken'] = list(broken_after - broken_before)

    return health_after, comparison


# ============================================================================
# SELF-TEST
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()
    logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("heal_encryption.py - Self Tests (Updated for Hardcoded Keys)")
    print("=" * 60)

    # Test 1: EncryptionHealth dataclass
    print("\n1. Testing EncryptionHealth dataclass...")
    health = EncryptionHealth()
    assert len(health.is_broken) == 25
    assert len(health.get_broken_raida()) == 0
    assert len(health.get_working_raida()) == 25
    print("   PASS: Default state correct")

    # Test 2: Mark broken
    print("\n2. Testing mark broken...")
    health.is_broken[5] = True
    health.is_broken[10] = True
    assert 5 in health.get_broken_raida()
    assert 10 in health.get_broken_raida()
    assert 5 not in health.get_working_raida()
    print(f"   PASS: Broken = {health.get_broken_raida()}")

    # Test 3: Mark fixed
    print("\n3. Testing mark fixed...")
    health.mark_fixed(5)
    assert 5 not in health.get_broken_raida()
    assert 5 in health.get_working_raida()
    print("   PASS: RAIDA5 fixed")

    # Test 4: Failure tracking
    print("\n4. Testing failure tracking...")
    health.mark_failed(10)
    health.mark_failed(10)
    health.mark_failed(10)
    assert health.is_persistently_broken[10] == True
    assert health.can_retry(10) == False
    print("   PASS: RAIDA10 marked persistently broken after 3 failures")

    # Test 5: Find shared secrets
    print("\n5. Testing find_shared_secrets...")
    test_coins = [
        CloudCoinBin(serial_number=1, pown='ppppppppppppppppppppppppp'),
        CloudCoinBin(serial_number=2, pown='fffffffffffffffffffffffff'),
    ]
    secrets = find_shared_secrets(test_coins)
    assert secrets[0] is not None
    assert secrets[0].serial_number == 1
    print("   PASS: Found shared secrets correctly")

    # Test 6: Split AN into key parts
    print("\n6. Testing split_an_into_key_parts...")
    test_an = bytes(range(16))  # 0x00 to 0x0F
    part0, part1 = split_an_into_key_parts(test_an)
    assert len(part0) == 8
    assert len(part1) == 8
    assert part0 == bytes(range(8))
    assert part1 == bytes(range(8, 16))
    print(f"   PASS: Split {test_an.hex()} into {part0.hex()} and {part1.hex()}")

    # Test 7: Select ID key SN
    print("\n7. Testing select_id_key_sn...")
    for raida_id in [0, 5, 24]:
        sn = select_id_key_sn(raida_id)
        expected_min = raida_id * 1000
        expected_max = raida_id * 1000 + 999
        assert expected_min <= sn <= expected_max, f"SN {sn} out of range for RAIDA{raida_id}"
        print(f"   RAIDA{raida_id}: SN={sn} (range {expected_min}-{expected_max})")
    print("   PASS: ID key SNs in correct ranges")

    # Test 8: Build Get Encryption Ticket body
    print("\n8. Testing build_get_encryption_ticket_body...")
    test_coin = CloudCoinBin(
        serial_number=12345,
        denomination=1,
        pown='ppppppppppppppppppppppppp'
    )
    # Set AN for broken RAIDA 5
    test_coin.ans[5] = bytes(range(16))
    body, challenge = build_get_encryption_ticket_body(
        broken_raida_id=5,
        key_part=bytes(range(8)),
        fracked_coin=test_coin
    )
    # Server expects 32 bytes: Challenge(16) + BrokenID(1) + DN(1) + SN(4) + KeyPart(8) + Terminator(2)
    assert len(body) == 32, f"Body length {len(body)} != 32"
    assert body[-2:] == TERMINATOR
    print(f"   PASS: Body length = {len(body)} bytes (expected 32)")

    # Test 9: Build Fix Encryption body
    print("\n9. Testing build_fix_encryption_body...")
    key_parts = [
        EncryptedKeyPart(helper_raida_id=1, denomination=1, serial_number=12345,
                         encrypted_key_part=bytes(16), split_id=0),
        EncryptedKeyPart(helper_raida_id=2, denomination=1, serial_number=12345,
                         encrypted_key_part=bytes(16), split_id=1)
    ]
    body, challenge = build_fix_encryption_body(test_coin, key_parts)
    # Expected: 16 challenge + 1 dn + 4 sn + 1 num_tickets + (19 * 2) + 2 terminator = 62 bytes
    expected_len = 16 + 1 + 4 + 1 + (19 * 2) + 2
    assert len(body) == expected_len, f"Body length {len(body)} != {expected_len}"
    assert body[-2:] == TERMINATOR
    print(f"   PASS: Body length = {len(body)} bytes (expected {expected_len})")

    # Test 10: Verify fix success
    print("\n10. Testing verify_fix_success...")
    # Test all accepted
    result = verify_fix_success([True, True])
    assert result == True
    print(f"   PASS: All accepted = True")
    # Test partial failure
    result = verify_fix_success([True, False])
    assert result == False
    print(f"   PASS: Partial failure = False")
    # Test empty
    result = verify_fix_success([])
    assert result == False
    print(f"   PASS: Empty = False")

    # Test 11: FixEncryptionResult dataclass
    print("\n11. Testing FixEncryptionResult dataclass...")
    result = FixEncryptionResult()
    assert result.success == False
    assert result.total_fixed == 0
    result.fixed_raida = [1, 2, 3]
    result.total_fixed = 3
    result.success = True
    assert len(result.fixed_raida) == 3
    print("   PASS: FixEncryptionResult works correctly")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
    print("\nNote: Network tests require live RAIDA servers.")
    print("Server uses HARDCODED_TEST_KEY and HARDCODED_TEST_NONCE for debugging.")