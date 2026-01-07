"""
heal_encryption.py - Encryption Health Check and Fix for RAIDA

This module handles encryption status checking and shared secret
establishment with RAIDA servers.

Author: Claude Opus 4.5
Version: 1.0.0
Date: 2025-12-26

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
# For encryption
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

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
    # Rule: Coins in Bank folder MUST have all 25 RAIDA passing (0xA)
    # Therefore, if Bank has ANY coins, all 25 RAIDA have shared secrets
    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    err, bank_coins = load_coins_from_folder(bank_folder)

    if err == HealErrorCode.SUCCESS and bank_coins:
        logger.info(f"  -> Found {len(bank_coins)} coins in Bank folder")
        logger.info("  -> Bank coins exist - all 25 RAIDA have shared secrets")
        logger.info("  -> No lost encryption detected")
        # All RAIDA have shared secrets (health.is_broken is already all False)
        return HealErrorCode.SUCCESS, health

    # Step 2: Bank is empty - check Fracked folder for shared secrets
    logger.info("  -> Bank folder empty, checking Fracked folder...")
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    err, fracked_coins = load_coins_from_folder(fracked_folder)

    if err != HealErrorCode.SUCCESS or not fracked_coins:
        logger.warning("  -> No coins in Bank or Fracked folders - all RAIDA marked as broken")
        health.is_broken = [True] * RAIDA_COUNT
        return HealErrorCode.SUCCESS, health

    logger.info(f"  -> Found {len(fracked_coins)} coins in Fracked folder")

    # Step 3: Find shared secrets from Fracked coins
    # For each RAIDA, we need at least ONE coin with 'p' (0xA) status
    shared_secrets = find_shared_secrets(fracked_coins)

    # Step 4: Identify which RAIDA have NO passing coins (truly broken encryption)
    broken_count = 0
    broken_raida = []
    for raida_id in range(RAIDA_COUNT):
        if shared_secrets[raida_id] is None:
            health.is_broken[raida_id] = True
            broken_count += 1
            broken_raida.append(raida_id)

    if broken_count > 0:
        logger.warning(f"  -> {broken_count} RAIDA have no shared secrets: {broken_raida}")
        logger.info("     These RAIDA are fracked on ALL coins - encryption fix required")
    else:
        logger.info("  -> All RAIDA have shared secrets (at least one passing coin each)")

    return HealErrorCode.SUCCESS, health


# ============================================================================
# HELPER FUNCTIONS FOR FIX ENCRYPTION
# ============================================================================

def split_an_into_key_parts(an: bytes) -> Tuple[bytes, bytes]:
    """
    Split a 16-byte AN into two 8-byte key parts.

    The key parts are the actual halves of the AN we want to sync
    with the broken RAIDA. Helper RAIDA will encrypt these using
    their shared secret with the broken RAIDA.

    Args:
        an: 16-byte Authenticity Number

    Returns:
        Tuple of (part_0: bytes[8], part_1: bytes[8])
    """
    if len(an) < AN_SIZE:
        an = an.ljust(AN_SIZE, b'\x00')
    return an[0:8], an[8:16]


# ID Key denomination - ID keys used for RAIDA-to-RAIDA encryption
# These are special internal tokens with denomination 1 (smallest unit)
# Each RAIDA has 1000 ID keys for inter-RAIDA communication
ID_KEY_DENOMINATION = 1


def select_id_key_sn(broken_raida_id: int) -> int:
    """
    Select a random ID key serial number for the broken RAIDA.

    Each RAIDA has 1000 ID keys numbered:
        RAIDA 0:  0-999
        RAIDA 1:  1000-1999
        ...
        RAIDA 24: 24000-24999

    These ID keys are used for encrypted communication between RAIDA servers.
    The client tells the helper RAIDA which ID key to use when encrypting
    the key part for the broken RAIDA.

    Args:
        broken_raida_id: RAIDA ID (0-24)

    Returns:
        Random SN in the range [raida_id*1000, raida_id*1000+999]
    """
    base = broken_raida_id * 1000
    return base + random.randint(0, 999)


class CryptoUnavailableError(Exception):
    """Raised when cryptography library is required but not available."""
    pass


def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt data using AES-128-CTR mode.

    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key (coin AN)
        nonce: 8-byte nonce (from request header)

    Returns:
        Encrypted data

    Raises:
        CryptoUnavailableError: If cryptography library is not installed
    """
    if not CRYPTO_AVAILABLE:
        raise CryptoUnavailableError(
            "Cryptography library required for Fix Encryption. "
            "Install with: pip install cryptography"
        )

    # Pad nonce to 16 bytes for CTR mode (nonce || counter)
    iv = nonce.ljust(16, b'\x00')
    cipher = Cipher(algorithms.AES(key[:16]), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt data using AES-128-CTR mode.

    Args:
        ciphertext: Data to decrypt
        key: 16-byte AES key (coin AN)
        nonce: 8-byte nonce (from response header)

    Returns:
        Decrypted data

    Raises:
        CryptoUnavailableError: If cryptography library is not installed
    """
    if not CRYPTO_AVAILABLE:
        raise CryptoUnavailableError(
            "Cryptography library required for Fix Encryption. "
            "Install with: pip install cryptography"
        )

    # CTR mode decryption is same as encryption
    return aes_ctr_encrypt(ciphertext, key, nonce)


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

    Body format (31 bytes total):
        - Challenge: 16 bytes (12 random + 4 CRC32)
        - Broken RAIDA ID: 1 byte (which RAIDA we're encrypting for)
        - Coin SN: 4 bytes (fracked coin's serial number, big-endian)
        - Key Part: 8 bytes (half of fracked coin's AN for broken RAIDA)
        - Terminator: 2 bytes (0x3E3E)

    Protocol:
        - payload[0] = broken_raida_id (tells helper which RAIDA to encrypt for)
        - Server gets DN from header (ci->encryption_denomination)
        - Server uses get_inter_raida_key(my_id, broken_raida_id, 0, key) for proper key

    Server creates 16-byte encrypted block:
        KeyPart[0-7] + DN[8] + SN[9-12] + Random[13-14] + 0xFF[15]

    NOTE: This request must be ENCRYPTED using helper RAIDA's AN.

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

    # Broken RAIDA ID (1 byte) - tells helper which RAIDA to encrypt for
    # Server uses this to select the correct RAIDA-to-RAIDA key
    # DN is obtained from header (ci->encryption_denomination)
    body.append(broken_raida_id & 0xFF)

    # Coin SN (4 bytes, big-endian) - the fracked coin's SN
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

    Body format - from server cmd_key_exchange.c:
        - Challenge: 16 bytes
        - Fracked Coin DN: 1 byte
        - Fracked Coin SN: 4 bytes (big-endian per Go client)
        - Key Part Records: N x 26 bytes each
        - Terminator: 2 bytes (0x3E3E)

    Each Key Part Record (26 bytes):
        - Coin ID: 2 bytes (0x0006)
        - Split ID: 1 byte (0 for first half, 1 for second half of AN)
        - Helper RAIDA ID (DA): 1 byte
        - Shard ID: 1 byte (0x00)
        - DN: 1 byte
        - SN: 4 bytes (big-endian per Go client)
        - Encrypted Key Part: 16 bytes

    NOTE: This request is UNENCRYPTED.

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

    # Fracked Coin DN (1 byte)
    body.append(fracked_coin.denomination & 0xFF)

    # Fracked Coin SN (4 bytes, big-endian per Go client)
    body.extend(struct.pack('>I', fracked_coin.serial_number))

    # Key Part Records (26 bytes each)
    for kp in key_parts:
        # Coin ID (2 bytes) - 0x0006 for CloudCoin
        body.extend(struct.pack('>H', 0x0006))

        # Split ID (1 byte) - 0 for first half of AN, 1 for second half
        body.append(kp.split_id & 0x01)

        # Helper RAIDA ID / Detection Agent (1 byte)
        body.append(kp.helper_raida_id & 0xFF)

        # Shard ID (1 byte)
        body.append(0x00)

        # DN (1 byte)
        body.append(kp.denomination & 0xFF)

        # SN (4 bytes, big-endian per Go client)
        body.extend(struct.pack('>I', kp.serial_number))

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

    Response format:
        - Header: 32 bytes
        - Encrypted key part: 16 bytes
        - Terminator: 2 bytes (0x3E3E)

    Args:
        response: Raw response bytes

    Returns:
        Tuple of (error_code, 16-byte encrypted key part)
    """
    if len(response) < 50:  # 32 header + 16 key + 2 terminator
        return HealErrorCode.ERR_NETWORK_ERROR, bytes(16)

    raida_id, status, cmd_group, body_size = parse_response_header(response)

    # Check for success status (0 = NO_ERROR in server, 1 = success, 250 = STATUS_SUCCESS)
    if status not in (0, 1, 250):
        logger.debug(f"Get Encryption Ticket failed with status: {status}")
        return HealErrorCode.ERR_ENCRYPTION_FAILED, bytes(16)

    # Extract body
    body = response[32:]

    if len(body) < 18:  # 16 key + 2 terminator
        return HealErrorCode.ERR_NETWORK_ERROR, bytes(16)

    # Verify terminator
    if body[-2:] != TERMINATOR:
        logger.debug("Invalid terminator in Get Encryption Ticket response")
        return HealErrorCode.ERR_NETWORK_ERROR, bytes(16)

    # Extract encrypted key part (first 16 bytes of body)
    encrypted_key_part = body[:16]

    return HealErrorCode.SUCCESS, encrypted_key_part


def parse_fix_encryption_response(
    response: bytes,
    expected_key_parts: int
) -> Tuple[HealErrorCode, List[bool]]:
    """
    Parse response from Fix Encryption command (CMD 45).

    Response format (from server cmd_key_exchange.c):
        - Header: 32 bytes
        - Acceptance statuses: N bytes (0x00=fail, 0x01=success per key part)
        NO hash, NO terminator in body

    Server validates each key part by:
        1. Decrypting with RAIDA-to-RAIDA shared key
        2. Checking last byte is 0xFF marker
        3. Comparing embedded DN/SN with cleartext DN/SN

    Args:
        response: Raw response bytes
        expected_key_parts: Number of key parts sent

    Returns:
        Tuple of (error_code, list of accepted statuses)
    """
    min_size = 32 + expected_key_parts  # header + N status bytes
    if len(response) < min_size:
        logger.debug(f"Response too short: {len(response)} < {min_size}")
        return HealErrorCode.ERR_NETWORK_ERROR, []

    raida_id, status, cmd_group, body_size = parse_response_header(response)

    # Check for success status (STATUS_SUCCESS = 250 or 1)
    if status not in (250, 1, 0):  # 0 = NO_ERROR in server
        logger.debug(f"Fix Encryption failed with status: {status}")
        return HealErrorCode.ERR_FIX_REJECTED, []

    # Body is just the status bytes (no hash, no terminator)
    body = response[32:]

    # Extract acceptance statuses (0x00=fail, 0x01=success)
    accepted = []
    for i in range(expected_key_parts):
        if i < len(body):
            accepted.append(body[i] == 0x01)
        else:
            accepted.append(False)

    logger.debug(f"Fix Encryption statuses: {accepted}")
    return HealErrorCode.SUCCESS, accepted


def verify_fix_success(accepted_statuses: List[bool]) -> bool:
    """
    Verify Fix Encryption succeeded based on acceptance statuses.

    The server validates each key part internally by:
        1. Decrypting with RAIDA-to-RAIDA shared key
        2. Checking last byte is 0xFF marker
        3. Comparing embedded DN/SN with cleartext DN/SN
        4. Writing the 8-byte key part to the coin record

    The server returns 0x01 for success, 0x00 for failure per key part.
    No hash is returned - validation is done server-side.

    Args:
        accepted_statuses: List of accepted status for each key part

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
    2. Build header with encryption enabled (using helper_coin's AN)
    3. Send ENCRYPTED request to helper RAIDA
    4. Parse response to extract encrypted key part

    IMPORTANT: All helpers must use the SAME nonce because the broken RAIDA
    will decrypt ALL key parts using the single nonce from the CMD 45 header.

    Args:
        helper_raida_id: RAIDA that will encrypt for us (has shared secret)
        broken_raida_id: Broken RAIDA we're fixing
        key_part: 8-byte key part (half of fracked coin's AN)
        fracked_coin: The coin we're fixing
        shared_nonce: 8-byte nonce (all helpers MUST use the same nonce)
        split_id: 0 for AN bytes 0-7, 1 for AN bytes 8-15

    Returns:
        Tuple of (error_code, EncryptedKeyPart with 16-byte encrypted key)
    """
    # Use shared nonce (critical: all helpers must use same nonce for CMD 45 to work)
    nonce = shared_nonce if shared_nonce else os.urandom(8)

    result = EncryptedKeyPart(
        helper_raida_id=helper_raida_id,
        denomination=fracked_coin.denomination,
        serial_number=fracked_coin.serial_number,
        original_key_part=key_part,
        nonce=nonce,  # Store nonce - spec suggests CMD 45 may need matching nonces
        split_id=split_id  # 0 for first half, 1 for second half of AN
    )

    # Build request body (31 bytes per server cmd_encrypt_key)
    body, challenge = build_get_encryption_ticket_body(
        broken_raida_id,
        key_part,
        fracked_coin
    )

    logger.debug(f"CMD 44 body ({len(body)} bytes): {body.hex()}")

    # Build header with encryption type 1 (shared secret)
    # SN must be big-endian in header (build_request_header uses big-endian)
    header = build_request_header(
        raida_id=helper_raida_id,
        command_group=CMD_GROUP_KEY_EXCHANGE,
        command_code=CMD_GET_ENCRYPTION_TICKET,
        body_length=len(body),
        encryption_type=ENC_SHARED_SECRET,
        denomination=fracked_coin.denomination,
        serial_number=fracked_coin.serial_number
    )

    # Encrypt ENTIRE body except terminator using helper's AN
    # The nonce is already in header bytes 24-31 from build_request_header
    helper_an = fracked_coin.ans[helper_raida_id]
    encrypted_part = aes_ctr_encrypt(body[:-2], helper_an, nonce)  # Encrypt all but terminator
    encrypted_body = encrypted_part + TERMINATOR

    # Update header with our nonce (overwrite the random one)
    header = bytearray(header)
    header[24:32] = nonce
    header = bytes(header)

    logger.debug(f"CMD 44 header ({len(header)} bytes): {header.hex()}")

    request = header + encrypted_body
    err, response = send_request(helper_raida_id, request)

    if err != HealErrorCode.SUCCESS:
        logger.debug(f"Network error getting ticket from RAIDA{helper_raida_id}: {err}")
        return err, result

    logger.debug(f"CMD 44 response ({len(response)} bytes): {response[:64].hex() if response else 'empty'}")

    # Parse response
    err, encrypted_key_part = parse_get_encryption_ticket_response(response)

    if err != HealErrorCode.SUCCESS:
        # Get more info from response header
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
    3. Use nonce from first helper's CMD 44 request
    4. Send UNENCRYPTED request to broken RAIDA
    5. Check response body for acceptance status (0x01 = accepted per key part)

    Server-side validation (per cmd_key_exchange.c):
        - Decrypts each key part using RAIDA-to-RAIDA shared key
        - Checks last byte is 0xFF marker
        - Compares embedded DN/SN with cleartext DN/SN
        - Writes 8-byte key part to coin record if valid
        - Returns 0x01 (accepted) or 0x00 (rejected) per key part

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

    # Build header with NO encryption
    header = build_request_header(
        raida_id=broken_raida_id,
        command_group=CMD_GROUP_KEY_EXCHANGE,
        command_code=CMD_FIX_ENCRYPTION,
        body_length=len(body),
        encryption_type=ENC_NONE
    )

    # Use nonce from first helper's request
    # Server uses this nonce for CTR mode decryption of key parts
    if encrypted_key_parts[0].nonce:
        header = bytearray(header)
        header[24:32] = encrypted_key_parts[0].nonce
        header = bytes(header)
        logger.debug(f"Using nonce from helper RAIDA{encrypted_key_parts[0].helper_raida_id}")

    request = header + body

    logger.debug(f"CMD 45 request to RAIDA{broken_raida_id}:")
    logger.debug(f"  Header ({len(header)} bytes): {header.hex()}")
    logger.debug(f"  Body ({len(body)} bytes): {body.hex()}")

    err, response = send_request(broken_raida_id, request)

    if err != HealErrorCode.SUCCESS:
        logger.debug(f"Network error fixing RAIDA{broken_raida_id}: {err}")
        return err, False

    # Check response
    if len(response) < 34:  # 32 header + at least 2 status bytes
        logger.debug(f"Response too short from RAIDA{broken_raida_id}: {len(response)} bytes")
        return HealErrorCode.ERR_NETWORK_ERROR, False

    raida_id, status, cmd_group, body_size = parse_response_header(response)
    response_body = response[32:]

    logger.debug(f"RAIDA{broken_raida_id} response: status={status}, body_size={body_size}")
    logger.debug(f"Response body ({len(response_body)} bytes): {response_body.hex()}")

    # Check header status first
    if status not in (0, 1, 250):
        logger.warning(f"Fix Encryption FAILED for RAIDA{broken_raida_id}: status={status}")
        return HealErrorCode.ERR_FIX_REJECTED, False

    # Check body bytes: each key part has a status byte (0x00=rejected, 0x01=accepted)
    # Per Go client: result.Data.Data[0] != 1 || result.Data.Data[1] != 1
    num_parts = len(encrypted_key_parts)
    if len(response_body) < num_parts:
        logger.warning(f"Response body too short: {len(response_body)} < {num_parts}")
        return HealErrorCode.ERR_NETWORK_ERROR, False

    all_accepted = True
    for i in range(num_parts):
        accepted = response_body[i] == 0x01
        logger.debug(f"  Key part {i}: {'ACCEPTED' if accepted else 'REJECTED'} (0x{response_body[i]:02x})")
        if not accepted:
            all_accepted = False

    if all_accepted:
        logger.info(f"Fix Encryption SUCCESS for RAIDA{broken_raida_id}: all {num_parts} key parts accepted")
        return HealErrorCode.SUCCESS, True
    else:
        logger.warning(f"Fix Encryption FAILED for RAIDA{broken_raida_id}: not all key parts accepted")
        return HealErrorCode.ERR_FIX_REJECTED, False


# ============================================================================
# MAIN FIX ENCRYPTION FUNCTION
# ============================================================================

def select_helpers(
    working_raida: List[int],
    fracked_coin: CloudCoinBin,
    count: int = 6
) -> List[int]:
    """
    Select helper RAIDA for fix encryption.

    Selects more helpers than needed (default 6) to handle timeouts.
    The actual ticket retrieval will use the first successful responses.

    Args:
        working_raida: List of working RAIDA IDs
        fracked_coin: Coin to use for encryption
        count: Number of helpers to select (default 6 for redundancy)

    Returns:
        List of helper RAIDA IDs
    """
    # Filter to RAIDA where coin has 'p' status
    valid_helpers = [r for r in working_raida if fracked_coin.pown[r] == 'p']

    if len(valid_helpers) <= count:
        return valid_helpers

    # Randomly select helpers (more than 2 for redundancy)
    return random.sample(valid_helpers, count)


def get_encryption_tickets_parallel(
    broken_raida_id: int,
    helper_raida_ids: List[int],
    fracked_coin: CloudCoinBin
) -> List[EncryptedKeyPart]:
    """
    Get encryption tickets from multiple helpers in parallel.

    Uses ThreadPoolExecutor for better error handling and
    result collection compared to raw threading.

    Sends requests to all helpers and returns as soon as 2 succeed.
    This handles timeouts gracefully by using redundant helpers.

    CRITICAL: The nonce must be ALL ZEROS because:
    - CMD 45 uses encryption type 0 (unencrypted)
    - For type 0, the server sets ci->nonce to zeros (protocol.c line 519)
    - The broken RAIDA decrypts key parts using this zero nonce
    - So helpers must encrypt with zero nonce for decryption to work

    Args:
        broken_raida_id: RAIDA we're fixing
        helper_raida_ids: List of helper RAIDA IDs (should be > 2 for redundancy)
        fracked_coin: Coin we're using

    Returns:
        List of EncryptedKeyPart (2 parts if successful, less if not enough respond)
    """
    # Split AN into key parts (one for each helper)
    original_an = fracked_coin.ans[broken_raida_id]
    key_part_0, key_part_1 = split_an_into_key_parts(original_an)

    # CRITICAL: Use ZERO nonce because CMD 45 is unencrypted (type 0)
    # For type 0, the server hardcodes ci->nonce to all zeros
    # The broken RAIDA will decrypt using zero nonce, so helpers must encrypt with zero nonce
    shared_nonce = bytes(8)  # 8 bytes of zeros
    logger.debug(f"Using zero nonce for helpers (required for CMD 45 type 0): {shared_nonce.hex()}")

    # We need exactly 2 key parts - alternate between them for redundancy
    results_part0 = []  # Responses for key_part_0
    results_part1 = []  # Responses for key_part_1

    with ThreadPoolExecutor(max_workers=len(helper_raida_ids)) as executor:
        future_to_helper = {}
        # Send to all helpers, alternating key parts (all use same nonce)
        # split_id=0 for key_part_0 (AN bytes 0-7), split_id=1 for key_part_1 (AN bytes 8-15)
        for i, helper_id in enumerate(helper_raida_ids):
            split_id = i % 2
            key_part = key_part_0 if split_id == 0 else key_part_1
            future = executor.submit(
                get_encryption_ticket,
                helper_id,
                broken_raida_id,
                key_part,
                fracked_coin,
                shared_nonce,  # All helpers use same nonce
                split_id       # Track which half of AN this is for
            )
            future_to_helper[future] = (helper_id, split_id)

        # Collect results as they complete
        for future in as_completed(future_to_helper):
            helper_id, part_idx = future_to_helper[future]
            try:
                err, encrypted_part = future.result()
                if err == HealErrorCode.SUCCESS:
                    if part_idx == 0 and len(results_part0) == 0:
                        results_part0.append(encrypted_part)
                        logger.debug(f"Got key_part_0 ticket from RAIDA{helper_id}")
                    elif part_idx == 1 and len(results_part1) == 0:
                        results_part1.append(encrypted_part)
                        logger.debug(f"Got key_part_1 ticket from RAIDA{helper_id}")

                    # Check if we have both parts
                    if len(results_part0) >= 1 and len(results_part1) >= 1:
                        logger.debug("Got both key parts, done collecting")
                        break
                else:
                    logger.warning(f"Helper RAIDA{helper_id} failed: {err}")
            except Exception as e:
                logger.error(f"Helper RAIDA{helper_id} exception: {e}")

    # Return combined results
    return results_part0 + results_part1


def fix_encryption(
    wallet_path: str,
    health: EncryptionHealth
) -> FixEncryptionResult:
    """
    Fix broken encryption by establishing shared secrets.

    Algorithm (from K. Healing Services for Keys.md):
    1. Identify broken RAIDA from health object
    2. Load coins from FRACKED folder (Bank is empty when fix needed)
    3. Find a coin with enough working RAIDA (2+ for helpers)
    4. For each broken RAIDA:
       a. Split the AN into two 8-byte key parts
       b. Get encrypted key parts from 2 helper RAIDA (parallel)
       c. Call fix_encryption_on_raida with collected tickets
       d. Verify hash matches and update health status
    5. Return detailed results

    Args:
        wallet_path: Path to wallet folder
        health: Encryption health status from check_encryption

    Returns:
        FixEncryptionResult with detailed success/failure info
    """
    logger.info("=" * 60)
    logger.info("FIX ENCRYPTION - Establishing Shared Secrets")
    logger.info("=" * 60)

    result = FixEncryptionResult()

    # Check crypto availability early - required for CMD 44 encryption
    if not CRYPTO_AVAILABLE:
        logger.error("Cryptography library not available - required for Fix Encryption")
        logger.error("Install with: pip install cryptography")
        # Return error without attempting any RAIDA communication
        for r in health.get_broken_raida():
            result.failed_raida.append(r)
            result.errors[r] = FixEncryptionError.NO_COINS_AVAILABLE  # Closest error type
        return result

    broken_raida = health.get_broken_raida()
    working_raida = health.get_working_raida()

    result.total_broken = len(broken_raida)

    if not broken_raida:
        logger.info("No broken encryption to fix")
        result.success = True
        return result

    if len(working_raida) < 2:
        logger.error(f"Not enough working RAIDA for helpers ({len(working_raida)} < 2)")
        for r in broken_raida:
            result.failed_raida.append(r)
            result.errors[r] = FixEncryptionError.INSUFFICIENT_HELPERS
        return result

    logger.info(f"Broken RAIDA: {broken_raida}")
    logger.info(f"Working RAIDA: {working_raida}")

    # Load coins - try Bank first (preferred as they have all 25 RAIDA passing),
    # then Fracked folder. Bank may be empty when fix encryption is needed,
    # but if Bank has coins, they're better candidates for helpers.
    coins = []

    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    err, bank_coins = load_coins_from_folder(bank_folder)
    if err == HealErrorCode.SUCCESS and bank_coins:
        coins.extend(bank_coins)
        logger.info(f"Found {len(bank_coins)} coins in Bank folder")

    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    err, fracked_coins = load_coins_from_folder(fracked_folder)
    if err == HealErrorCode.SUCCESS and fracked_coins:
        coins.extend(fracked_coins)
        logger.info(f"Found {len(fracked_coins)} coins in Fracked folder")

    if not coins:
        logger.error("No coins available for encryption fix")
        for r in broken_raida:
            result.failed_raida.append(r)
            result.errors[r] = FixEncryptionError.NO_COINS_AVAILABLE
        return result

    logger.info(f"Total {len(coins)} coins available for fix encryption")

    # Find a coin that has 'p' status on at least 2 working RAIDA (for helpers)
    fix_coin = None
    for coin in coins:
        helper_count = sum(1 for r in working_raida if coin.pown[r] == 'p')
        if helper_count >= 2:
            fix_coin = coin
            break

    if fix_coin is None:
        logger.error("No coin has enough helper RAIDA (need 2+ with 'p' status)")
        for r in broken_raida:
            result.failed_raida.append(r)
            result.errors[r] = FixEncryptionError.INSUFFICIENT_HELPERS
        return result

    logger.info(f"Using coin SN={fix_coin.serial_number} for encryption fix")

    # Fix each broken RAIDA
    for broken_id in broken_raida:
        if not health.can_retry(broken_id):
            logger.debug(f"Skipping RAIDA{broken_id} (cooldown)")
            result.failed_raida.append(broken_id)
            result.errors[broken_id] = FixEncryptionError.RAIDA_OFFLINE
            continue

        health.mark_attempt(broken_id)
        logger.info(f"\nFixing RAIDA{broken_id}...")

        # Select 6 helpers for redundancy (only need 2 to respond)
        helpers = select_helpers(working_raida, fix_coin)
        if len(helpers) < 2:
            logger.warning(f"Not enough helpers for RAIDA{broken_id}")
            health.mark_failed(broken_id)
            result.failed_raida.append(broken_id)
            result.errors[broken_id] = FixEncryptionError.INSUFFICIENT_HELPERS
            continue

        logger.info(f"  Helpers selected: {helpers} (using first 2 to respond)")

        # Get encrypted key parts from helpers (parallel)
        encrypted_parts = get_encryption_tickets_parallel(
            broken_id, helpers, fix_coin
        )

        if len(encrypted_parts) < 2:
            logger.warning(f"Failed to get enough tickets for RAIDA{broken_id}")
            health.mark_failed(broken_id)
            result.failed_raida.append(broken_id)
            result.errors[broken_id] = FixEncryptionError.TICKET_FAILED
            continue

        logger.info(f"  Got {len(encrypted_parts)} encrypted key parts")

        # Send Fix Encryption to broken RAIDA
        err, verified = fix_encryption_on_raida(broken_id, fix_coin, encrypted_parts)

        if err == HealErrorCode.SUCCESS and verified:
            health.mark_fixed(broken_id)
            health.reset_failure(broken_id)
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
    print("heal_encryption.py - Self Tests (Updated for Fix Encryption)")
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
    # Server expects 31 bytes: Challenge(16) + DN(1) + SN(4) + KeyPart(8) + Terminator(2)
    assert len(body) == 31, f"Body length {len(body)} != 31"
    assert body[-2:] == TERMINATOR
    print(f"   PASS: Body length = {len(body)} bytes (expected 31)")

    # Test 9: Build Fix Encryption body
    print("\n9. Testing build_fix_encryption_body...")
    key_parts = [
        EncryptedKeyPart(helper_raida_id=1, denomination=1, serial_number=12345,
                         encrypted_key_part=bytes(16)),
        EncryptedKeyPart(helper_raida_id=2, denomination=1, serial_number=12345,
                         encrypted_key_part=bytes(16))
    ]
    body, challenge = build_fix_encryption_body(test_coin, key_parts)
    expected_len = 16 + 1 + 4 + (26 * 2) + 2  # challenge + dn + sn + 2 records + terminator
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
    print("Crypto available:", CRYPTO_AVAILABLE)
