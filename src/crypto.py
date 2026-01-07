"""
crypto.py - AES-128 CTR Encryption Module for QMail Client Core

This module handles AES-128 CTR encryption/decryption for all data stripes
and server communication. Uses pycryptodome for cryptographic operations.

Author: Claude Opus 4.5
Phase: I
Version: 1.0.0

Key Management:
    - Keys stored in Data/keys.txt (25 lines, one key per line)
    - Key format: 32-character hex string (16 bytes)
    - Key index = server port - 50000 (e.g., port 50002 -> index 2)

C Notes:
    - Use OpenSSL EVP_* functions for AES operations in Phase III
    - Nonce generation maps to RAND_bytes() in OpenSSL
    - File reading maps to standard C file I/O

Functions:
    load_key_from_file(port)       -> (CryptoErrorCode, bytes[16] or None)
    encrypt_data(data, key)        -> (CryptoErrorCode, encrypted_bytes or None)
    decrypt_data(data, key)        -> (CryptoErrorCode, decrypted_bytes or None)
    derive_nonce()                 -> bytes[8]

Nonce Handling (AES-CTR):
    PyCryptodome's AES-CTR mode uses an 8-byte nonce combined with an 8-byte
    counter to form the full 16-byte counter block. We generate and store only
    the 8-byte nonce portion - the counter starts at 0 and increments automatically.
"""

import os
from typing import Optional, Tuple

# PyCryptodome imports for real AES-128 CTR encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    AES = None
    get_random_bytes = None

# Import error codes from qmail_types
try:
    from qmail_types import CryptoErrorCode
except ImportError:
    # Fallback for standalone testing
    from enum import IntEnum

    class CryptoErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_KEY = 1
        ERR_ENCRYPTION_FAILED = 2
        ERR_DECRYPTION_FAILED = 3
        ERR_SIGNATURE_FAILED = 4
        ERR_VERIFICATION_FAILED = 5
        ERR_HASH_FAILED = 6

# Import logger (optional - for error reporting)
try:
    from logger import log_error, log_info, log_debug, log_warning, LoggerHandle
except ImportError:
    # Fallback for standalone testing
    LoggerHandle = None

    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")

    def log_info(handle, context, msg):
        print(f"[INFO] [{context}] {msg}")

    def log_debug(handle, context, msg):
        print(f"[DEBUG] [{context}] {msg}")

    def log_warning(handle, context, msg):
        print(f"[WARNING] [{context}] {msg}")


# ============================================================================
# CONSTANTS
# ============================================================================

AES_KEY_SIZE = 16           # 16 bytes = 128 bits
AES_CTR_NONCE_SIZE = 8      # 8 bytes for CTR nonce (pycryptodome uses 8-byte nonce + 8-byte counter)
KEY_HEX_LENGTH = 32         # 32 hex chars = 16 bytes
NUM_KEYS = 25               # 25 keys for servers 50000-50024
BASE_PORT = 50000           # Port 50000 = key index 0

# Default keys file path (relative to project root)
DEFAULT_KEYS_PATH = "Data/keys.txt"

# Context name for logging
CRYPTO_CONTEXT = "CryptoMod"


# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

def _validate_key(key: bytes) -> bool:
    """
    Validate that key is exactly 16 bytes.

    Args:
        key: Key bytes to validate

    Returns:
        True if valid (16 bytes), False otherwise

    C signature: static bool _validate_key(const uint8_t* key);
    """
    return key is not None and len(key) == AES_KEY_SIZE


def _hex_to_bytes(hex_str: str) -> Optional[bytes]:
    """
    Convert a hex string to bytes.

    Args:
        hex_str: Hex string (e.g., "a1b2c3d4...")

    Returns:
        Bytes if valid hex, None if invalid

    C signature: static bool _hex_to_bytes(const char* hex, uint8_t* out, size_t len);
    """
    try:
        # Strip whitespace and validate length
        hex_str = hex_str.strip()
        if len(hex_str) != KEY_HEX_LENGTH:
            return None
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def _get_keys_path() -> str:
    """
    Get the absolute path to keys.txt.

    Handles running from src/ directory or project root.

    Returns:
        Absolute path to keys.txt
    """
    # Try relative to current working directory first
    if os.path.exists(DEFAULT_KEYS_PATH):
        return os.path.abspath(DEFAULT_KEYS_PATH)

    # Try relative to this script's directory (for running from src/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir) == 'src':
        project_root = os.path.dirname(script_dir)
        path = os.path.join(project_root, DEFAULT_KEYS_PATH)
        if os.path.exists(path):
            return path

    # Return default path (caller will handle file not found)
    return DEFAULT_KEYS_PATH


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def derive_nonce() -> bytes:
    """
    Generate a random 8-byte nonce for AES-CTR encryption.

    Uses cryptographically secure random number generation.
    PyCryptodome's CTR mode uses an 8-byte nonce + 8-byte counter.

    Returns:
        8 random bytes suitable for use as a CTR nonce

    C signature:
        void derive_nonce(uint8_t* out_nonce);

    Note:
        In C, this maps to OpenSSL's RAND_bytes(nonce, 8)
    """
    if CRYPTO_AVAILABLE and get_random_bytes:
        return get_random_bytes(AES_CTR_NONCE_SIZE)
    else:
        # Fallback to os.urandom (also cryptographically secure)
        return os.urandom(AES_CTR_NONCE_SIZE)


def load_key_from_file(
    port: int,
    logger_handle: Optional[object] = None,
    keys_path: Optional[str] = None
) -> Tuple[CryptoErrorCode, Optional[bytes]]:
    """
    Load AES-128 key from file based on server port.

    Key index is calculated as: port - 50000
    For example, port 50002 loads the key at line index 2 (third line).

    Args:
        port: Server port number (50000-50024)
        logger_handle: Optional logger handle for error reporting
        keys_path: Path to keys.txt file (default: "Data/keys.txt")

    Returns:
        Tuple of (CryptoErrorCode, key_bytes or None)
        - SUCCESS, 16-byte key on success
        - ERR_INVALID_KEY, None if key file missing, invalid format, or port out of range

    C signature:
        CryptoErrorCode load_key_from_file(int port, uint8_t* out_key, const char* keys_path);

    File Format (Data/keys.txt):
        Line 0: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4  (key for port 50000)
        Line 1: 1234567890abcdef1234567890abcdef  (key for port 50001)
        ...
        Line 24: fedcba0987654321fedcba0987654321 (key for port 50024)

    Example:
        err, key = load_key_from_file(50002)
        if err != CryptoErrorCode.SUCCESS:
            # Handle error - stop communication, inform user
            pass
    """
    # Use default path if not specified
    if keys_path is None:
        keys_path = _get_keys_path()

    # Validate port range
    key_index = port - BASE_PORT
    if key_index < 0 or key_index >= NUM_KEYS:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            f"Key load failed for port {port}",
            f"port out of range (valid: {BASE_PORT}-{BASE_PORT + NUM_KEYS - 1})"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Check if file exists
    if not os.path.exists(keys_path):
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            f"Key load failed for port {port}",
            f"keys file not found: {keys_path}"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Read and parse the file
    try:
        with open(keys_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except IOError as e:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            f"Key load failed for port {port}",
            f"file read error: {e}"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Check if requested line exists
    if key_index >= len(lines):
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            f"Key load failed for port {port}",
            f"key index {key_index} not found (file has {len(lines)} lines)"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Parse the hex key
    hex_key = lines[key_index].strip()
    key_bytes = _hex_to_bytes(hex_key)

    if key_bytes is None:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            f"Key load failed for port {port}",
            f"invalid hex format on line {key_index} (expected {KEY_HEX_LENGTH} hex chars)"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    log_debug(
        logger_handle, CRYPTO_CONTEXT,
        f"Key loaded for port {port} (index {key_index})"
    )
    return CryptoErrorCode.SUCCESS, key_bytes


def encrypt_data(
    data: bytes,
    key: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[CryptoErrorCode, Optional[bytes]]:
    """
    Encrypt data using AES-128 CTR mode.

    The encrypted output format is: [8-byte nonce][ciphertext]
    The nonce is randomly generated and prepended to the ciphertext.

    Args:
        data: Plaintext data to encrypt
        key: 16-byte AES key
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (CryptoErrorCode, encrypted_bytes or None)
        - SUCCESS, nonce+ciphertext on success
        - ERR_INVALID_KEY, None if key is wrong size
        - ERR_ENCRYPTION_FAILED, None on encryption error

    C signature:
        CryptoErrorCode encrypt_data(const uint8_t* data, size_t data_len,
                                      const uint8_t* key, uint8_t** out_encrypted,
                                      size_t* out_len);

    AES-128 CTR Details:
        - Uses pycryptodome's AES.new(key, AES.MODE_CTR, nonce=nonce)
        - Nonce is 8 bytes, randomly generated
        - Counter is 8 bytes, starts at 0 and increments automatically
        - No padding required (CTR is a stream cipher mode)

    Example:
        err, encrypted = encrypt_data(b"Hello, World!", key)
        if err != CryptoErrorCode.SUCCESS:
            # Encryption error - stop server communication
            pass
    """
    # Validate key
    if not _validate_key(key):
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Encryption failed",
            f"key must be {AES_KEY_SIZE} bytes (got {len(key) if key else 0})"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Check if crypto library is available
    if not CRYPTO_AVAILABLE:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Encryption failed",
            "pycryptodome not installed (pip install pycryptodome)"
        )
        return CryptoErrorCode.ERR_ENCRYPTION_FAILED, None

    try:
        # Generate random 8-byte nonce for CTR mode
        nonce = derive_nonce()

        # Create cipher and encrypt
        # PyCryptodome CTR: 8-byte nonce + 8-byte counter = 16-byte block
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(data)

        # Prepend 8-byte nonce to ciphertext
        encrypted = nonce + ciphertext

        log_debug(
            logger_handle, CRYPTO_CONTEXT,
            f"Encrypted {len(data)} bytes -> {len(encrypted)} bytes"
        )
        return CryptoErrorCode.SUCCESS, encrypted

    except Exception as e:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Encryption failed",
            str(e)
        )
        return CryptoErrorCode.ERR_ENCRYPTION_FAILED, None


def decrypt_data(
    encrypted_data: bytes,
    key: bytes,
    logger_handle: Optional[object] = None
) -> Tuple[CryptoErrorCode, Optional[bytes]]:
    """
    Decrypt data using AES-128 CTR mode.

    The encrypted input format is: [8-byte nonce][ciphertext]
    The nonce is extracted from the first 8 bytes.

    Args:
        encrypted_data: Data to decrypt (nonce + ciphertext)
        key: 16-byte AES key
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (CryptoErrorCode, plaintext_bytes or None)
        - SUCCESS, decrypted data on success
        - ERR_INVALID_KEY, None if key is wrong size
        - ERR_DECRYPTION_FAILED, None if data too short or decryption fails

    C signature:
        CryptoErrorCode decrypt_data(const uint8_t* encrypted, size_t encrypted_len,
                                      const uint8_t* key, uint8_t** out_decrypted,
                                      size_t* out_len);

    Example:
        err, plaintext = decrypt_data(encrypted_data, key)
        if err != CryptoErrorCode.SUCCESS:
            log_error(handle, "CryptoMod", "Decryption failed", "possible key mismatch")
    """
    # Validate key
    if not _validate_key(key):
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Decryption failed",
            f"key must be {AES_KEY_SIZE} bytes (got {len(key) if key else 0})"
        )
        return CryptoErrorCode.ERR_INVALID_KEY, None

    # Check if crypto library is available
    if not CRYPTO_AVAILABLE:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Decryption failed",
            "pycryptodome not installed (pip install pycryptodome)"
        )
        return CryptoErrorCode.ERR_DECRYPTION_FAILED, None

    # Validate data length (must have at least 8-byte nonce)
    if encrypted_data is None or len(encrypted_data) < AES_CTR_NONCE_SIZE:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Decryption failed",
            f"data too short (need at least {AES_CTR_NONCE_SIZE} bytes for nonce)"
        )
        return CryptoErrorCode.ERR_DECRYPTION_FAILED, None

    try:
        # Extract 8-byte nonce and ciphertext
        nonce = encrypted_data[:AES_CTR_NONCE_SIZE]
        ciphertext = encrypted_data[AES_CTR_NONCE_SIZE:]

        # Create cipher and decrypt
        # PyCryptodome CTR: 8-byte nonce + 8-byte counter = 16-byte block
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        log_debug(
            logger_handle, CRYPTO_CONTEXT,
            f"Decrypted {len(encrypted_data)} bytes -> {len(plaintext)} bytes"
        )
        return CryptoErrorCode.SUCCESS, plaintext

    except Exception as e:
        log_error(
            logger_handle, CRYPTO_CONTEXT,
            "Decryption failed",
            str(e)
        )
        return CryptoErrorCode.ERR_DECRYPTION_FAILED, None


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the crypto module with realistic scenarios.
    """
    print("=" * 60)
    print("crypto.py - Test Suite")
    print("=" * 60)

    # Check if pycryptodome is available
    if not CRYPTO_AVAILABLE:
        print("\nWARNING: pycryptodome not installed.")
        print("Install with: pip install pycryptodome")
        print("Some tests will fail without the crypto library.\n")

    # Test 1: Nonce generation
    print("\n1. Testing derive_nonce()...")
    nonce1 = derive_nonce()
    nonce2 = derive_nonce()
    assert len(nonce1) == AES_CTR_NONCE_SIZE, f"Nonce must be {AES_CTR_NONCE_SIZE} bytes"
    assert nonce1 != nonce2, "Nonces should be unique"
    print(f"   SUCCESS: Generated nonces of {len(nonce1)} bytes")
    print(f"   Nonce 1: {nonce1.hex()}")
    print(f"   Nonce 2: {nonce2.hex()}")

    if CRYPTO_AVAILABLE:
        # Test 2: Encryption/Decryption round-trip
        print("\n2. Testing encrypt_data() and decrypt_data()...")
        test_key = bytes.fromhex("0123456789abcdef0123456789abcdef")
        test_data = b"Hello, QMail Client!"

        err, encrypted = encrypt_data(test_data, test_key)
        assert err == CryptoErrorCode.SUCCESS, f"Encryption failed: {err}"
        assert encrypted is not None
        assert len(encrypted) == len(test_data) + AES_CTR_NONCE_SIZE
        print(f"   Encrypted {len(test_data)} bytes -> {len(encrypted)} bytes")

        err, decrypted = decrypt_data(encrypted, test_key)
        assert err == CryptoErrorCode.SUCCESS, f"Decryption failed: {err}"
        assert decrypted == test_data, "Round-trip failed"
        print(f"   Decrypted back to: {decrypted.decode()}")
        print("   SUCCESS: Round-trip encryption/decryption works")

        # Test 3: Invalid key size
        print("\n3. Testing invalid key handling...")
        err, _ = encrypt_data(test_data, b"short_key")
        assert err == CryptoErrorCode.ERR_INVALID_KEY
        print("   SUCCESS: Invalid key correctly rejected")

        # Test 4: Empty data encryption
        print("\n4. Testing empty data encryption...")
        err, encrypted_empty = encrypt_data(b"", test_key)
        assert err == CryptoErrorCode.SUCCESS
        err, decrypted_empty = decrypt_data(encrypted_empty, test_key)
        assert err == CryptoErrorCode.SUCCESS
        assert decrypted_empty == b""
        print("   SUCCESS: Empty data encryption/decryption works")

        # Test 5: Large data encryption
        print("\n5. Testing large data encryption...")
        large_data = os.urandom(1024 * 100)  # 100 KB
        err, encrypted_large = encrypt_data(large_data, test_key)
        assert err == CryptoErrorCode.SUCCESS
        err, decrypted_large = decrypt_data(encrypted_large, test_key)
        assert err == CryptoErrorCode.SUCCESS
        assert decrypted_large == large_data
        print(f"   SUCCESS: {len(large_data)} bytes encrypted and decrypted")

    else:
        print("\n2-5. SKIPPED: pycryptodome not available")

    # Test 6: Key file loading
    print("\n6. Testing load_key_from_file()...")
    keys_path = _get_keys_path()
    print(f"   Keys path: {keys_path}")

    if os.path.exists(keys_path):
        # Test valid port
        err, key = load_key_from_file(50002)
        if err == CryptoErrorCode.SUCCESS:
            print(f"   SUCCESS: Loaded key for port 50002 ({len(key)} bytes)")
            print(f"   Key: {key.hex()}")
        else:
            print(f"   Key load returned error code: {err}")

        # Test another port
        err, key = load_key_from_file(50014)
        if err == CryptoErrorCode.SUCCESS:
            print(f"   SUCCESS: Loaded key for port 50014 ({len(key)} bytes)")

        # Test invalid port (too low)
        err, key = load_key_from_file(49999)
        assert err == CryptoErrorCode.ERR_INVALID_KEY
        print("   SUCCESS: Port 49999 correctly rejected (out of range)")

        # Test invalid port (too high)
        err, key = load_key_from_file(50025)
        assert err == CryptoErrorCode.ERR_INVALID_KEY
        print("   SUCCESS: Port 50025 correctly rejected (out of range)")

    else:
        print(f"   SKIPPED: {keys_path} not found")
        print("   Create Data/keys.txt with 25 hex keys (32 chars each) to test key loading")

    print("\n" + "=" * 60)
    print("Crypto tests completed!")
    print("=" * 60)
