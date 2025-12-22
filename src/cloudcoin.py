"""
cloudcoin.py - CloudCoin Module for QMail Client Core

This module manages CloudCoin locker keys for server interactions.
Locker keys are used to authenticate and pay for QMail server operations.

Author: Claude Opus 4.5
Phase: I
Version: 1.1.0

Key Storage Format:
    - Files named by denomination: {amount}.locker_keys.txt
    - Examples: 100.locker_keys.txt, 0.1.locker_keys.txt, 1.locker_keys.txt
    - One locker key per line (hex string or base64)
    - Keys are consumed from BOTTOM of file (FIFO)
    - New keys are added to TOP of file

Usage:
    # Get keys for server operations
    keys = get_locker_keys(0.1, count=5)  # Get 5 keys worth 0.1 each

    # Store returned/unused keys
    store_locker_keys(0.1, unused_keys)

C Notes:
    - File I/O with proper locking (flock on Unix, LockFile on Win32)
    - Secure memory handling for keys
    - Thread-safe file access
"""

import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum

# File locking - try portalocker first, fallback to platform-specific
try:
    import portalocker
    HAS_PORTALOCKER = True
except ImportError:
    HAS_PORTALOCKER = False
    import sys
    if sys.platform == 'win32':
        import msvcrt
    else:
        import fcntl

# Import logger
try:
    from .logger import log_error, log_info, log_debug, log_warning
except ImportError:
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")


# ============================================================================
# CONSTANTS
# ============================================================================

# Module context for logging
CC_CONTEXT = "CloudCoin"

# Default data directory for locker key files
DEFAULT_DATA_DIR = "Data"

# Locker key file extension
LOCKER_KEY_EXTENSION = ".locker_keys.txt"

# Standard denominations (CloudCoin values)
DENOMINATIONS = [0.1, 0.25, 1, 5, 25, 100, 250]

# Locker key length (hex string, 16 bytes = 32 hex chars)
LOCKER_KEY_LENGTH = 32

# Maximum keys per file (prevents unbounded growth)
MAX_KEYS_PER_FILE = 10000

# File lock timeout in seconds
FILE_LOCK_TIMEOUT = 5.0


# ============================================================================
# ERROR CODES
# ============================================================================

class CloudCoinErrorCode(IntEnum):
    """
    Error codes for CloudCoin operations.
    C: typedef enum { CC_SUCCESS = 0, ... } CloudCoinErrorCode;
    """
    SUCCESS = 0
    ERR_FILE_NOT_FOUND = 1
    ERR_INSUFFICIENT_KEYS = 2
    ERR_INVALID_KEY = 3
    ERR_IO_ERROR = 4
    ERR_INVALID_AMOUNT = 5
    ERR_INVALID_PARAM = 6
    ERR_FILE_FULL = 7           # File has MAX_KEYS_PER_FILE keys
    ERR_DUPLICATE_KEY = 8       # Key already exists in file
    ERR_LOCK_TIMEOUT = 9        # Could not acquire file lock
    WARN_PARTIAL_SUCCESS = 50   # Partial success (some keys retrieved)
    ERR_NOT_IMPLEMENTED = 99


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class LockerKey:
    """
    Represents a single locker key.
    C: typedef struct LockerKey { ... } LockerKey;
    """
    key: str                    # Hex string (32 chars = 16 bytes)
    amount: float = 0.0         # Denomination value
    used: bool = False          # Whether key has been used


@dataclass
class Locker:
    """
    Represents an open locker (stub for future implementation).
    C: typedef struct Locker { ... } Locker;
    """
    locker_id: str = ""
    balance: int = 0
    coins: List[Any] = field(default_factory=list)
    is_open: bool = False


@dataclass
class CloudCoin:
    """
    Represents a CloudCoin (stub for future implementation).
    C: typedef struct CloudCoin { ... } CloudCoin;
    """
    serial_number: int = 0
    denomination: int = 0
    an: bytes = b''             # Authenticity Number (16 bytes)


@dataclass
class TransactionResult:
    """
    Result of a coin transfer (stub for future implementation).
    C: typedef struct TransactionResult { ... } TransactionResult;
    """
    success: bool = False
    transaction_id: str = ""
    message: str = ""
    coins_transferred: int = 0


@dataclass
class CloudCoinHandle:
    """
    Handle for CloudCoin operations with configuration.
    C: typedef struct CloudCoinHandle { ... } CloudCoinHandle;
    """
    data_dir: str = DEFAULT_DATA_DIR
    mutex: threading.Lock = field(default_factory=threading.Lock)
    logger_handle: Optional[object] = None


# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

def _format_amount(amount: float) -> str:
    """
    Format amount for filename (removes trailing zeros).

    Examples:
        0.1 -> "0.1"
        1.0 -> "1"
        100.0 -> "100"
        0.25 -> "0.25"

    C signature: void format_amount(double amount, char* buffer, size_t size);
    """
    if amount == int(amount):
        return str(int(amount))
    else:
        # Remove trailing zeros but keep at least one decimal place
        return f"{amount:g}"


def _get_locker_file_path(data_dir: str, amount: float) -> str:
    """
    Get full path to locker key file for given amount.

    C signature: void get_locker_file_path(const char* data_dir, double amount, char* path, size_t size);
    """
    filename = f"{_format_amount(amount)}{LOCKER_KEY_EXTENSION}"
    return os.path.join(data_dir, filename)


def _validate_locker_key(key: str) -> bool:
    """
    Validate locker key format.

    Keys must be exactly LOCKER_KEY_LENGTH (32) hex characters.

    C signature: bool validate_locker_key(const char* key);
    """
    if not key or not isinstance(key, str):
        return False

    # Remove whitespace
    key = key.strip()

    if not key:
        return False

    # Check exact length
    if len(key) != LOCKER_KEY_LENGTH:
        return False

    # Check if it's valid hex
    try:
        bytes.fromhex(key)
        return True
    except ValueError:
        return False


def _ensure_data_dir(data_dir: str) -> bool:
    """
    Ensure data directory exists.

    C signature: bool ensure_data_dir(const char* data_dir);
    """
    try:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False


def _lock_file(f, exclusive: bool = True) -> bool:
    """
    Lock a file for exclusive or shared access.

    Args:
        f: File object to lock
        exclusive: True for write lock, False for read lock

    Returns:
        True if locked successfully, False otherwise

    C signature: bool lock_file(FILE* f, bool exclusive);
    """
    try:
        if HAS_PORTALOCKER:
            lock_type = portalocker.LOCK_EX if exclusive else portalocker.LOCK_SH
            portalocker.lock(f, lock_type)
        elif os.name == 'nt':
            # Windows: lock first byte
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK if exclusive else msvcrt.LK_RLCK, 1)
        else:
            # Unix: use fcntl
            lock_type = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(f.fileno(), lock_type)
        return True
    except (IOError, OSError):
        return False


def _unlock_file(f) -> bool:
    """
    Unlock a previously locked file.

    C signature: bool unlock_file(FILE* f);
    """
    try:
        if HAS_PORTALOCKER:
            portalocker.unlock(f)
        elif os.name == 'nt':
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return True
    except (IOError, OSError):
        return False


def _atomic_write_lines(file_path: str, lines: List[str], data_dir: str) -> bool:
    """
    Atomically write lines to a file using temp file + rename.

    This prevents file corruption if the process crashes during write.

    C signature: bool atomic_write_lines(const char* path, char** lines, int count);
    """
    temp_fd = None
    temp_path = None
    try:
        # Create temp file in same directory (for atomic rename)
        temp_fd, temp_path = tempfile.mkstemp(dir=data_dir, suffix='.tmp')
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
            temp_fd = None  # Ownership transferred to fdopen
            for line in lines:
                f.write(line + '\n')

        # Atomic rename (on most filesystems)
        os.replace(temp_path, file_path)

        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # Ignore permission errors (e.g., on Windows)

        return True

    except (IOError, OSError):
        # Clean up temp file on failure
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        return False

    finally:
        # Close temp_fd if fdopen failed
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass


def _set_file_permissions(file_path: str) -> None:
    """
    Set restrictive file permissions (owner read/write only).

    C signature: void set_file_permissions(const char* path);
    """
    try:
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Ignore on platforms where this fails


# ============================================================================
# LOCKER KEY FUNCTIONS (IMPLEMENTED)
# ============================================================================

def init_cloudcoin(
    data_dir: str = DEFAULT_DATA_DIR,
    logger_handle: Optional[object] = None
) -> CloudCoinHandle:
    """
    Initialize CloudCoin module.

    Args:
        data_dir: Directory containing locker key files
        logger_handle: Optional logger handle

    Returns:
        CloudCoinHandle for use with other functions

    C signature:
        CloudCoinHandle* init_cloudcoin(const char* data_dir);

    Example:
        handle = init_cloudcoin("Data")
        keys = get_locker_keys(handle, 0.1, 5)
    """
    _ensure_data_dir(data_dir)

    handle = CloudCoinHandle(
        data_dir=data_dir,
        logger_handle=logger_handle
    )

    log_debug(logger_handle, CC_CONTEXT,
              f"CloudCoin initialized (data_dir={data_dir})")

    return handle


def get_locker_key(
    handle: CloudCoinHandle,
    amount: float
) -> Tuple[CloudCoinErrorCode, Optional[str]]:
    """
    Get a single locker key for the specified amount.

    Reads and removes the LAST line from the locker key file.
    This implements FIFO behavior (oldest keys used first).

    Args:
        handle: CloudCoin handle
        amount: Denomination amount (e.g., 0.1, 1, 100)

    Returns:
        Tuple of (error code, locker key string or None)

    C signature:
        CloudCoinErrorCode get_locker_key(CloudCoinHandle* handle,
                                          double amount,
                                          char* out_key);

    Example:
        err, key = get_locker_key(handle, 0.1)
        if err == CloudCoinErrorCode.SUCCESS:
            # Use key for server request
            send_request(..., locker_key=key)
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, None

    if amount <= 0:
        log_error(handle.logger_handle, CC_CONTEXT,
                  "get_locker_key failed", f"invalid amount: {amount}")
        return CloudCoinErrorCode.ERR_INVALID_AMOUNT, None

    file_path = _get_locker_file_path(handle.data_dir, amount)

    with handle.mutex:
        # Check if file exists
        if not os.path.exists(file_path):
            log_warning(handle.logger_handle, CC_CONTEXT,
                       f"No locker keys available for amount {amount}")
            return CloudCoinErrorCode.ERR_FILE_NOT_FOUND, None

        try:
            # Open with file locking for multi-process safety
            with open(file_path, 'r+', encoding='utf-8') as f:
                if not _lock_file(f, exclusive=True):
                    log_error(handle.logger_handle, CC_CONTEXT,
                             "get_locker_key failed", "could not acquire file lock")
                    return CloudCoinErrorCode.ERR_LOCK_TIMEOUT, None

                try:
                    # Read all lines
                    lines = f.readlines()

                    # Remove empty lines and whitespace
                    lines = [line.strip() for line in lines if line.strip()]

                    if not lines:
                        log_warning(handle.logger_handle, CC_CONTEXT,
                                   f"No locker keys remaining for amount {amount}")
                        return CloudCoinErrorCode.ERR_INSUFFICIENT_KEYS, None

                    # Get the LAST line (FIFO - oldest first)
                    key = lines[-1]

                    # Validate key format
                    if not _validate_locker_key(key):
                        log_error(handle.logger_handle, CC_CONTEXT,
                                 "get_locker_key failed", "invalid key format in file")
                        return CloudCoinErrorCode.ERR_INVALID_KEY, None

                    # Write remaining lines back atomically
                    remaining = lines[:-1]

                finally:
                    _unlock_file(f)

            # Atomic write outside of lock (file is closed)
            if not _atomic_write_lines(file_path, remaining, handle.data_dir):
                log_error(handle.logger_handle, CC_CONTEXT,
                         "get_locker_key failed", "atomic write failed")
                return CloudCoinErrorCode.ERR_IO_ERROR, None

            log_debug(handle.logger_handle, CC_CONTEXT,
                     f"Retrieved locker key for amount {amount} ({len(remaining)} remaining)")

            return CloudCoinErrorCode.SUCCESS, key

        except FileNotFoundError:
            log_warning(handle.logger_handle, CC_CONTEXT,
                       f"No locker keys available for amount {amount}")
            return CloudCoinErrorCode.ERR_FILE_NOT_FOUND, None

        except IOError as e:
            log_error(handle.logger_handle, CC_CONTEXT,
                     "get_locker_key failed", f"IO error: {e}")
            return CloudCoinErrorCode.ERR_IO_ERROR, None


def get_locker_keys(
    handle: CloudCoinHandle,
    amount: float,
    count: int
) -> Tuple[CloudCoinErrorCode, List[str]]:
    """
    Get multiple locker keys for the specified amount.

    Useful when sending requests to multiple QMail servers.
    Each server requires its own unique locker key.

    Args:
        handle: CloudCoin handle
        amount: Denomination amount (e.g., 0.1, 1, 100)
        count: Number of keys needed

    Returns:
        Tuple of (error code, list of locker key strings)
        If fewer keys available than requested, returns what's available
        with ERR_INSUFFICIENT_KEYS error code.

    C signature:
        CloudCoinErrorCode get_locker_keys(CloudCoinHandle* handle,
                                           double amount,
                                           int count,
                                           char** out_keys,
                                           int* out_count);

    Example:
        # Get 25 keys for all RAIDA servers
        err, keys = get_locker_keys(handle, 0.1, 25)
        if err == CloudCoinErrorCode.SUCCESS:
            for server, key in zip(servers, keys):
                send_request(server, locker_key=key)
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, []

    if amount <= 0:
        log_error(handle.logger_handle, CC_CONTEXT,
                  "get_locker_keys failed", f"invalid amount: {amount}")
        return CloudCoinErrorCode.ERR_INVALID_AMOUNT, []

    if count <= 0:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, []

    file_path = _get_locker_file_path(handle.data_dir, amount)

    with handle.mutex:
        # Check if file exists
        if not os.path.exists(file_path):
            log_warning(handle.logger_handle, CC_CONTEXT,
                       f"No locker keys available for amount {amount}")
            return CloudCoinErrorCode.ERR_FILE_NOT_FOUND, []

        try:
            # Open with file locking for multi-process safety
            with open(file_path, 'r+', encoding='utf-8') as f:
                if not _lock_file(f, exclusive=True):
                    log_error(handle.logger_handle, CC_CONTEXT,
                             "get_locker_keys failed", "could not acquire file lock")
                    return CloudCoinErrorCode.ERR_LOCK_TIMEOUT, []

                try:
                    # Read all lines
                    lines = f.readlines()

                    # Remove empty lines and whitespace
                    lines = [line.strip() for line in lines if line.strip()]

                    if not lines:
                        log_warning(handle.logger_handle, CC_CONTEXT,
                                   f"No locker keys remaining for amount {amount}")
                        return CloudCoinErrorCode.ERR_INSUFFICIENT_KEYS, []

                    # Determine how many keys we can get
                    available = len(lines)
                    keys_to_get = min(count, available)

                    # Get keys from the END of the list (FIFO - oldest first)
                    keys = lines[-keys_to_get:]

                    # Validate all keys
                    valid_keys = []
                    for key in keys:
                        if _validate_locker_key(key):
                            valid_keys.append(key)
                        else:
                            log_warning(handle.logger_handle, CC_CONTEXT,
                                       "Skipping invalid key format")

                    if not valid_keys:
                        return CloudCoinErrorCode.ERR_INVALID_KEY, []

                    # Remaining lines (all except the ones we took)
                    remaining = lines[:-keys_to_get] if keys_to_get < len(lines) else []

                finally:
                    _unlock_file(f)

            # Atomic write outside of lock (file is closed)
            if not _atomic_write_lines(file_path, remaining, handle.data_dir):
                log_error(handle.logger_handle, CC_CONTEXT,
                         "get_locker_keys failed", "atomic write failed")
                return CloudCoinErrorCode.ERR_IO_ERROR, []

            log_debug(handle.logger_handle, CC_CONTEXT,
                     f"Retrieved {len(valid_keys)} locker keys for amount {amount} "
                     f"({len(remaining)} remaining)")

            # Check if we got enough - use WARN_PARTIAL_SUCCESS for partial results
            if len(valid_keys) < count:
                log_warning(handle.logger_handle, CC_CONTEXT,
                           f"Only {len(valid_keys)} keys available, {count} requested")
                return CloudCoinErrorCode.WARN_PARTIAL_SUCCESS, valid_keys

            return CloudCoinErrorCode.SUCCESS, valid_keys

        except FileNotFoundError:
            log_warning(handle.logger_handle, CC_CONTEXT,
                       f"No locker keys available for amount {amount}")
            return CloudCoinErrorCode.ERR_FILE_NOT_FOUND, []

        except IOError as e:
            log_error(handle.logger_handle, CC_CONTEXT,
                     "get_locker_keys failed", f"IO error: {e}")
            return CloudCoinErrorCode.ERR_IO_ERROR, []


def store_locker_key(
    handle: CloudCoinHandle,
    amount: float,
    key: str
) -> CloudCoinErrorCode:
    """
    Store a locker key back to the file.

    Adds the key to the TOP of the file (prepends).
    Creates the file if it doesn't exist.

    Args:
        handle: CloudCoin handle
        amount: Denomination amount
        key: Locker key string to store

    Returns:
        Error code

    C signature:
        CloudCoinErrorCode store_locker_key(CloudCoinHandle* handle,
                                            double amount,
                                            const char* key);

    Example:
        # Store unused key back
        store_locker_key(handle, 0.1, unused_key)
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM

    if amount <= 0:
        log_error(handle.logger_handle, CC_CONTEXT,
                  "store_locker_key failed", f"invalid amount: {amount}")
        return CloudCoinErrorCode.ERR_INVALID_AMOUNT

    if not key:
        return CloudCoinErrorCode.ERR_INVALID_PARAM

    # Clean the key
    key = key.strip()

    if not _validate_locker_key(key):
        log_error(handle.logger_handle, CC_CONTEXT,
                 "store_locker_key failed", "invalid key format")
        return CloudCoinErrorCode.ERR_INVALID_KEY

    file_path = _get_locker_file_path(handle.data_dir, amount)

    with handle.mutex:
        try:
            # Ensure directory exists
            _ensure_data_dir(handle.data_dir)

            # Read existing lines (if file exists) with file locking
            existing_lines = []
            if os.path.exists(file_path):
                with open(file_path, 'r+', encoding='utf-8') as f:
                    if not _lock_file(f, exclusive=True):
                        log_error(handle.logger_handle, CC_CONTEXT,
                                 "store_locker_key failed", "could not acquire file lock")
                        return CloudCoinErrorCode.ERR_LOCK_TIMEOUT
                    try:
                        existing_lines = [line.strip() for line in f.readlines() if line.strip()]
                    finally:
                        _unlock_file(f)

            # Check file size limit
            if len(existing_lines) >= MAX_KEYS_PER_FILE:
                log_error(handle.logger_handle, CC_CONTEXT,
                         "store_locker_key failed", f"file full ({MAX_KEYS_PER_FILE} keys)")
                return CloudCoinErrorCode.ERR_FILE_FULL

            # Check for duplicate key
            if key in existing_lines:
                log_warning(handle.logger_handle, CC_CONTEXT,
                           "Duplicate key detected - not storing")
                return CloudCoinErrorCode.ERR_DUPLICATE_KEY

            # Prepend new key to TOP
            all_lines = [key] + existing_lines

            # Atomic write
            if not _atomic_write_lines(file_path, all_lines, handle.data_dir):
                log_error(handle.logger_handle, CC_CONTEXT,
                         "store_locker_key failed", "atomic write failed")
                return CloudCoinErrorCode.ERR_IO_ERROR

            log_debug(handle.logger_handle, CC_CONTEXT,
                     f"Stored locker key for amount {amount} ({len(all_lines)} total)")

            return CloudCoinErrorCode.SUCCESS

        except IOError as e:
            log_error(handle.logger_handle, CC_CONTEXT,
                     "store_locker_key failed", f"IO error: {e}")
            return CloudCoinErrorCode.ERR_IO_ERROR


def store_locker_keys(
    handle: CloudCoinHandle,
    amount: float,
    keys: List[str]
) -> Tuple[CloudCoinErrorCode, int]:
    """
    Store multiple locker keys back to the file.

    Adds keys to the TOP of the file (prepends).
    Keys are reversed internally for FIFO behavior: the first key
    in the list will be at the BOTTOM (retrieved first).

    Args:
        handle: CloudCoin handle
        amount: Denomination amount
        keys: List of locker key strings to store

    Returns:
        Tuple of (error code, number of keys successfully stored)

    C signature:
        CloudCoinErrorCode store_locker_keys(CloudCoinHandle* handle,
                                             double amount,
                                             const char** keys,
                                             int count,
                                             int* out_stored);

    Example:
        # Store unused keys back
        err, stored = store_locker_keys(handle, 0.1, unused_keys)
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, 0

    if amount <= 0:
        log_error(handle.logger_handle, CC_CONTEXT,
                  "store_locker_keys failed", f"invalid amount: {amount}")
        return CloudCoinErrorCode.ERR_INVALID_AMOUNT, 0

    if not keys:
        return CloudCoinErrorCode.SUCCESS, 0

    # Validate and clean keys
    valid_keys = []
    for key in keys:
        key = key.strip() if key else ""
        if _validate_locker_key(key):
            valid_keys.append(key)
        else:
            log_warning(handle.logger_handle, CC_CONTEXT,
                       "Skipping invalid key during store")

    if not valid_keys:
        return CloudCoinErrorCode.ERR_INVALID_KEY, 0

    file_path = _get_locker_file_path(handle.data_dir, amount)

    with handle.mutex:
        try:
            # Ensure directory exists
            _ensure_data_dir(handle.data_dir)

            # Read existing lines (if file exists) with file locking
            existing_lines = []
            if os.path.exists(file_path):
                with open(file_path, 'r+', encoding='utf-8') as f:
                    if not _lock_file(f, exclusive=True):
                        log_error(handle.logger_handle, CC_CONTEXT,
                                 "store_locker_keys failed", "could not acquire file lock")
                        return CloudCoinErrorCode.ERR_LOCK_TIMEOUT, 0
                    try:
                        existing_lines = [line.strip() for line in f.readlines() if line.strip()]
                    finally:
                        _unlock_file(f)

            # Check file size limit
            space_available = MAX_KEYS_PER_FILE - len(existing_lines)
            if space_available <= 0:
                log_error(handle.logger_handle, CC_CONTEXT,
                         "store_locker_keys failed", f"file full ({MAX_KEYS_PER_FILE} keys)")
                return CloudCoinErrorCode.ERR_FILE_FULL, 0

            # Filter out duplicates
            existing_set = set(existing_lines)
            unique_keys = []
            duplicates_skipped = 0
            for key in valid_keys:
                if key in existing_set:
                    duplicates_skipped += 1
                    log_warning(handle.logger_handle, CC_CONTEXT,
                               "Skipping duplicate key during store")
                else:
                    unique_keys.append(key)
                    existing_set.add(key)  # Prevent duplicates within batch

            if duplicates_skipped > 0 and not unique_keys:
                return CloudCoinErrorCode.ERR_DUPLICATE_KEY, 0

            # Limit to available space
            if len(unique_keys) > space_available:
                log_warning(handle.logger_handle, CC_CONTEXT,
                           f"Only storing {space_available} of {len(unique_keys)} keys (file limit)")
                unique_keys = unique_keys[:space_available]

            if not unique_keys:
                return CloudCoinErrorCode.SUCCESS, 0

            # Prepend new keys to TOP (reversed for FIFO)
            # First key in list ends up at bottom, last key at top
            # This ensures FIFO: first stored -> first retrieved (from bottom)
            all_lines = list(reversed(unique_keys)) + existing_lines

            # Atomic write
            if not _atomic_write_lines(file_path, all_lines, handle.data_dir):
                log_error(handle.logger_handle, CC_CONTEXT,
                         "store_locker_keys failed", "atomic write failed")
                return CloudCoinErrorCode.ERR_IO_ERROR, 0

            log_debug(handle.logger_handle, CC_CONTEXT,
                     f"Stored {len(unique_keys)} locker keys for amount {amount} "
                     f"({len(all_lines)} total)")

            return CloudCoinErrorCode.SUCCESS, len(unique_keys)

        except IOError as e:
            log_error(handle.logger_handle, CC_CONTEXT,
                     "store_locker_keys failed", f"IO error: {e}")
            return CloudCoinErrorCode.ERR_IO_ERROR, 0


def get_available_key_count(
    handle: CloudCoinHandle,
    amount: float
) -> Tuple[CloudCoinErrorCode, int]:
    """
    Get count of available locker keys for an amount.

    Args:
        handle: CloudCoin handle
        amount: Denomination amount

    Returns:
        Tuple of (error code, count)

    C signature:
        CloudCoinErrorCode get_available_key_count(CloudCoinHandle* handle,
                                                   double amount,
                                                   int* out_count);
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, 0

    if amount <= 0:
        return CloudCoinErrorCode.ERR_INVALID_AMOUNT, 0

    file_path = _get_locker_file_path(handle.data_dir, amount)

    with handle.mutex:
        if not os.path.exists(file_path):
            return CloudCoinErrorCode.SUCCESS, 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            return CloudCoinErrorCode.SUCCESS, len(lines)

        except IOError as e:
            log_error(handle.logger_handle, CC_CONTEXT,
                     "get_available_key_count failed", f"IO error: {e}")
            return CloudCoinErrorCode.ERR_IO_ERROR, 0


def list_available_denominations(
    handle: CloudCoinHandle
) -> Tuple[CloudCoinErrorCode, List[Tuple[float, int]]]:
    """
    List all denominations with available keys.

    Returns:
        Tuple of (error code, list of (amount, count) tuples)

    C signature:
        CloudCoinErrorCode list_available_denominations(CloudCoinHandle* handle,
                                                        DenominationInfo** out_info,
                                                        int* out_count);
    """
    if handle is None:
        return CloudCoinErrorCode.ERR_INVALID_PARAM, []

    results = []

    try:
        # List all .locker_keys.txt files in data directory
        if not os.path.exists(handle.data_dir):
            return CloudCoinErrorCode.SUCCESS, []

        for filename in os.listdir(handle.data_dir):
            if filename.endswith(LOCKER_KEY_EXTENSION):
                # Extract amount from filename
                amount_str = filename[:-len(LOCKER_KEY_EXTENSION)]
                try:
                    amount = float(amount_str)
                    err, count = get_available_key_count(handle, amount)
                    if err == CloudCoinErrorCode.SUCCESS and count > 0:
                        results.append((amount, count))
                except ValueError:
                    continue

        # Sort by amount
        results.sort(key=lambda x: x[0])

        return CloudCoinErrorCode.SUCCESS, results

    except OSError as e:
        log_error(handle.logger_handle, CC_CONTEXT,
                 "list_available_denominations failed", f"OS error: {e}")
        return CloudCoinErrorCode.ERR_IO_ERROR, []


# ============================================================================
# STUB FUNCTIONS (For future implementation)
# ============================================================================

def open_locker(
    handle: CloudCoinHandle,
    locker_key: str
) -> Tuple[CloudCoinErrorCode, Optional[Locker]]:
    """
    Open a locker using the provided key.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        locker_key: Key to open the locker

    Returns:
        Tuple of (error code, Locker object or None)

    C signature:
        CloudCoinErrorCode open_locker(CloudCoinHandle* handle,
                                       const char* locker_key,
                                       Locker** out_locker);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "open_locker is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED, None


def close_locker(
    handle: CloudCoinHandle,
    locker: Locker
) -> CloudCoinErrorCode:
    """
    Close an open locker.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        locker: Locker to close

    Returns:
        Error code

    C signature:
        CloudCoinErrorCode close_locker(CloudCoinHandle* handle,
                                        Locker* locker);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "close_locker is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED


def get_coin_balance(
    handle: CloudCoinHandle,
    locker: Locker
) -> Tuple[CloudCoinErrorCode, int]:
    """
    Get the coin balance in a locker.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        locker: Open locker

    Returns:
        Tuple of (error code, balance)

    C signature:
        CloudCoinErrorCode get_coin_balance(CloudCoinHandle* handle,
                                            const Locker* locker,
                                            int* out_balance);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "get_coin_balance is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED, 0


def withdraw_coins(
    handle: CloudCoinHandle,
    locker: Locker,
    amount: int
) -> Tuple[CloudCoinErrorCode, List[CloudCoin]]:
    """
    Withdraw coins from a locker.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        locker: Open locker
        amount: Amount to withdraw

    Returns:
        Tuple of (error code, list of CloudCoin objects)

    C signature:
        CloudCoinErrorCode withdraw_coins(CloudCoinHandle* handle,
                                          Locker* locker,
                                          int amount,
                                          CloudCoin** out_coins,
                                          int* out_count);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "withdraw_coins is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED, []


def deposit_coins(
    handle: CloudCoinHandle,
    locker: Locker,
    coins: List[CloudCoin]
) -> CloudCoinErrorCode:
    """
    Deposit coins into a locker.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        locker: Open locker
        coins: Coins to deposit

    Returns:
        Error code

    C signature:
        CloudCoinErrorCode deposit_coins(CloudCoinHandle* handle,
                                         Locker* locker,
                                         const CloudCoin* coins,
                                         int count);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "deposit_coins is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED


def validate_coin(
    handle: CloudCoinHandle,
    coin: CloudCoin
) -> Tuple[CloudCoinErrorCode, bool]:
    """
    Validate a CloudCoin.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        coin: Coin to validate

    Returns:
        Tuple of (error code, is_valid)

    C signature:
        CloudCoinErrorCode validate_coin(CloudCoinHandle* handle,
                                         const CloudCoin* coin,
                                         bool* out_valid);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "validate_coin is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED, False


def transfer_coins(
    handle: CloudCoinHandle,
    coins: List[CloudCoin],
    destination: str
) -> Tuple[CloudCoinErrorCode, TransactionResult]:
    """
    Transfer coins to a destination.

    STUB: To be implemented with specialized CloudCoin software.

    Args:
        handle: CloudCoin handle
        coins: Coins to transfer
        destination: Destination address/locker

    Returns:
        Tuple of (error code, TransactionResult)

    C signature:
        CloudCoinErrorCode transfer_coins(CloudCoinHandle* handle,
                                          const CloudCoin* coins,
                                          int count,
                                          const char* destination,
                                          TransactionResult* out_result);
    """
    log_warning(handle.logger_handle if handle else None, CC_CONTEXT,
               "transfer_coins is a stub - not implemented")
    return CloudCoinErrorCode.ERR_NOT_IMPLEMENTED, TransactionResult()


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the cloudcoin module.
    """
    import tempfile
    import shutil

    print("=" * 60)
    print("cloudcoin.py - Test Suite")
    print("=" * 60)

    # Create temp directory for tests
    test_dir = tempfile.mkdtemp(prefix="cloudcoin_test_")
    print(f"\nUsing temp directory: {test_dir}")

    try:
        # Test 1: Initialize
        print("\n1. Testing init_cloudcoin()...")
        handle = init_cloudcoin(data_dir=test_dir)
        assert handle is not None
        assert handle.data_dir == test_dir
        print("   SUCCESS: CloudCoin initialized")

        # Test 2: Format amount
        print("\n2. Testing _format_amount()...")
        assert _format_amount(0.1) == "0.1"
        assert _format_amount(1.0) == "1"
        assert _format_amount(100.0) == "100"
        assert _format_amount(0.25) == "0.25"
        print("   SUCCESS: Amount formatting works")

        # Test 3: Store single key
        print("\n3. Testing store_locker_key()...")
        test_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"  # 32 hex chars
        err = store_locker_key(handle, 0.1, test_key)
        assert err == CloudCoinErrorCode.SUCCESS
        print("   SUCCESS: Single key stored")

        # Test 4: Get single key
        print("\n4. Testing get_locker_key()...")
        err, key = get_locker_key(handle, 0.1)
        assert err == CloudCoinErrorCode.SUCCESS
        assert key == test_key
        print(f"   Retrieved: {key[:8]}...")
        print("   SUCCESS: Single key retrieved")

        # Test 5: Get key from empty file
        print("\n5. Testing get_locker_key() on empty...")
        err, key = get_locker_key(handle, 0.1)
        assert err == CloudCoinErrorCode.ERR_INSUFFICIENT_KEYS
        assert key is None
        print("   SUCCESS: Empty file handled correctly")

        # Test 6: Store multiple keys (32 hex chars each)
        print("\n6. Testing store_locker_keys()...")
        test_keys = [
            f"1111111111111111111111111111{i:04x}"
            for i in range(5)
        ]
        err, stored = store_locker_keys(handle, 1.0, test_keys)
        assert err == CloudCoinErrorCode.SUCCESS
        assert stored == 5
        print(f"   Stored {stored} keys")
        print("   SUCCESS: Multiple keys stored")

        # Test 7: Get multiple keys
        print("\n7. Testing get_locker_keys()...")
        err, keys = get_locker_keys(handle, 1.0, 3)
        assert err == CloudCoinErrorCode.SUCCESS
        assert len(keys) == 3
        # Keys should come from the END (FIFO - oldest first)
        # We stored [0,1,2,3,4], get 3 from end = [2,3,4]
        print(f"   Retrieved {len(keys)} keys")
        print("   SUCCESS: Multiple keys retrieved")

        # Test 8: Verify remaining keys
        print("\n8. Testing remaining keys...")
        err, count = get_available_key_count(handle, 1.0)
        assert err == CloudCoinErrorCode.SUCCESS
        assert count == 2  # 5 - 3 = 2 remaining
        print(f"   Remaining: {count}")
        print("   SUCCESS: Key count correct")

        # Test 9: Get more keys than available (partial success)
        print("\n9. Testing get_locker_keys() with insufficient...")
        err, keys = get_locker_keys(handle, 1.0, 10)
        assert err == CloudCoinErrorCode.WARN_PARTIAL_SUCCESS
        assert len(keys) == 2  # Returns what's available
        print(f"   Got {len(keys)} keys (requested 10)")
        print("   SUCCESS: Partial success handled correctly")

        # Test 10: File not found
        print("\n10. Testing file not found...")
        err, key = get_locker_key(handle, 999.0)
        assert err == CloudCoinErrorCode.ERR_FILE_NOT_FOUND
        print("   SUCCESS: File not found handled correctly")

        # Test 11: Invalid amount
        print("\n11. Testing invalid amount...")
        err, key = get_locker_key(handle, -1.0)
        assert err == CloudCoinErrorCode.ERR_INVALID_AMOUNT
        print("   SUCCESS: Invalid amount handled correctly")

        # Test 12: Invalid key format
        print("\n12. Testing invalid key format...")
        err = store_locker_key(handle, 0.1, "not-hex-string!")
        assert err == CloudCoinErrorCode.ERR_INVALID_KEY
        print("   SUCCESS: Invalid key rejected")

        # Test 13: List available denominations
        print("\n13. Testing list_available_denominations()...")
        # Store some keys for different denominations (32 hex chars each)
        store_locker_key(handle, 0.1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        store_locker_key(handle, 0.1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02")
        store_locker_key(handle, 100, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

        err, denoms = list_available_denominations(handle)
        assert err == CloudCoinErrorCode.SUCCESS
        assert len(denoms) >= 2
        print(f"   Available denominations: {denoms}")
        print("   SUCCESS: Denominations listed")

        # Test 14: FIFO behavior verification
        print("\n14. Testing FIFO behavior...")
        # Clear and store fresh keys - use valid hex keys
        # Keys stored at TOP in order: first, second, third
        # File will be: third (line 1), second (line 2), first (line 3)
        # FIFO retrieves from BOTTOM: first, then second, then third
        first_key = "11111111111111111111111111111111"
        second_key = "22222222222222222222222222222222"
        third_key = "33333333333333333333333333333333"

        err, stored = store_locker_keys(handle, 5.0, [first_key, second_key, third_key])
        assert err == CloudCoinErrorCode.SUCCESS
        assert stored == 3

        # Get one key - should get "first_key" (first stored, at bottom of file)
        err, key = get_locker_key(handle, 5.0)
        assert err == CloudCoinErrorCode.SUCCESS
        assert key == first_key, f"Expected first_key, got {key}"
        # Get next - should get "second_key"
        err, key = get_locker_key(handle, 5.0)
        assert err == CloudCoinErrorCode.SUCCESS
        assert key == second_key, f"Expected second_key, got {key}"
        # Get last - should get "third_key"
        err, key = get_locker_key(handle, 5.0)
        assert err == CloudCoinErrorCode.SUCCESS
        assert key == third_key, f"Expected third_key, got {key}"
        print("   SUCCESS: FIFO behavior verified")

        # Test 15: Stub functions
        print("\n15. Testing stub functions...")
        err, locker = open_locker(handle, "test")
        assert err == CloudCoinErrorCode.ERR_NOT_IMPLEMENTED
        err = close_locker(handle, Locker())
        assert err == CloudCoinErrorCode.ERR_NOT_IMPLEMENTED
        print("   SUCCESS: Stubs return NOT_IMPLEMENTED")

        # Test 16: Key validation (now enforces exact 32-char length)
        print("\n16. Testing key validation...")
        assert _validate_locker_key("abcdef1234567890abcdef1234567890")  # Valid 32-char hex
        assert _validate_locker_key("ABCDEF1234567890ABCDEF1234567890")  # Valid uppercase
        assert not _validate_locker_key("")  # Empty
        assert not _validate_locker_key("not-hex!")  # Invalid chars
        assert not _validate_locker_key("abcd1234")  # Too short (8 chars)
        assert not _validate_locker_key("abcdef1234567890abcdef1234567890ff")  # Too long (34 chars)
        print("   SUCCESS: Key validation works (including length check)")

        # Test 17: Duplicate key detection
        print("\n17. Testing duplicate key detection...")
        unique_key = "44444444444444444444444444444444"
        err = store_locker_key(handle, 7.0, unique_key)
        assert err == CloudCoinErrorCode.SUCCESS
        # Try to store same key again
        err = store_locker_key(handle, 7.0, unique_key)
        assert err == CloudCoinErrorCode.ERR_DUPLICATE_KEY
        print("   SUCCESS: Duplicate key rejected")

        # Test 18: Concurrent access (multi-threading)
        print("\n18. Testing concurrent access...")
        import concurrent.futures

        # Store 50 unique keys
        concurrent_keys = [f"{i:032x}" for i in range(100, 150)]
        err, stored = store_locker_keys(handle, 8.0, concurrent_keys)
        assert err == CloudCoinErrorCode.SUCCESS
        assert stored == 50

        # Retrieve keys concurrently from multiple threads
        retrieved_keys = []
        errors = []

        def get_key_thread():
            err, key = get_locker_key(handle, 8.0)
            return (err, key)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(get_key_thread) for _ in range(50)]
            for future in concurrent.futures.as_completed(futures):
                err, key = future.result()
                if err == CloudCoinErrorCode.SUCCESS:
                    retrieved_keys.append(key)
                else:
                    errors.append(err)

        # All keys should be unique (no duplicates retrieved)
        assert len(retrieved_keys) == len(set(retrieved_keys)), "Duplicate keys retrieved!"
        assert len(retrieved_keys) == 50, f"Expected 50 keys, got {len(retrieved_keys)}"
        print(f"   Retrieved {len(retrieved_keys)} unique keys concurrently")
        print("   SUCCESS: Concurrent access is thread-safe")

        print("\n" + "=" * 60)
        print("All cloudcoin tests passed! (18 tests)")
        print("=" * 60)

    finally:
        # Cleanup temp directory
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\nCleaned up temp directory: {test_dir}")
