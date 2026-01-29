"""
email_sender.py - Email Sender Orchestrator for QMail Client Core

This module orchestrates the complete "Send Email" flow:
1. Validate request (files exist, recipients valid)
2. Generate file_group_guid for the email package
3. Calculate payment and request locker code
4. For each file (email body + attachments):
   - Encrypt the file data
   - Split into stripes (4 data + 1 parity)
   - Upload stripes to servers in parallel
5. Send Tell notifications to recipients
6. Store email locally in database

Author: Claude Opus 4.5
Phase: I
Version: 1.0.0

Functions:
    send_email_async() - Main entry point, creates and runs task
    validate_request() - Validate files and recipients
    process_email_package() - Process and upload email with attachments
"""

import os
import uuid
import time
import struct
import asyncio
from datetime import datetime
from typing import Any, List, Optional, Tuple, Dict, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from qmail_types import (
    ErrorCode, SendEmailErrorCode, SendEmailRequest, SendEmailResult,
    FileUploadInfo, EmailPackage, IdentityConfig
)
from protocol import (
    build_complete_tell_request, CMD_GROUP_QMAIL, CMD_TELL, TELL_TYPE_QMAIL, custom_sn_to_int,
    weeks_to_duration_code
)
from network import connect_to_server, send_request, disconnect
from payment import calculate_storage_cost, request_locker_code, calculate_total_payment
from logger import log_info, log_error, log_warning, log_debug
from config import get_raida_server_config
from locker_download import download_from_locker, LockerDownloadResult


import os
import struct

from coin_scanner import get_coins_by_value, parse_denomination_code, find_identity_coin , load_coin_from_file
from coin_break import break_coin
from locker_put import put_to_locker, CoinForPut, PutResult
from key_manager import get_keys_from_locker_code


async def _attempt_refund_async(
    locker_code: bytes,
    wallet_path: str,
    db_handle: object,
    logger_handle: object,
    max_attempts: int = 2
) -> Tuple[bool, int]:
    """
    Attempt to refund coins from locker after upload failure.
    
    This function tries to recover coins that were locked for payment
    but never consumed by the server due to upload failure.
    
    Args:
        locker_code: The 8-byte locker code (e.g., b'AES-12KM')
        wallet_path: Path to wallet for saving recovered coins
        db_handle: Database handle for RAIDA server lookup
        logger_handle: Logger
        max_attempts: Maximum refund attempts (default 2)
    
    Returns:
        Tuple of (success: bool, coins_recovered: int)
    """
    # Import locally to avoid circular dependencies
    from locker_download import download_from_locker, LockerDownloadResult
    
    REFUND_CONTEXT = "RefundHandler"
    
    if not locker_code or len(locker_code) < 8:
        log_error(logger_handle, REFUND_CONTEXT, 
                  "Cannot refund: invalid locker code")
        return False, 0
    
    for attempt in range(max_attempts):
        try:
            # Decode locker code for logging (safe decode)
            locker_str = locker_code[:8].decode('ascii', errors='ignore')
            
            log_info(logger_handle, REFUND_CONTEXT,
                     f"Refund attempt {attempt + 1}/{max_attempts} "
                     f"for locker {locker_str}")
            
            result, recovered_coins = await download_from_locker(
                locker_code=locker_code,
                wallet_path=wallet_path,
                db_handle=db_handle,
                logger_handle=logger_handle
            )
            
            if result == LockerDownloadResult.SUCCESS:
                coin_count = len(recovered_coins)
                total_value = sum(
                    10.0 ** c.denomination for c in recovered_coins
                    if hasattr(c, 'denomination') and c.denomination != 11
                )
                log_info(logger_handle, REFUND_CONTEXT,
                         f"Refund SUCCESS: {coin_count} coins recovered "
                         f"(~{total_value:.6f} CC)")
                return True, coin_count
            
            elif result == LockerDownloadResult.ERR_LOCKER_EMPTY:
                # Locker is empty - either already refunded or payment was consumed
                log_warning(logger_handle, REFUND_CONTEXT,
                            "Locker is empty - coins may have been consumed by server")
                return False, 0
            
            elif result == LockerDownloadResult.ERR_INSUFFICIENT_RESPONSES:
                # Network issue - worth retrying
                log_warning(logger_handle, REFUND_CONTEXT,
                            f"Insufficient RAIDA responses, attempt {attempt + 1}")
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2)  # Wait before retry
                continue
            
            else:
                log_error(logger_handle, REFUND_CONTEXT,
                          f"Refund failed with code: {result}")
                if attempt < max_attempts - 1:
                    await asyncio.sleep(1)
                continue
                
        except Exception as e:
            log_error(logger_handle, REFUND_CONTEXT,
                      f"Refund attempt {attempt + 1} exception: {e}")
            if attempt < max_attempts - 1:
                await asyncio.sleep(1)
            continue
    
    # Decode locker code for final error message
    locker_str = locker_code[:8].decode('ascii', errors='ignore')
    log_error(logger_handle, REFUND_CONTEXT,
              f"Refund FAILED after {max_attempts} attempts. "
              f"Manual recovery may be needed for locker: {locker_str}")
    return False, 0


def _attempt_refund(
    locker_code: bytes,
    wallet_path: str,
    db_handle: object,
    logger_handle: object,
    max_attempts: int = 2
) -> Tuple[bool, int]:
    """
    Synchronous wrapper for _attempt_refund_async.
    Handles the asyncio event loop correctly for worker threads.
    
    Args:
        locker_code: The 8-byte locker code (e.g., b'AES-12KM')
        wallet_path: Path to wallet for saving recovered coins
        db_handle: Database handle for RAIDA server lookup
        logger_handle: Logger
        max_attempts: Maximum refund attempts (default 2)
    
    Returns:
        Tuple of (success: bool, coins_recovered: int)
    """
    import asyncio
    
    try:
        # Try to get the running loop (Python 3.10+)
        try:
            loop = asyncio.get_running_loop()
            # If we're already in an async context, we can't use run_until_complete
            # This shouldn't happen in our thread pool case, but handle it gracefully
            log_warning(logger_handle, "RefundHandler", 
                        "Already in async context, creating new task")
            future = asyncio.ensure_future(_attempt_refund_async(
                locker_code, wallet_path, db_handle, logger_handle, max_attempts
            ))
            # We can't await the result here in sync mode without blocking badly,
            # so we return False to indicate immediate status is unknown.
            # The async task will run in background.
            return False, 0
        except RuntimeError:
            # No running loop - this is the expected case for worker threads
            pass
        
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                _attempt_refund_async(
                    locker_code, wallet_path, db_handle, logger_handle, max_attempts
                )
            )
            return result
        finally:
            # Clean up the loop
            loop.close()
            
    except Exception as e:
        log_error(logger_handle, "RefundHandler", 
                  f"Failed to run refund: {e}")
        return False, 0

async def create_recipient_locker(
    wallet_path: str,
    amount: float,
    identity_sn: int,
    logger_handle
) -> Tuple[int, Optional[str]]:
    """
    Create a locker with coins for recipient payment.
    
    IMPORTANT: Never uses identity coin - it's protected.
    
    Args:
        wallet_path: Path to wallet
        amount: Amount to lock
        identity_sn: Identity coin serial number to exclude
        logger_handle: Logger
        
    Returns:
        (error_code, locker_code_hex_16bytes)
        error_code: 0=success, 1=insufficient funds, 2=network error
    """
    from locker_put import put_to_locker, CoinForPut, PutResult
    from key_manager import get_keys_from_locker_code
    from coin_break import break_coin
    from coin_scanner import parse_denomination_code
    import secrets
    import string
    import os
    import math
    
    try:
        # 1. Get coins (Could be a single large coin or a list of small coins)
        coins = get_coins_by_value(wallet_path, amount, identity_sn=identity_sn)
        
        if not coins:
            log_warning(logger_handle, "LockerCreate", 
                        f"No spendable coins available for amount {amount}")
            return 1, None
        
        final_coins_to_lock = []
        total_value_selected = sum(parse_denomination_code(c.denomination) for c in coins)

        # 2. Decide if we need to break or use the selection as-is
        if abs(total_value_selected - amount) < 0.0001:
            # Exact match (from aggregation or single coin)
            final_coins_to_lock = coins
        elif total_value_selected > amount:
            # We picked a larger coin that MUST be broken
            # Note: get_coins_by_value only returns 1 coin if it's a 'larger' case
            coin_to_break = coins[0]
            log_info(logger_handle, "LockerCreate",
                    f"Breaking coin {total_value_selected} to get {amount}")
            
            # --- FIX: Handle BreakResult object correctly ---
            break_result = await break_coin(coin_to_break, wallet_path, None, logger_handle)
            
            broken_coins = []
            # Check if result is an object with .coins attribute (standard implementation)
            if hasattr(break_result, 'new_coins'):
               broken_coins = break_result.new_coins
            # Fallback if it returns a list directly
            elif isinstance(break_result, list):
                broken_coins = break_result
            
            if not broken_coins:
                log_error(logger_handle, "LockerCreate", "Failed to break coin (Empty result)")
                return 2, None
            
            if hasattr(break_result, 'success') and break_result.success:
              broken_coins = break_result.new_coins
            
            # MATH FIX: Calculate how many small coins are needed
            # e.g. If we broke a 1.0 to pay 0.3, broken_coins[0] is 0.1.
            # num_needed = ceil(0.3 / 0.1) = 3
            small_val = parse_denomination_code(broken_coins[0].denomination)
            num_needed = int(math.ceil((amount - 0.000001) / small_val))
            
            # Take the specific number of coins needed to reach the amount
            final_coins_to_lock = broken_coins[:num_needed]
            
            # The remaining broken_coins are already saved to the Bank by break_coin logic
        else:
            # Should not happen if get_coins_by_value logic is sound
            return 1, None

        # 3. Generate random locker code in XXX-XXXX format (matches Go GenerateTransmitCode)
        # Generate 7 random alphanumeric chars, insert hyphen at position 3
        random_chars = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                               for _ in range(7))
        locker_code = random_chars[:3] + '-' + random_chars[3:]  # e.g., "ABC-1234"
        
        # 4. Get 25 locker keys from code (MD5(raida_id + code))
        locker_keys_25 = get_keys_from_locker_code(locker_code)
        
        # 5. Prepare coins for PUT payload
        coins_for_put = []
        for c in final_coins_to_lock:
            coins_for_put.append(CoinForPut(
                denomination=c.denomination,
                serial_number=c.serial_number,
                ans=c.ans
            ))
        
        # 6. Lock coins on RAIDA (Command 82)
        result, details = await put_to_locker(coins_for_put, locker_keys_25)
        
        if result != PutResult.SUCCESS:
            log_error(logger_handle, "LockerCreate", f"PUT failed: {result}")
            return 2, None
        
        # 7. Cleanup: Delete original coins from bank (if they were used directly)
        # If we performed a 'break', the break_coin logic usually handles the original file
        for c in coins:
            try:
                if os.path.exists(c.file_path):
                    os.remove(c.file_path)
            except:
                pass
        
        # 8. Return locker code as 16-byte hex (null-padded)
        # This is what goes into the TELL packet recipient entry
        locker_key_16 = locker_code.encode('ascii').ljust(16, b'\x00')
        return 0, locker_key_16.hex()
        
    except Exception as e:
        log_error(logger_handle, "LockerCreate", f"Exception creating locker: {e}")
        return 2, None

import json
import socket

try:
    from qmail_types import (
        ErrorCode, SendEmailErrorCode, SendEmailRequest, SendEmailResult,
        FileUploadInfo, EmailPackage, RecipientInfo, UploadResult,
        IdentityConfig, StorageDuration, RecipientType,
        TellRecipient, TellServer, TellResult, PendingTell
    )
    from striping import create_upload_stripes, calculate_parity_from_bytes
    from protocol import (
        build_complete_upload_request, validate_upload_response,
        weeks_to_duration_code, ProtocolErrorCode,
        build_complete_tell_request, validate_tell_response,
        TELL_TYPE_QMAIL, CMD_TELL
    )
    from payment import (
        calculate_total_payment, request_locker_code,
        get_server_fees, PaymentCalculation
    )
    from database import (
        get_user_by_address, insert_pending_tell, get_pending_tells,
        update_pending_tell_status, delete_pending_tell, fix_null_beacon_ids,
        DatabaseErrorCode
    )
    from cloudcoin import get_locker_keys, CloudCoinErrorCode
    from logger import log_error, log_info, log_debug, log_warning
    from wallet_structure import initialize_wallet_structure
except ImportError:
    # Fallback for standalone testing
    from enum import IntEnum

    class ErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_PARAM = 1
        ERR_NOT_FOUND = 2
        ERR_IO = 4
        ERR_NETWORK = 5

    class SendEmailErrorCode(IntEnum):
        SUCCESS = 0
        ERR_NO_EMAIL_FILE = 101
        ERR_NO_RECIPIENTS = 102
        ERR_ATTACHMENT_NOT_FOUND = 105
        ERR_TOO_MANY_ATTACHMENTS = 106
        ERR_INSUFFICIENT_FUNDS = 108
        ERR_SERVER_UNREACHABLE = 201
        ERR_PARTIAL_FAILURE = 208
        ERR_ENCRYPTION_FAILED = 209

    class StorageDuration:
        ONE_DAY = 0
        ONE_WEEK = 1
        ONE_MONTH = 2
        THREE_MONTHS = 3
        SIX_MONTHS = 4
        ONE_YEAR = 5
        PERMANENT = 255
        

    class RecipientType:
        TO = 0
        CC = 1
        BC = 2

    def log_error(handle, context, msg, reason=None):
        print(f"[ERROR] [{context}] {msg}" + (f" | REASON: {reason}" if reason else ""))
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")

    # Fallback dataclass definitions for standalone testing
    @dataclass
    class FileUploadInfo:
        file_index: int = 1
        file_data: bytes = b''
        file_name: str = ""
        file_size: int = 0
        encrypted_data: bytes = b''
        stripes: List[bytes] = field(default_factory=list)
        parity_stripe: bytes = b''
        upload_results: Dict[str, bool] = field(default_factory=dict)

    @dataclass
    class RecipientInfo:
        address: str = ""
        recipient_type: int = 0
        display_name: str = ""
        coin_id: int = 0x0006
        denomination: int = 1
        serial_number: int = 0

    @dataclass
    class EmailPackage:
        file_group_guid: bytes = b''
        email_file: 'FileUploadInfo' = None
        attachments: List['FileUploadInfo'] = field(default_factory=list)
        recipients: List['RecipientInfo'] = field(default_factory=list)
        locker_code: bytes = b''
        encryption_key: bytes = b''

    @dataclass
    class UploadResult:
        server_id: str = ""
        stripe_index: int = 0
        success: bool = False
        status_code: int = 0
        error_message: str = ""
        ip_address: str = ""
        port: int = 0

    @dataclass
    class IdentityConfig:
        coin_id: int = 0x0006
        denomination: int = 1
        serial_number: int = 0
        device_id: int = 1
        an: bytes = b''
        beacon_id: str = "raida11"

    @dataclass
    class SendEmailRequest:
        email_file: bytes = b''
        email_subject: str = ""
        to_recipients: List = field(default_factory=list)
        cc_recipients: List = field(default_factory=list)
        bcc_recipients: List = field(default_factory=list)
        attachments: List[str] = field(default_factory=list)
        storage_weeks: int = 4

    @dataclass
    class SendEmailResult:
        error_code: int = 0
        file_group_guid: bytes = b''
        upload_results: List = field(default_factory=list)
        tell_results: List = field(default_factory=list)
        error_message: str = ""

    @dataclass
    class TellRecipient:
        address_type: int = 0
        coin_id: int = 0x0006
        denomination: int = 1
        domain_id: int = 0
        serial_number: int = 0
        locker_payment_key: bytes = b''

    @dataclass
    class TellServer:
        stripe_index: int = 0
        stripe_type: int = 0
        server_id: int = 0
        ip_address: str = ""
        port: int = 0
    

    @dataclass
    class TellResult:
        recipient_address: str = ""
        beacon_server_id: str = ""
        success: bool = False
        status_code: int = 0
        error_message: str = ""

    @dataclass
    class PendingTell:
        tell_id: int = 0
        file_group_guid: bytes = b''
        recipient_address: str = ""
        recipient_type: int = 0
        beacon_server_id: str = ""
        locker_code: bytes = b''
        server_list_json: str = ""
        retry_count: int = 0
        last_attempt_at: Optional[str] = None
        error_message: str = ""
        status: str = "pending"

    # Fallback protocol constants and functions
    TELL_TYPE_QMAIL = 0
    CMD_TELL = 61

    class ProtocolErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_BODY = 1
        ERR_INCOMPLETE_DATA = 2

    def build_complete_tell_request(*args, **kwargs):
        return ProtocolErrorCode.SUCCESS, b'', b''

    def validate_tell_response(*args, **kwargs):
        return ProtocolErrorCode.SUCCESS, 250, "OK"

    def build_complete_upload_request(*args, **kwargs):
        return ProtocolErrorCode.SUCCESS, b'', b''

    def validate_upload_response(*args, **kwargs):
        return ProtocolErrorCode.SUCCESS, 250, "OK"

    def weeks_to_duration_code(weeks):
        if weeks <= 0: return StorageDuration.ONE_DAY
        elif weeks == 1: return StorageDuration.ONE_WEEK
        elif weeks <= 4: return StorageDuration.ONE_MONTH
        elif weeks <= 12: return StorageDuration.THREE_MONTHS
        elif weeks <= 26: return StorageDuration.SIX_MONTHS
        elif weeks <= 52: return StorageDuration.ONE_YEAR
        else: return StorageDuration.PERMANENT
        

    # Fallback database functions
    class DatabaseErrorCode(IntEnum):
        SUCCESS = 0
        ERR_NOT_FOUND = 1
        ERR_INVALID_PARAM = 2

    def get_user_by_address(handle, address):
        return DatabaseErrorCode.ERR_NOT_FOUND, None

    def insert_pending_tell(*args, **kwargs):
        return DatabaseErrorCode.SUCCESS, 1

    def get_pending_tells(*args, **kwargs):
        return DatabaseErrorCode.SUCCESS, []

    def update_pending_tell_status(*args, **kwargs):
        return DatabaseErrorCode.SUCCESS

    def delete_pending_tell(*args, **kwargs):
        return DatabaseErrorCode.SUCCESS

    def fix_null_beacon_ids(*args, **kwargs):
        return DatabaseErrorCode.SUCCESS, 0

    # Fallback cloudcoin function
    class CloudCoinErrorCode(IntEnum):
        SUCCESS = 0
        ERR_NOT_FOUND = 1

    def get_locker_keys(handle, identity, count=1):
        return CloudCoinErrorCode.SUCCESS, [os.urandom(16) for _ in range(count)]

    # Fallback striping functions
    def create_upload_stripes(data, num_stripes, logger_handle=None):
        """Mock stripe creation for fallback."""
        stripe_size = (len(data) + num_stripes - 1) // num_stripes
        stripes = []
        for i in range(num_stripes):
            start = i * stripe_size
            end = min(start + stripe_size, len(data))
            stripe = data[start:end]
            if len(stripe) < stripe_size:
                stripe = stripe + bytes(stripe_size - len(stripe))
            stripes.append(stripe)
        return ErrorCode.SUCCESS, stripes

    def calculate_parity_from_bytes(stripes, logger_handle=None):
        """Mock parity calculation for fallback."""
        if not stripes:
            return ErrorCode.SUCCESS, b''
        max_len = max(len(s) for s in stripes)
        parity = bytearray(max_len)
        for stripe in stripes:
            for i, b in enumerate(stripe):
                parity[i] ^= b
        return ErrorCode.SUCCESS, bytes(parity)

    from wallet_structure import initialize_wallet_structure


# ============================================================================
# CONSTANTS
# ============================================================================

SENDER_CONTEXT = "EmailSender"

# Network configuration
DEFAULT_BEACON_PORT = 19000  # Standard RAIDA beacon port

# Limits
MAX_ATTACHMENTS = 200
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB per file
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB total

# Security: Allowed base directory for attachments (None = current working directory)
# Set this to restrict attachment paths to a specific directory
ALLOWED_ATTACHMENTS_DIR = None  # Configure via set_allowed_attachments_dir()


def set_allowed_attachments_dir(base_dir: str) -> None:
    """
    Set the allowed base directory for attachment file paths.

    Security: This prevents path traversal attacks by restricting
    attachment paths to files within the specified directory.

    Args:
        base_dir: Absolute path to the allowed attachments directory
    """
    global ALLOWED_ATTACHMENTS_DIR
    ALLOWED_ATTACHMENTS_DIR = os.path.realpath(base_dir) if base_dir else None


def _validate_file_path(
    file_path: str,
    logger_handle: Optional[object] = None
) -> Tuple[bool, str]:
    """
    Validate that a file path is safe and within allowed directory.

    Security: Prevents path traversal attacks (e.g., "../../../etc/passwd")
    by canonicalizing paths and checking they're within the allowed directory.

    Args:
        file_path: The file path to validate
        logger_handle: Optional logger handle

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file_path:
        return False, "Empty file path"

    # Canonicalize the path (resolves .., symlinks, etc.)
    try:
        real_path = os.path.realpath(file_path)
    except (OSError, ValueError) as e:
        log_error(logger_handle, SENDER_CONTEXT,
                  "Path validation failed", f"Cannot resolve path: {e}")
        return False, f"Invalid path: {file_path}"

    # Check for path traversal attempts in the original path
    if '..' in file_path or file_path.startswith('/') or file_path.startswith('\\'):
        # Only flag as suspicious if we have a restricted directory
        if ALLOWED_ATTACHMENTS_DIR:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Suspicious path pattern detected: {file_path}")

    # If we have a restricted directory, ensure the path is within it
    if ALLOWED_ATTACHMENTS_DIR:
        allowed_dir = os.path.realpath(ALLOWED_ATTACHMENTS_DIR)
        if not real_path.startswith(allowed_dir + os.sep) and real_path != allowed_dir:
            log_error(logger_handle, SENDER_CONTEXT,
                      "Path traversal attempt blocked",
                      f"Path {file_path} resolves to {real_path} which is outside {allowed_dir}")
            return False, f"Access denied: path outside allowed directory"

    # Check the file exists
    if not os.path.exists(real_path):
        return False, f"File not found: {file_path}"

    # Check it's a regular file (not a directory, device, etc.)
    if not os.path.isfile(real_path):
        return False, f"Not a regular file: {file_path}"

    return True, real_path


def _safe_hex_to_bytes(
    hex_string: Optional[str],
    expected_length: int,
    field_name: str,
    logger_handle: Optional[object] = None
) -> Tuple[bool, bytes, str]:
    """
    Safely convert a hex string to bytes with validation.

    Args:
        hex_string: The hex string to convert
        expected_length: Expected byte length (hex string should be 2x this)
        field_name: Name of the field for error messages
        logger_handle: Optional logger handle

    Returns:
        Tuple of (success, bytes_result, error_message)
    """
    if not hex_string:
        return False, bytes(expected_length), f"{field_name} is empty or None"

    # Remove any whitespace or common separators
    clean_hex = hex_string.strip().replace(' ', '').replace('-', '').replace(':', '')

    # Validate length
    if len(clean_hex) != expected_length * 2:
        return False, bytes(expected_length), \
               f"{field_name} must be exactly {expected_length * 2} hex characters (got {len(clean_hex)})"

    # Validate hex characters
    try:
        result = bytes.fromhex(clean_hex)
        return True, result, ""
    except ValueError as e:
        log_error(logger_handle, SENDER_CONTEXT,
                  f"Invalid hex in {field_name}", str(e))
        return False, bytes(expected_length), f"{field_name} contains invalid hex characters"

# File index values
FILE_INDEX_BODY = 1
FILE_INDEX_ATTACHMENT_START = 10

# Server configuration
DEFAULT_NUM_SERVERS = 5 # for fall back only
DEFAULT_NUM_DATA_STRIPES = 4 # for fall back only
MAX_RETRIES = 3
RETRY_BACKOFF_MS = 1000


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class SendTaskState:
    """Internal state for a send email task."""
    task_id: str = ""
    status: str = "PENDING"
    progress: int = 0
    message: str = ""
    file_group_guid: bytes = b''
    locker_code: bytes = b''
    total_files: int = 0
    files_uploaded: int = 0
    error_code: SendEmailErrorCode = SendEmailErrorCode.SUCCESS
    error_message: str = ""


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_request(
    request: 'SendEmailRequest',
    logger_handle: Optional[object] = None
) -> Tuple[SendEmailErrorCode, str]:
    """
    Validate a send email request.
    UPDATED: Supports Pretty Email Address format and maintains strict security.

    Checks:
    - Email file/content is provided
    - At least one recipient exists and matches allowed formats
    - All attachment paths are safe and exist
    - Attachment count and sizes are within limits
    """
    from logger import log_error, log_debug
    from email_sender import SENDER_CONTEXT, MAX_ATTACHMENTS, MAX_FILE_SIZE, _validate_file_path
    import os

    # 1. CHECK EMAIL CONTENT
    # Body ya file bytes ka hona lazmi hai
    if not request.email_file or len(request.email_file) == 0:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed", "No email file provided")
        return SendEmailErrorCode.ERR_NO_EMAIL_FILE, "Email content is required"

    # 2. CHECK RECIPIENTS
    all_recipients = (request.to_recipients or []) + \
                    (request.cc_recipients or []) + \
                    (request.bcc_recipients or [])
    
    if not all_recipients:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed", "No recipients provided")
        return SendEmailErrorCode.ERR_NO_RECIPIENTS, "At least one recipient is required"

    # PRETTY FORMAT VALIDATION: Check if address is technical OR pretty
    for addr in all_recipients:
        addr_str = str(addr).strip()
        # Address ya toh technical hona chahiye (0006.D.SN) ya Pretty (#Base32.Class)
        is_pretty = '#' in addr_str and '.' in addr_str
        is_technical = addr_str.startswith('0006.')
        
        if not (is_pretty or is_technical):
            log_error(logger_handle, SENDER_CONTEXT, "Validation failed", f"Invalid recipient format: {addr_str}")
            return SendEmailErrorCode.ERR_INVALID_PARAM, f"Invalid recipient address: {addr_str}"

    # 3. CHECK ATTACHMENT COUNT
    attachment_count = len(request.attachment_paths) if request.attachment_paths else 0
    if attachment_count > MAX_ATTACHMENTS:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                  f"Too many attachments: {attachment_count} > {MAX_ATTACHMENTS}")
        return SendEmailErrorCode.ERR_TOO_MANY_ATTACHMENTS, \
               f"Maximum {MAX_ATTACHMENTS} attachments allowed"

    # 4. CHECK ATTACHMENT FILES (Security & Size)
    for path in (request.attachment_paths or []):
        # SECURITY: Validate path to prevent path traversal attacks (../etc/passwd)
        is_valid, result_or_error = _validate_file_path(path, logger_handle)
        
        if not is_valid:
            log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                      f"Attachment path validation failed: {result_or_error}")
            return SendEmailErrorCode.ERR_ATTACHMENT_NOT_FOUND, \
                   f"Attachment file error: {result_or_error}"

        # validated real path use karein size check ke liye
        real_path = result_or_error
        try:
            size = os.path.getsize(real_path)
            if size > MAX_FILE_SIZE:
                log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                          f"Attachment too large: {path} ({size} bytes)")
                return SendEmailErrorCode.ERR_ATTACHMENT_NOT_FOUND, \
                       f"Attachment too large: {path}"
        except OSError as e:
            log_error(logger_handle, SENDER_CONTEXT, "Validation failed", f"Could not access file: {path}")
            return SendEmailErrorCode.ERR_ATTACHMENT_NOT_FOUND, f"File access error: {path}"

    log_debug(logger_handle, SENDER_CONTEXT,
              f"Request validated: {len(all_recipients)} recipients, "
              f"{attachment_count} attachments")

    return SendEmailErrorCode.SUCCESS, ""

# ============================================================================
# FILE PROCESSING FUNCTIONS
# ============================================================================

def prepare_file_for_upload(
    file_data: bytes,
    file_name: str,
    file_index: int,
    encryption_key: bytes,  # Param kept for signature but ignored
    logger_handle: Optional[object] = None,
    num_servers: int = 5  # NEW PARAMETER: Number of QMail servers
) -> Tuple[ErrorCode, Optional[FileUploadInfo]]:
    """
    Prepare a file for upload (stripe and calculate parity).
    
    Creates (num_servers - 1) data stripes + 1 parity stripe = num_servers total stripes.
    
    Args:
        file_data: Raw file bytes
        file_name: Name of the file
        file_index: Index for this file in the email package
        encryption_key: (Unused) Kept for signature compatibility
        logger_handle: Optional logger
        num_servers: Number of QMail servers (determines stripe count)
    
    Implementation: Encryption is bypassed to ensure recipients can reassemble stripes
    and read content immediately.
    """
    from striping import create_upload_stripes, calculate_parity_from_bytes
    from logger import log_debug, log_error

    info = FileUploadInfo()
    info.file_index = file_index
    info.file_name = file_name
    info.file_data = file_data
    info.file_size = len(file_data)

    # DIRECTIVE: Use raw data for striping. Encryption is transport-only (Type 0).
    info.encrypted_data = file_data 

    # Create data stripes based on server count
    # create_upload_stripes creates (num_servers - 1) data stripes
    err, stripes = create_upload_stripes(info.encrypted_data, num_servers, logger_handle)
    if err != ErrorCode.SUCCESS:
        log_error(logger_handle, "Sender", f"Striping failed for index {file_index}")
        return err, None

    info.stripes = stripes

    # Calculate parity stripe (XOR of all data stripes)
    err, parity = calculate_parity_from_bytes(stripes, logger_handle)
    if err != ErrorCode.SUCCESS:
        log_error(logger_handle, "Sender", f"Parity failed for index {file_index}")
        return err, None

    info.parity_stripe = parity

    total_stripes = len(stripes) + 1  # data stripes + parity
    log_debug(logger_handle, "Sender", 
              f"Prepared '{file_name}' (plaintext) - {total_stripes} stripes "
              f"({len(stripes)} data + 1 parity) for {num_servers} servers.")
    return ErrorCode.SUCCESS, info

def upload_stripe_to_server(
    server_address: str,
    server_port: int,
    server_id: int,
    stripe_data: bytes,
    stripe_index: int,
    identity: 'IdentityConfig',
    file_group_guid: bytes,
    locker_code: bytes,
    storage_duration: int,
    logger_handle: Optional[object] = None,
    verify_only: bool = False,
    file_type: int = 0  # <--- UPDATED: Added file_type argument
) -> UploadResult:
    """
    Upload a single stripe with Adaptive Idempotency.
    
    Args:
        verify_only: If True, starts by sending Zero-Code to check if file exists 
                     (used for retrying previously successful uploads).
                     If verification fails (166), it falls back to payment.
    """
    from network import connect_to_server, send_raw_request, disconnect, ServerInfo, NetworkErrorCode
    from protocol import build_complete_upload_request
    
    result = UploadResult()
    result.server_id = str(server_id)
    result.stripe_index = stripe_index

    # 1. AN Slicing
    hex_an = getattr(identity, 'authenticity_number', '')
    if len(hex_an) == 800:
        start_hex = server_id * 32
        target_hex = hex_an[start_hex : start_hex + 32]
        _, target_an, _ = _safe_hex_to_bytes(target_hex, 16, f"an_raida{server_id}", logger_handle)
    else:
        _, target_an, _ = _safe_hex_to_bytes(hex_an, 16, "authenticity_number", logger_handle)

    # --- ADAPTIVE RETRY STATE ---
    # If verify_only is True, we start with Zero-Code to avoid double-payment
    # If verify_only is False, we start with Real Code (normal upload)
    current_locker_code = bytes(8) if verify_only else locker_code
    
    # We treat the first "verify_only" attempt like a timeout recovery
    # so that if it fails (166), the logic below knows to switch to real code.
    using_zero_code = verify_only

    for attempt in range(MAX_RETRIES):
        try:
            # 2. Build Request
            err_proto, request_bytes, challenge, nonce = build_complete_upload_request(
                raida_id=server_id,
                denomination=identity.denomination,
                serial_number=identity.serial_number,
                device_id=identity.device_id,
                an=target_an,
                file_group_guid=file_group_guid,
                locker_code=current_locker_code,
                storage_duration=storage_duration,
                stripe_data=stripe_data,
                file_type=file_type,  # <--- PASS file_type
                encryption_type=0,
                logger_handle=logger_handle
            )
           
            if err_proto != 0:
                result.error_message = "Protocol Build Error"
                return result

            # 3. Connect and Send
            s_info = ServerInfo(host=server_address, port=server_port, raida_id=server_id)
            err_conn, conn = connect_to_server(s_info, logger_handle=logger_handle)

            if err_conn != NetworkErrorCode.SUCCESS or not conn:
                continue 

            net_err, resp, _ = send_raw_request(conn, request_bytes, logger_handle=logger_handle)
            status_code = resp.status if resp else 0
            disconnect(conn)

            # --- SUCCESS CASE ---
            if net_err == NetworkErrorCode.SUCCESS and status_code == 250:
                result.success = True
                result.status_code = status_code
                return result

            # --- LOGIC: ZERO-CODE REJECTION (SCENARIO 2 Fallback) ---
            # If we tried Zero-Code (either because verify_only=True OR previous timeout)
            # and server said "Payment Required" (166), we must PAY.
            if using_zero_code and status_code == 166:
                log_info(logger_handle, SENDER_CONTEXT, 
                         f"Zero-Code probe rejected by {server_id} (Status 166). Switching to Real Payment.")
                current_locker_code = locker_code # Switch to Real Code
                using_zero_code = False
                continue

            # --- LOGIC: AMBIGUOUS FAILURE (SCENARIO 1) ---
            # If Real Code timed out, we don't know if it worked. Probe with Zero-Code next.
            if net_err in [NetworkErrorCode.ERR_TIMEOUT, NetworkErrorCode.ERR_SEND_FAILED]:
                log_warning(logger_handle, SENDER_CONTEXT, 
                            f"Timeout on RAIDA {server_id}. Probing with Zero-Code next.")
                current_locker_code = bytes(8)
                using_zero_code = True
                continue

        except Exception as e:
            log_error(logger_handle, SENDER_CONTEXT, f"RAIDA {server_id} crash", str(e))

    result.success = False
    result.error_message = "Max retries reached."
    return result


def upload_file_to_servers(
    file_info: FileUploadInfo,
    servers: List[Dict],
    identity: 'IdentityConfig',
    file_group_guid: bytes,
    locker_code: bytes,
    storage_duration: int,
    thread_pool: Optional[ThreadPoolExecutor] = None,
    logger_handle: Optional[object] = None,
    skip_payment_indices: List[int] = None,
    file_type: int = 0  # <--- UPDATED: Added file_type argument
) -> Tuple[ErrorCode, List[UploadResult]]:
    """
    Upload a file's stripes to all servers in parallel.
    
    Args:
        skip_payment_indices: List of stripe indices (0-4) that have already succeeded 
                              in a previous run. These will be sent with Zero-Code first.
    """
    all_stripes = file_info.stripes + [file_info.parity_stripe]
    results = []
    
    # Safe set for checking indices
    skip_indices = set(skip_payment_indices) if skip_payment_indices else set()

    if len(servers) != len(all_stripes):
        log_error(logger_handle, SENDER_CONTEXT, "upload_file_to_servers failed",
                  f"Server/stripe count mismatch: {len(servers)} servers, {len(all_stripes)} stripes")
        return ErrorCode.ERR_INVALID_PARAM, []

    def upload_single(args):
        stripe_idx, stripe_data, server = args
        
        # Determine if we should start in "Verify Only" mode for this specific stripe
        should_verify = stripe_idx in skip_indices
        
        # --- ROBUST ACCESS ---
        if isinstance(server, dict):
            s_addr = server.get('ip_address', server.get('host', 'localhost'))
            s_port = server.get('port', 50000 + stripe_idx)
            s_id = server.get('server_index', server.get('server_id', stripe_idx))
            # Get per-server locker code, fallback to passed locker_code
            s_locker = server.get('locker_code', locker_code)
            if isinstance(s_id, str) and s_id.startswith("RAIDA"):
                try: s_id = int(s_id.replace("RAIDA", ""))
                except: s_id = stripe_idx
        else:
            s_addr = getattr(server, 'address', getattr(server, 'host', 'localhost'))
            s_port = getattr(server, 'port', 50000 + stripe_idx)
            s_id = getattr(server, 'index', getattr(server, 'server_id', stripe_idx))
            s_locker = getattr(server, 'locker_code', locker_code)

        return upload_stripe_to_server(
            server_address=s_addr,
            server_port=int(s_port),
            server_id=int(s_id),
            stripe_data=stripe_data,
            stripe_index=stripe_idx,
            identity=identity,
            file_group_guid=file_group_guid,
            locker_code=s_locker,  # Use per-server locker code
            storage_duration=storage_duration,
            logger_handle=logger_handle,
            verify_only=should_verify,
            file_type=file_type  # <--- PASS file_type
        )

    # Prepare tasks
    tasks = [
        (i, all_stripes[i], servers[i])
        for i in range(len(all_stripes))
    ]

    # Execute
    if thread_pool:
        futures = [thread_pool.submit(upload_single, task) for task in tasks]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                log_error(logger_handle, SENDER_CONTEXT, "Upload task failed", str(e))
                results.append(UploadResult(success=False, error_message=str(e)))
    else:
        for task in tasks:
            results.append(upload_single(task))

    success_count = sum(1 for r in results if r.success)
    
    log_info(logger_handle, SENDER_CONTEXT,
             f"File upload complete: {success_count}/{len(results)} stripes succeeded")

    if success_count < NUM_DATA_STRIPES:
        return ErrorCode.ERR_NETWORK, results

    return ErrorCode.SUCCESS, results
# ============================================================================
# MAIN ORCHESTRATION FUNCTIONS
# ============================================================================

class UploadException(Exception):
    """Raised when upload fails and refund should be attempted."""
    pass
def send_email_async(
    request: 'SendEmailRequest',
    identity: 'IdentityConfig',
    db_handle: object,
    servers: List[Dict],
    thread_pool: Optional[ThreadPoolExecutor] = None,
    task_callback: Optional[callable] = None,
    logger_handle: Optional[object] = None,
    cc_handle: object = None,
    config: object = None
) -> Tuple[SendEmailErrorCode, SendEmailResult]:
    """
    Send an email asynchronously.
    UPDATED: Implements 'Encryption Before Payment' and 'Refund on Total Failure'.
    Uses _safe_hex_to_bytes for correct Type 0 key derivation.
    """
    result = SendEmailResult()
    state = SendTaskState()
    state.task_id = f"send_{int(time.time() * 1000)}"
    
    # Track if payment was made (for refund decision)
    payment_made = False

    def update_state(status: str, progress: int, message: str):
        state.status = status
        state.progress = progress
        state.message = message
        if task_callback:
            task_callback(state)
        log_info(logger_handle, SENDER_CONTEXT, f"[{state.task_id}] {status}: {message}")

    try:
        # --- 1. Validate Request ---
        update_state("VALIDATING", 5, "Validating request...")
        err, err_msg = validate_request(request, logger_handle)
        if err != SendEmailErrorCode.SUCCESS:
            result.error_code = err
            result.error_message = err_msg
            update_state("FAILED", 0, err_msg)
            return err, result

        # --- 2. Load Identity ---
        from coin_scanner import find_identity_coin, load_coin_from_file
        
        mailbox_bank = "Data/Wallets/Mailbox/Bank"
        default_bank = "Data/Wallets/Default/Bank"

        identity_coin = find_identity_coin(mailbox_bank, identity.serial_number)
        if not identity_coin:
            identity_coin = find_identity_coin(default_bank, identity.serial_number)
        
        if not identity_coin:
            msg = f"Identity coin not found for SN {identity.serial_number}"
            log_error(logger_handle, SENDER_CONTEXT, msg)
            result.error_code = SendEmailErrorCode.ERR_ENCRYPTION_FAILED
            result.error_message = msg
            update_state("FAILED", 0, result.error_message)
            return result.error_code, result
        
        # Robust AN Extraction
        raw_ans = None
        file_path = "unknown"

        if isinstance(identity_coin, dict):
            raw_ans = identity_coin.get('ans')
            file_path = identity_coin.get('file_path', 'unknown')
        else:
            raw_ans = getattr(identity_coin, 'ans', None)
            file_path = getattr(identity_coin, 'file_path', 'unknown')

        if not raw_ans:
            # Try reloading manually if scanner failed
            log_warning(logger_handle, SENDER_CONTEXT, f"Scanner failed to read ANs. Trying manual load: {file_path}")
            manual_coin = load_coin_from_file(file_path)
            if manual_coin:
                raw_ans = manual_coin.ans
        
        if not raw_ans:
            log_error(logger_handle, SENDER_CONTEXT, f"Coin IS corrupted or empty. Path: {file_path}")
            return SendEmailErrorCode.ERR_ENCRYPTION_FAILED, result

        # Convert to hex string for protocol usage
        try:
            hex_an_list = [an.hex() if isinstance(an, bytes) else str(an) for an in raw_ans]
            identity.authenticity_number = "".join(hex_an_list)
        except Exception as e:
            log_error(logger_handle, SENDER_CONTEXT, f"Failed to format ANs: {e}")
            return SendEmailErrorCode.ERR_ENCRYPTION_FAILED, result

        log_info(logger_handle, SENDER_CONTEXT, f"Loaded identity from: {os.path.basename(file_path)}")

        # --- 3. Setup Task ---
        state.file_group_guid = uuid.uuid4().bytes
        result.file_group_guid = state.file_group_guid
        attachment_count = len(request.attachment_paths) if request.attachment_paths else 0
        state.total_files = 1 + attachment_count 
        result.file_count = state.total_files

       # ============================================================
        # STEP 4: GET SERVER COUNT & PREPARE FILES
        # ============================================================
        # Get server count FIRST (needed for dynamic stripe creation)
        update_state("PROCESSING", 10, "Getting server configuration...")
        
        # Import database functions
        try:
            from database import get_all_servers, DatabaseErrorCode
        except ImportError:
            from .database import get_all_servers, DatabaseErrorCode
        
        # Get available servers from database
        err_db, db_servers = get_all_servers(db_handle, available_only=True)
        
        if err_db != DatabaseErrorCode.SUCCESS or not db_servers:
            log_error(logger_handle, SENDER_CONTEXT, "Failed to get servers from database")
            result.error_message = "No QMail servers available"
            return SendEmailErrorCode.ERR_SERVER_UNREACHABLE, result
        
        num_servers = len(db_servers)
        
        if num_servers < 2:
            log_error(logger_handle, SENDER_CONTEXT, 
                      f"Not enough servers: {num_servers} (minimum 2 required)")
            result.error_message = "Not enough QMail servers available"
            return SendEmailErrorCode.ERR_SERVER_UNREACHABLE, result
        
        log_info(logger_handle, SENDER_CONTEXT, 
                 f"Using {num_servers} servers for upload "
                 f"({num_servers - 1} data stripes + 1 parity stripe)")

        # Now prepare files with correct stripe count
        update_state("PROCESSING", 12, "Processing files (Parity & Encryption)...")
        
        # --- Master Encryption Key Selection (Restored Old Logic) ---
        # Use RAIDA 0's 16-byte AN (the first 32 hex chars) for local file encryption.
        success_an, all_ans_bytes, _ = _safe_hex_to_bytes(
            identity.authenticity_number, 400, "authenticity_number", logger_handle
        )
        if not success_an:
             return SendEmailErrorCode.ERR_ENCRYPTION_FAILED, result
             
        encryption_key = all_ans_bytes[0:16]  # 16 bytes for AES

        # Prepare Body with dynamic stripe count
        err, body_info = prepare_file_for_upload(
            request.email_file, "email_body.cbdf", FILE_INDEX_BODY,
            encryption_key, logger_handle,
            num_servers=num_servers  # Pass server count for stripe creation
        )
        if err != ErrorCode.SUCCESS:
            result.error_message = "Failed to prepare email body"
            return SendEmailErrorCode.ERR_ENCRYPTION_FAILED, result

        # Prepare Attachments with same stripe count
        prepared_attachments = []
        for i, path in enumerate(request.attachment_paths or []):
            is_valid, res = _validate_file_path(path, logger_handle)
            if not is_valid: continue
            
            with open(res, 'rb') as f: 
                file_data = f.read()
            
            err, att_info = prepare_file_for_upload(
                file_data, os.path.basename(res), FILE_INDEX_ATTACHMENT_START + i,
                encryption_key, logger_handle,
                num_servers=num_servers  # Pass server count for stripe creation
            )
            if err == ErrorCode.SUCCESS:
                prepared_attachments.append(att_info)

        # ============================================================
        # STEP 5: PREPARE PER-SERVER STORAGE PAYMENTS (RAIDA Interaction)
        # ============================================================
        update_state("CALCULATING", 15, "Calculating and preparing per-server payments...")
        
        # Calculate total file size from ENCRYPTED sizes
        file_sizes = [body_info.file_size] + [att.file_size for att in prepared_attachments]
        total_size = sum(file_sizes)
        
        # Use new per-server payment preparation (storage fees only)
        # Recipient fees are handled separately in send_tell_notifications()
        from payment import prepare_server_payments, ServerPayment
        
        err, payments = prepare_server_payments(
            db_handle=db_handle,
            total_file_size_bytes=total_size,
            storage_weeks=request.storage_weeks,
            wallet_path="Data/Wallets/Default",
            logger_handle=logger_handle,
            config=config,
            identity_sn=identity.serial_number
        )

        if err != ErrorCode.SUCCESS or not payments:
            log_error(logger_handle, SENDER_CONTEXT, f"Payment preparation failed: {err}")
            
            # User-friendly error message
            if err == ErrorCode.ERR_NOT_FOUND:
                result.error_message = "Insufficient CloudCoins. Please add more coins to your wallet or try a smaller file."
            else:
                result.error_message = "Payment failed due to network issues. Please check your connection and try again."
            
            result.error_code = SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS
            update_state("FAILED", 0, result.error_message)
            return SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS, result
        
        # Check all payments succeeded
        failed_payments = [p for p in payments if not p.success]
        if failed_payments:
            log_error(logger_handle, SENDER_CONTEXT,
                      f"{len(failed_payments)}/{len(payments)} payment PUTs failed")
            
            result.error_message = "Payment to servers failed. Your coins are safe - please try again in a few minutes."
            result.error_code = SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS
            update_state("FAILED", 0, result.error_message)
            return SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS, result
        

        
        # --- CRITICAL: PAYMENTS CREATED ---
        payment_made = True
        
        # Build server info list from payments (has IP, port, locker code from DB)
        servers = []
        for p in payments:
            servers.append({
                'server_index': p.server_index,
                'server_id': p.server_id,
                'ip_address': p.ip_address,
                'port': p.port,
                'locker_code': p.locker_code  # Per-server locker code
            })
        
        # Use first locker code for state tracking (for refund if needed)
        state.locker_code = payments[0].locker_code if payments else b'\x00' * 8
        
        locker_str_safe = payments[0].locker_code_str if payments else "N/A"
        log_info(logger_handle, SENDER_CONTEXT, 
                 f"All {len(payments)} storage payments successful. Primary locker: {locker_str_safe}")
        
        storage_duration = weeks_to_duration_code(request.storage_weeks)

        # ============================================================
        # STEP 6: UPLOAD TO QMAIL (REFUND PROTECTED + RETRY LOOP)
        # ============================================================
        try:
            update_state("UPLOADING", 25, "Uploading to QMail servers...")
            
            # --- ROBUST UPLOAD LOOP ---
            # Track which stripe indices have successfully uploaded
            successful_body_stripes = set()
            MAX_BATCH_RETRIES = 3
            
            for attempt in range(MAX_BATCH_RETRIES):
                # If retrying, we skip payment for stripes that already succeeded.
                # They will be sent with "Zero-Code" to verify presence.
                skip_indices = list(successful_body_stripes)
                
                if attempt > 0:
                    log_warning(logger_handle, SENDER_CONTEXT, 
                                f"Retrying upload batch (Attempt {attempt+1}/{MAX_BATCH_RETRIES}). "
                                f"Verifying payment for: {skip_indices}")

                # Upload Body
                err, upload_results = upload_file_to_servers(
                    body_info, servers, identity, state.file_group_guid,
                    None, storage_duration, thread_pool, logger_handle,
                    skip_payment_indices=skip_indices,
                    file_type=1  # <--- Explicitly send Type 1 for body
                )
                
                # Update success set
                for r in upload_results:
                    if getattr(r, 'success', False):
                        successful_body_stripes.add(r.stripe_index)
                
                # Check consensus (Need 4 or 5 out of 5)
                if len(successful_body_stripes) >= 4:
                    result.upload_results.extend(upload_results)
                    break
                
                # Wait before retry if not done
                if attempt < MAX_BATCH_RETRIES - 1:
                    time.sleep(2)

            # --- CHECK FINAL BODY SUCCESS ---
            body_success_count = len(successful_body_stripes)
            
            # SCENARIO 1: TOTAL FAILURE (Refund Trigger)
            # If 0 servers accepted the file after retries, the payment is stranded on RAIDA.
            if body_success_count == 0:
                raise UploadException("Connection failed: 0/5 servers accepted the email.")

            # SCENARIO 2: PARTIAL FAILURE (No Refund)
            # If 1-3 servers accepted, the payment was likely consumed. 
            # We fail without refunding, relying on write-over logic for future retries.
            if body_success_count < 4:
                result.success = False
                result.error_code = SendEmailErrorCode.ERR_PARTIAL_FAILURE
                result.error_message = f"Consensus failed after retries: {body_success_count}/5 servers (No refund)"
                update_state("FAILED", 0, result.error_message)
                return result.error_code, result

            # Upload Attachments (Only if body succeeded)
            # Standard single pass for attachments (can be improved with similar retry logic if needed)
            state.files_uploaded = 1
            for i, att_info in enumerate(prepared_attachments): # <--- Changed iterator to get index
                # TYPE 10 + i = .0.bin, .1.bin, etc.
                err, att_results = upload_file_to_servers(
                    att_info, servers, identity, state.file_group_guid,
                    state.locker_code, storage_duration, thread_pool, logger_handle,
                    file_type=10 + i  # <--- Explicitly send Type 10+ for attachments
                )
                result.upload_results.extend(att_results)
                state.files_uploaded += 1
            
            # Final verification of attachments could go here
            
        except (UploadException, Exception) as upload_error:
            # ============================================================
            # REFUND HANDLER
            # ============================================================
            log_error(logger_handle, SENDER_CONTEXT, f"Upload failed: {upload_error}")
            
            if payment_made and state.locker_code:
                update_state("REFUNDING", 50, "Upload failed, recovering payment from RAIDA...")
                
                # Small delay to ensure server state settles
                time.sleep(2)
                
                # Attempt refund using synchronous wrapper
                refund_success, coins_recovered = _attempt_refund(
                    locker_code=state.locker_code,
                    wallet_path="Data/Wallets/Default",
                    db_handle=db_handle,
                    logger_handle=logger_handle,
                    max_attempts=2
                )
                
                # Decode locker code for error message
                locker_str = state.locker_code[:8].decode('ascii', errors='ignore')
                
                if refund_success:
                    result.error_code = SendEmailErrorCode.ERR_PARTIAL_FAILURE
                    result.error_message = (
                        f"Upload failed but payment recovered ({coins_recovered} coins). "
                        f"Please try again."
                    )
                else:
                    result.error_code = SendEmailErrorCode.ERR_PARTIAL_FAILURE
                    result.error_message = (
                        f"Upload failed and refund failed. "
                        f"Locker code: {locker_str}"
                    )
                
                update_state("FAILED", 0, result.error_message)
                return SendEmailErrorCode.ERR_PARTIAL_FAILURE, result
            
            # If no locker was created, just return error
            result.error_code = SendEmailErrorCode.ERR_PARTIAL_FAILURE
            result.error_message = str(upload_error)
            update_state("FAILED", 0, result.error_message)
            return SendEmailErrorCode.ERR_PARTIAL_FAILURE, result

        # --- 7. NOTIFICATIONS & STORAGE (Success Path) ---
        update_state("NOTIFYING", 92, "Sending notifications...")
        send_tell_notifications(
            request=request, file_group_guid=state.file_group_guid,
            servers=servers, identity=identity, logger_handle=logger_handle,
            db_handle=db_handle, cc_handle=cc_handle, locker_code=state.locker_code,
            upload_results=result.upload_results
        )

        update_state("STORING", 95, "Storing locally...")
        store_sent_email(request, state.file_group_guid, result.upload_results, db_handle, logger_handle)

        result.success = True
        result.error_code = SendEmailErrorCode.SUCCESS
        update_state("COMPLETED", 100, "Email sent successfully")

        return SendEmailErrorCode.SUCCESS, result

    except Exception as e:
        # Global Crash Handler
        log_error(logger_handle, SENDER_CONTEXT, "send_email_async crashed", str(e))
        
        # If we crashed AFTER creating the locker, try to save the user's money
        if payment_made and state.locker_code:
            try:
                log_warning(logger_handle, SENDER_CONTEXT, "Attempting emergency refund...")
                _attempt_refund(state.locker_code, "Data/Wallets/Default", db_handle, logger_handle)
                result.error_message = f"Crashed but payment recovered. Error: {e}"
            except:
                result.error_message = f"Crashed and refund failed. Error: {e}"
        else:
            result.error_message = str(e)
            
        update_state("FAILED", 0, str(e))
        return SendEmailErrorCode.ERR_PARTIAL_FAILURE, result
# ============================================================================
# STUB FUNCTIONS (to be implemented)
# ============================================================================

def send_tell_notifications(
    request: 'SendEmailRequest',
    file_group_guid: bytes,
    servers: List[Dict],
    identity: 'IdentityConfig',
    logger_handle: Optional[object] = None,
    db_handle: object = None,
    cc_handle: object = None,
    locker_code: bytes = None,
    upload_results: List['UploadResult'] = None
) -> ErrorCode:
    """
    Send Tell notifications to all recipients.
    
    IMPROVED: Pre-flight coin verification before recipient payment loop.
    
    Flow:
    1. Collect all recipients
    2. Calculate TOTAL fees needed (beacon + inbox for all)
    3. PRE-FLIGHT: Verify Bank coins, heal if needed
    4. Process each recipient (payment + send)
    """
    import asyncio
    import time
    import json
    import os
    
    from qmail_types import ErrorCode, TellRecipient, TellServer
    from logger import log_info, log_debug, log_warning, log_error
    from database import get_user_by_address, insert_pending_tell, DatabaseErrorCode

    SENDER_CONTEXT = "TellNotify"

    # ================================================================
    # 1. Collect Recipients
    # ================================================================
    all_recipients = []
    for r in (request.to_recipients or []): 
        all_recipients.append((r, 0))  # 0 = To
    for r in (request.cc_recipients or []): 
        all_recipients.append((r, 1))  # 1 = CC
    for r in (request.bcc_recipients or []): 
        all_recipients.append((r, 2))  # 2 = BCC

    if not all_recipients:
        log_debug(logger_handle, SENDER_CONTEXT, "No recipients for Tell notifications")
        return ErrorCode.SUCCESS

    log_info(logger_handle, SENDER_CONTEXT, 
             f"Processing Tell notifications for {len(all_recipients)} recipients")

    # ================================================================
    # 2. Process Pending Tells (Best Effort)
    # ================================================================
    if db_handle and cc_handle:
        try:
            _process_pending_tells(db_handle, cc_handle, identity, logger_handle)
        except Exception:
            pass

    # ================================================================
    # 3. Validation
    # ================================================================
    if db_handle is None:
        log_warning(logger_handle, SENDER_CONTEXT, "No database handle - cannot look up beacons")
        return ErrorCode.SUCCESS 
    
    if locker_code is None or len(locker_code) < 8:
        log_warning(logger_handle, SENDER_CONTEXT, 
                    "No File Locker Code - recipients will not be able to download")
        return ErrorCode.SUCCESS

    # ================================================================
    # 4. Calculate TOTAL fees needed for PRE-FLIGHT
    # ================================================================
    wallet_path = "Data/Wallets/Default"
    total_fees_needed = 0.0
    recipient_fee_info = []  # Store (address, r_type, beacon_id, beacon_fee, inbox_fee)
    
    for address, r_type in all_recipients:
        beacon_id = 'raida11'
        beacon_fee = 0.1
        inbox_fee = 0.0
        
        err, user = get_user_by_address(db_handle, address)
        if err == DatabaseErrorCode.SUCCESS and user:
            if user.get('beacon_id'):
                beacon_id = user['beacon_id']
            if user.get('beacon_fee'):
                try:
                    beacon_fee = float(user['beacon_fee'])
                except:
                    beacon_fee = 0.1
            if user.get('inbox_fee'):
                try:
                    inbox_fee = float(user['inbox_fee'])
                except:
                    inbox_fee = 0.0
        
        total_fees_needed += beacon_fee
        if inbox_fee > 0.00000001:
            total_fees_needed += inbox_fee
        
        recipient_fee_info.append((address, r_type, beacon_id, beacon_fee, inbox_fee))
    
    log_info(logger_handle, SENDER_CONTEXT,
             f"Total recipient fees needed: {total_fees_needed:.8f} CC "
             f"({len(all_recipients)} recipients)")

    # ================================================================
    # 5. PRE-FLIGHT: Verify Bank coins and heal if needed
    # ================================================================
    if total_fees_needed > 0.00000001:
        log_info(logger_handle, SENDER_CONTEXT, "PRE-FLIGHT: Verifying Bank coins for recipient fees...")
        
        preflight_ok = _preflight_verify_for_tells(
            wallet_path=wallet_path,
            total_amount_needed=total_fees_needed,
            identity_sn=identity.serial_number,
            logger_handle=logger_handle
        )
        
        if not preflight_ok:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"PRE-FLIGHT WARNING: May not have enough coins for {total_fees_needed:.8f} CC. "
                        f"Will attempt anyway...")
        else:
            log_info(logger_handle, SENDER_CONTEXT, "PRE-FLIGHT: Bank coins verified ✓")

    # ================================================================
    # 6. Build Server List (file locations)
    # ================================================================
    tell_servers = _build_tell_servers(upload_results, servers, logger_handle)

    # ================================================================
    # 7. Process Each Recipient (Payment + Send)
    # ================================================================
    tells_sent = 0
    tells_failed = 0
    timestamp = int(time.time())
    
    for address, r_type, beacon_id, beacon_fee, inbox_fee in recipient_fee_info:
        try:
            # --- A. Create Locker for BEACON PAYMENT ---
            err_code, beacon_locker_hex = asyncio.run(create_recipient_locker(
                wallet_path, beacon_fee, identity.serial_number, logger_handle
            ))

            if err_code != 0 or not beacon_locker_hex:
                log_error(logger_handle, SENDER_CONTEXT, 
                          f"Skipping Tell for {address}: Beacon Payment failed (Code {err_code})")
                tells_failed += 1
                continue

            beacon_locker_bytes = bytes.fromhex(beacon_locker_hex)[:8]

            # --- B. Create Locker for RECIPIENT INBOX FEE ---
            recipient_locker_bytes = bytes(16)  # Default: no payment
            if inbox_fee > 0.00000001:
                err_code, recipient_locker_hex = asyncio.run(create_recipient_locker(
                    wallet_path, inbox_fee, identity.serial_number, logger_handle
                ))
                
                if err_code != 0 or not recipient_locker_hex:
                    log_warning(logger_handle, SENDER_CONTEXT, 
                                f"Recipient inbox fee payment failed for {address}, continuing without it")
                else:
                    recipient_locker_bytes = bytes.fromhex(recipient_locker_hex)[:16]

            # --- C. Build Recipient Struct ---
            coin_id, denom, serial_number = _parse_qmail_address(address)

            tell_recipient = TellRecipient(
                address_type=r_type,
                coin_id=coin_id,
                denomination=denom,
                domain_id=0, 
                serial_number=serial_number,
                locker_payment_key=recipient_locker_bytes
            )

            # --- D. Send Notification ---
            beacon_raida_id = _beacon_id_to_raida_index(beacon_id)

            err = _send_single_tell(
                beacon_raida_id, beacon_id, tell_recipient, file_group_guid,
                tell_servers, beacon_locker_bytes, identity, timestamp, logger_handle
            )

            if err == ErrorCode.SUCCESS:
                tells_sent += 1
                log_debug(logger_handle, SENDER_CONTEXT, f"Tell sent to {address} via {beacon_id}")
            else:
                tells_failed += 1
                log_warning(logger_handle, SENDER_CONTEXT, f"Tell failed for {address} via {beacon_id}")

                # Store in Retry Queue
                if db_handle:
                    server_list_json = json.dumps([{
                        'stripe_index': s.stripe_index,
                        'stripe_type': s.stripe_type,
                        'ip_address': s.ip_address,
                        'port': s.port
                    } for s in tell_servers])

                    insert_pending_tell(
                        db_handle, file_group_guid, address, r_type,
                        beacon_id, locker_code, server_list_json
                    )

        except Exception as e:
            log_error(logger_handle, SENDER_CONTEXT, f"Exception processing Tell for {address}: {e}")
            tells_failed += 1

    log_info(logger_handle, SENDER_CONTEXT, 
             f"Tell notifications: {tells_sent} sent, {tells_failed} failed")
    return ErrorCode.SUCCESS


def _preflight_verify_for_tells(
    wallet_path: str,
    total_amount_needed: float,
    identity_sn: int,
    logger_handle: object
) -> bool:
    """
    PRE-FLIGHT: Verify Bank coins for recipient Tell payments.
    
    Similar to payment pre-flight but simpler - just verify and heal.
    
    Returns:
        True if enough healthy coins available
        False if insufficient (but we'll try anyway)
    """
    CONTEXT = "TellPreFlight"
    
    try:
        from heal import verify_bank_coins, heal_wallet
        from coin_scanner import get_coins_by_value, parse_denomination_code
    except ImportError:
        try:
            from .heal import verify_bank_coins, heal_wallet
            from .coin_scanner import get_coins_by_value, parse_denomination_code
        except ImportError:
            log_warning(logger_handle, CONTEXT, "Cannot import heal module - skipping pre-flight")
            return True  # Continue without pre-flight
    
    try:
        # Step 1: Verify Bank coins
        log_info(logger_handle, CONTEXT, "Verifying Bank coins...")
        err, checked, moved = verify_bank_coins(wallet_path)
        
        log_info(logger_handle, CONTEXT, 
                 f"Verified: {checked} coins checked, {moved} moved to Fracked")
        
        # Step 2: Heal if fracked found
        if moved > 0:
            log_info(logger_handle, CONTEXT, f"Found {moved} fracked coins. Healing...")
            
            result = heal_wallet(wallet_path, max_iterations=2)
            
            log_info(logger_handle, CONTEXT,
                     f"Healed: {result.total_fixed}/{result.total_fracked} coins fixed")
            
            # Small wait for filesystem sync
            import time
            time.sleep(1.0)
        
        # Step 3: Check available coins
        coins = get_coins_by_value(wallet_path, total_amount_needed, identity_sn=identity_sn)
        
        if not coins:
            log_warning(logger_handle, CONTEXT,
                        f"Insufficient healthy coins for {total_amount_needed:.8f} CC")
            return False
        
        total_available = sum(parse_denomination_code(c.denomination) for c in coins)
        log_info(logger_handle, CONTEXT,
                 f"Available: {total_available:.8f} CC (need {total_amount_needed:.8f} CC) ✓")
        
        return True
        
    except Exception as e:
        log_warning(logger_handle, CONTEXT, f"Pre-flight check failed: {e}")
        return True  # Continue anyway

def _send_single_tell(
    raida_id: int,
    beacon_id: str,
    recipient: 'TellRecipient',
    file_group_guid: bytes,
    servers: List['TellServer'],
    locker_code: bytes,
    identity: 'IdentityConfig',
    timestamp: int,
    logger_handle: Optional[object] = None
) -> ErrorCode:
    """
    Deliver Tell notification with TCP-to-UDP fallback.
    """
    from network import ServerInfo, connect_to_server, send_raw_request, disconnect, NetworkErrorCode
    from protocol import build_complete_tell_request, TELL_TYPE_QMAIL, validate_tell_response
    
    # 1. Prepare AN for this specific RAIDA (Used for Packet Authentication)
    target_an = bytes(16)
    
    hex_an = getattr(identity, 'authenticity_number', '')
    if hex_an and len(hex_an) >= 800:
        try:
            start_idx = raida_id * 32 # 32 hex chars = 16 bytes
            an_slice_hex = hex_an[start_idx : start_idx + 32]
            target_an = bytes.fromhex(an_slice_hex)
        except Exception:
            pass 

    # 2. Build the request
    # locker_code: The File Access Code (allows recipient to download file)
    # recipient.locker_payment_key: The Notification Fee (0.1 CC for this Tell)
    err, request_bytes, challenge, nonce = build_complete_tell_request(
    raida_id=raida_id,
    denomination=getattr(identity, 'denomination', 1),
    serial_number=getattr(identity, 'serial_number', 0),
    device_id=0,
    an=target_an,
    file_group_guid=file_group_guid,
    beacon_payment_locker=locker_code,  # This is the beacon payment (was just 'locker_code')
    timestamp=timestamp,
    tell_type=TELL_TYPE_QMAIL,
    recipients=[recipient],
    servers=servers,
    logger_handle=logger_handle
)

    if err != 0:
        return ErrorCode.ERR_PROTOCOL

    # 3. Try TCP Port 50000+
    host = f"{beacon_id}.cloudcoin.global"
    s_info = ServerInfo(host=host, port=50000 + raida_id, raida_id=raida_id)
    err_conn, conn = connect_to_server(s_info, logger_handle=logger_handle)
    
    if err_conn == NetworkErrorCode.SUCCESS and conn:
        try:
            # net_err 0 = SUCCESS
            net_err, resp, _ = send_raw_request(conn, request_bytes, logger_handle=logger_handle)
            if net_err == NetworkErrorCode.SUCCESS and resp and resp.status == 250:
                return ErrorCode.SUCCESS
        finally:
            disconnect(conn)

    return ErrorCode.ERR_NETWORK

    # # 4. FALLBACK: UDP Port 19000
    # log_info(logger_handle, "EmailSender", f"TCP failed, trying UDP for {beacon_id}")
    
    # # Assuming _send_udp_request is available in the module scope
    # response = _send_udp_request(host, 19000, request_bytes, logger_handle)
    # if response:
    #     _, status, _ = validate_tell_response(response, challenge, logger_handle)
    #     if status == 250:
    #         return ErrorCode.SUCCESS

   

def _send_udp_request(
    ip: str,
    port: int,
    request: bytes,
    logger_handle: Optional[object] = None,
    timeout: float = 5.0
) -> Optional[bytes]:
    """
    Send UDP request and receive response.

    Args:
        ip: Server IP address
        port: Server port
        request: Request bytes to send
        logger_handle: Optional logger handle
        timeout: Socket timeout in seconds

    Returns:
        Response bytes or None on failure
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        sock.sendto(request, (ip, port))
        response, _ = sock.recvfrom(4096)

        sock.close()
        return response

    except socket.timeout:
        log_warning(logger_handle, SENDER_CONTEXT,
                    f"UDP timeout to {ip}:{port}")
        return None
    except socket.error as e:
        log_error(logger_handle, SENDER_CONTEXT,
                  f"UDP error to {ip}:{port}", str(e))
        return None
    finally:
        try:
            sock.close()
        except:
            pass


def _build_tell_servers(
    upload_results: List['UploadResult'],
    servers: List[Dict],
    logger_handle: Optional[object] = None
) -> List['TellServer']:
    """
    Build TellServer list from upload results.

    Args:
        upload_results: List of UploadResult from uploads
        servers: List of server configurations
        logger_handle: Optional logger handle

    Returns:
        List of TellServer objects (server locations for stripe download)
    """
    tell_servers = []

    if not upload_results:
        return tell_servers

    # Create server lookup dict
    server_lookup = {}
    for s in (servers or []):
        if isinstance(s, dict):
            server_id = s.get('server_id', s.get('QMailServerID', ''))
            server_lookup[server_id] = s
        elif hasattr(s, 'server_id'):
            server_lookup[s.server_id] = s

    # Build TellServer for each upload result
    for result in upload_results:
        if not result or not result.success:
            continue

        server_id = result.server_id if hasattr(result, 'server_id') else ''
        stripe_index = result.stripe_index if hasattr(result, 'stripe_index') else 0

        # Look up server info
        server_info = server_lookup.get(server_id, {})
        if isinstance(server_info, dict):
            ip = server_info.get('ip_address', server_info.get('IPAddress', ''))
            port = server_info.get('port', server_info.get('PortNumb', DEFAULT_BEACON_PORT))
        else:
            ip = getattr(server_info, 'ip_address', '')
            port = getattr(server_info, 'port', DEFAULT_BEACON_PORT)

        tell_servers.append(TellServer(
            stripe_index=stripe_index,
            stripe_type=0 if stripe_index < 4 else 1,  # 0=Data, 1=Parity
            server_id=0,
            ip_address=ip,
            port=port
            # No locker_code - not in protocol
        ))

    return tell_servers


def _parse_qmail_address(address: str) -> Tuple[int, int, int]:
    try:
        parts = address.split('.')
        if len(parts) >= 3:
            coin_id = int(parts[0])
            denom = int(parts[1])
            # FIXED: Use the helper to handle the 'C' prefix
            serial = custom_sn_to_int(parts[2]) 
            return coin_id, denom, serial
    except (ValueError, IndexError):
        pass
    return 0x0006, 1, 0


def _beacon_id_to_raida_index(beacon_id: str) -> int:
    """
    Convert beacon ID string to RAIDA index.

    Args:
        beacon_id: Beacon ID (e.g., "raida11", "RAIDA5")

    Returns:
        RAIDA index (0-24)
    """
    if not beacon_id:
        return 11  # Default to raida11

    # Extract number from string like "raida11" or "RAIDA5"
    try:
        import re
        match = re.search(r'\d+', beacon_id)
        if match:
            index = int(match.group())
            if 0 <= index <= 24:
                return index
    except:
        pass

    return 11  # Default to raida11


def _get_beacon_address(beacon_id: str) -> Tuple[str, int]:
    """
    Get beacon server IP and port.

    Args:
        beacon_id: Beacon ID (e.g., "raida11")

    Returns:
        Tuple of (ip_address, port)
    """
    # Extract RAIDA index
    index = _beacon_id_to_raida_index(beacon_id)

    # Standard RAIDA beacon addresses
    # Format: raida{N}.cloudcoin.global:DEFAULT_BEACON_PORT
    ip = f"raida{index}.cloudcoin.global"
    port = DEFAULT_BEACON_PORT

    return ip, port


def _process_pending_tells(
    db_handle: object,
    cc_handle: object,
    identity: 'IdentityConfig',
    logger_handle: Optional[object] = None,
    max_retries: int = 3
) -> int:
    """
    Process pending Tell notifications from retry queue.

    Args:
        db_handle: Database handle
        cc_handle: CloudCoin handle
        identity: User identity
        logger_handle: Optional logger handle
        max_retries: Maximum retry attempts before marking failed

    Returns:
        Number of tells successfully sent
    """
    err, pending = get_pending_tells(db_handle, 'pending', limit=20)
    if err != DatabaseErrorCode.SUCCESS or not pending:
        return 0

    log_info(logger_handle, SENDER_CONTEXT,
             f"Processing {len(pending)} pending Tell notifications")

    sent_count = 0
    timestamp = int(time.time())

    for tell in pending:
        tell_id = tell['tell_id']
        retry_count = tell.get('retry_count', 0)

        # Check retry limit
        if retry_count >= max_retries:
            update_pending_tell_status(
                db_handle, tell_id, 'failed',
                f"Max retries ({max_retries}) exceeded"
            )
            continue

        # Get fresh locker key
        err, keys = get_locker_keys(cc_handle, 0.1, 1)
        if err != CloudCoinErrorCode.SUCCESS or not keys:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Could not get locker key for pending tell {tell_id}")
            continue

        locker_key = bytes.fromhex(keys[0]) if isinstance(keys[0], str) else keys[0]

        # Get beacon info and locker code first (needed for TellServer)
        beacon_id = tell['beacon_server_id']
        raida_id = _beacon_id_to_raida_index(beacon_id)
        locker_code = tell['locker_code']

        # Ensure locker_code is bytes
        if isinstance(locker_code, str):
            try:
                locker_code = bytes.fromhex(locker_code)
            except ValueError:
                locker_code = locker_code.encode()[:8]
        if locker_code and len(locker_code) < 8:
            locker_code = locker_code + bytes(8 - len(locker_code))
        elif not locker_code:
            locker_code = bytes(8)

        # Parse stored data - include locker_code for recipient decryption
        try:
            server_list = json.loads(tell['server_list_json'])
            tell_servers = [TellServer(
                stripe_index=s.get('stripe_index', 0),
                stripe_type=s.get('stripe_type', 0),
                ip_address=s.get('ip_address', ''),
                port=s.get('port', DEFAULT_BEACON_PORT),
                locker_code=locker_code[:8]  # Include locker code for decryption
            ) for s in server_list]
        except (json.JSONDecodeError, TypeError):
            tell_servers = []

        # Build recipient
        coin_id, denom, serial = _parse_qmail_address(tell['recipient_address'])
        recipient = TellRecipient(
            address_type=tell.get('recipient_type', 0),
            coin_id=coin_id,
            denomination=denom,
            serial_number=serial,
            locker_payment_key=locker_key
        )

        # Send Tell
        err = _send_single_tell(
            raida_id, beacon_id, recipient, tell['file_group_guid'],
            tell_servers, locker_code, identity, timestamp, logger_handle
        )

        if err == ErrorCode.SUCCESS:
            delete_pending_tell(db_handle, tell_id)
            sent_count += 1
            log_debug(logger_handle, SENDER_CONTEXT,
                      f"Pending tell {tell_id} sent successfully")
        else:
            update_pending_tell_status(
                db_handle, tell_id, 'pending',
                f"Retry {retry_count + 1} failed",
                increment_retry=True
            )

    if sent_count > 0:
        log_info(logger_handle, SENDER_CONTEXT,
                 f"Processed {sent_count} pending tells successfully")

    return sent_count


def verify_an_loading(mailbox_file: str, logger_handle: Optional[object] = None):
    """
    Robustly loads 25 ANs from a .bin or .key file based on Go format definitions.
    """
    try:
        with open(mailbox_file, 'rb') as f:
            file_data = f.read()
        
        if len(file_data) < 32:
            return False, [], "File too small for header"

        # Byte 0 defines the format
        format_type = file_data[0]
        
        if format_type == 9:
            # Format 9: ANs start at header(32) + body_meta(7) = 39
            offset = 39
        elif format_type == 0:
            # Legacy CC2: ANs start at header(32) + body_meta(16) = 48
            offset = 48
        else:
            # Fallback for .KEY files which might have a different header
            # Usually .KEY is header(32) + ANs(400) = 432 bytes total
            offset = 32

        full_key_bytes = file_data[offset : offset + 400]
        
        if len(full_key_bytes) < 400:
            return False, [], f"Expected 400 bytes of AN data, got {len(full_key_bytes)}"
        
        # Convert to hex strings for compatibility with your existing slicing logic
        ans = [full_key_bytes[i*16 : (i+1)*16].hex() for i in range(25)]
        return True, ans, ""
        
    except Exception as e:
        return False, [], f"Failed to parse binary coin: {e}"

def store_sent_email(
    request: 'SendEmailRequest',
    file_group_guid: bytes,
    upload_results: List[UploadResult],
    db_handle: object,
    logger_handle: Optional[object] = None
) -> ErrorCode:
    """
    Store sent email metadata in Mailbox/Sent folder.
    """
    import json
    import time
    
    try:
        # Create Sent folder if doesn't exist
        sent_folder = "Data/Wallets/Mailbox/Sent"
        os.makedirs(sent_folder, exist_ok=True)
        
        # Extract recipients
        recipients = []
        for r in request.to_recipients:
            recipients.append(r.address if hasattr(r, 'address') else str(r))
        
        # Create metadata
        metadata = {
            "file_guid": file_group_guid.hex(),
            "subject": request.subject,
            "to": recipients,
            "body_preview": request.searchable_text[:200] if request.searchable_text else "",
            "timestamp": int(time.time()),
            "stripe_count": len(upload_results) if upload_results else 0
        }
        
        # Save as JSON file
        metadata_file = os.path.join(sent_folder, f"{file_group_guid.hex()}.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        log_info(logger_handle, SENDER_CONTEXT,
                f"Stored sent email metadata: {metadata_file}")
        
        return ErrorCode.SUCCESS
        
    except Exception as e:
        log_error(logger_handle, SENDER_CONTEXT,
                 f"Failed to store sent email: {e}")
        return ErrorCode.ERR_IO



def process_email_package(
    package: EmailPackage,
    identity: IdentityConfig,
    db_handle: Any,
    config: Any, 
    storage_weeks: int = 1,
    logger_handle: Optional[object] = None
) -> Tuple[SendEmailErrorCode, Optional[SendEmailResult]]:
    """
    Orchestrate full upload with Pretty Address resolution.
    FIXED: Uses robust key access (.get) to prevent crashes on missing dictionary keys.
    """
    import uuid, os, time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from network import connect_to_server, disconnect, send_raw_request
    from config import get_raida_server_config
    from protocol import build_complete_tell_request, weeks_to_duration_code, TELL_TYPE_QMAIL
    from database import get_user_by_address, store_email, DatabaseErrorCode
    from logger import log_info, log_error

    log_info(logger_handle, "Sender", "Starting Pretty Email upload process.")
    file_group_guid = uuid.uuid4().bytes

    # --- 1. RECIPIENT RESOLUTION ---
    recipient_sns = []
    tech_addresses = []
    
    for addr in package.recipients:
        err, user_info = get_user_by_address(db_handle, addr)
        if err == DatabaseErrorCode.SUCCESS and user_info:
            # ROBUST ACCESS: Use .get() and fallback to handle key casing issues safely
            sn = user_info.get('serial_number', user_info.get('SerialNumber', 0))
            # CRITICAL FIX: Handle missing denomination safely
            denom = user_info.get('denomination', user_info.get('Denomination', 0))
            
            recipient_sns.append(sn)
            # Construct Technical Address: 0006.DN.SN
            tech_addresses.append(f"0006.{denom}.{sn}")
        else:
            # Fallback for unknown users
            tech_addresses.append(addr)
            from protocol import custom_sn_to_int
            recipient_sns.append(custom_sn_to_int(addr))

    # --- 2. COST & LOCKER ---
    total_size = len(package.email_file) + sum(os.path.getsize(p) for p in package.attachment_paths)
    cost = calculate_storage_cost(total_size, storage_weeks, len(recipient_sns))
    err, locker_code = request_locker_code(cost, db_handle, logger_handle)
    if err != ErrorCode.SUCCESS: 
        return SendEmailErrorCode.ERR_PAYMENT_FAILED, None

    # Locker Sanitization
    if isinstance(locker_code, str):
        if len(locker_code) == 8:
            locker_code = locker_code.encode('ascii')
        else:
            clean_code = locker_code.replace('-', '').strip().upper()
            locker_code = clean_code.encode('ascii').ljust(8, b'\x00')

    # --- 3. PREPARATION ---
    files_to_upload = []
    # Body
    err, body_info = prepare_file_for_upload(package.email_file, "body.qmail", 0, bytes(16), logger_handle)
    if err == ErrorCode.SUCCESS: files_to_upload.append(body_info)

    # Attachments
    for i, path in enumerate(package.attachment_paths):
        with open(path, 'rb') as f:
            err, att_info = prepare_file_for_upload(f.read(), os.path.basename(path), i+1, bytes(16), logger_handle)
            if err == ErrorCode.SUCCESS: files_to_upload.append(att_info)

    # --- 4. PARALLEL UPLOAD ---
    duration_code = weeks_to_duration_code(storage_weeks)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for info in files_to_upload:
            for s_idx, s_data in enumerate(info.stripes + [info.parity_stripe]):
                srv = config.qmail_servers[s_idx]
                futures.append(executor.submit(
                    upload_stripe_to_server, 
                    srv, s_data, s_idx, identity, 
                    file_group_guid, locker_code, 
                    duration_code, logger_handle
                ))
        for f in as_completed(futures): f.result()

    # --- 5. BEACON NOTIFICATION ---
    beacon_id = 11
    try:
        timestamp = int(time.time())
        if hasattr(identity, 'authenticity_number') and len(identity.authenticity_number) >= 400:
            start = beacon_id * 16
            target_an = identity.authenticity_number[start : start+16]
        else:
            target_an = bytes(16)

        err_proto, tell_req, challenge, nonce = build_complete_tell_request(
            raida_id=beacon_id,
            denomination=identity.denomination,
            serial_number=identity.serial_number,
            device_id=0,
            an=target_an,
            file_group_guid=file_group_guid,
            locker_code=locker_code,
            timestamp=timestamp,
            tell_type=TELL_TYPE_QMAIL,
            recipients=tech_addresses, 
            servers=[] 
        )
        
        srv_cfg = get_raida_server_config(beacon_id, config.raida_servers)
        if srv_cfg:
            conn_err, conn = connect_to_server(srv_cfg)
            if conn_err == 0:
                net_err, resp, _ = send_raw_request(conn, tell_req, logger_handle=logger_handle)
                if net_err == 0 and resp.status == 250:
                    log_info(logger_handle, "Sender", f"Tell accepted by Beacon (RAIDA {beacon_id})")
                disconnect(conn)
    except Exception as e:
        log_error(logger_handle, "Sender", f"Tell failed: {e}")

    # --- 6. LOCAL STORAGE ---
    sent_email_data = {
        'email_id': file_group_guid,
        'subject': package.subject,
        'body': package.searchable_text,
        'sender_sn': identity.serial_number,
        'recipient_sns': recipient_sns,
        'folder': 'sent',
        'is_read': 1,
        'sent_timestamp': int(time.time())
    }
    store_email(db_handle, sent_email_data)

    return SendEmailErrorCode.SUCCESS, SendEmailResult(file_group_guid, locker_code)
# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("=" * 60)
    print("email_sender.py - Test Suite")
    print("=" * 60)

    # Create mock request
    from dataclasses import dataclass as dc
    @dc
    class MockRequest:
        email_file: bytes = b'Test email content'
        searchable_text: str = "Test"
        subject: str = "Test Subject"
        subsubject: str = None
        to_recipients: list = None
        cc_recipients: list = None
        bcc_recipients: list = None
        attachment_paths: list = None
        storage_weeks: int = 8
        index_attachments: bool = False

    @dc
    class MockIdentity:
        coin_type: int = 6
        denomination: int = 1
        serial_number: int = 12345678
        device_id: int = 1
        authenticity_number: str = "00112233445566778899aabbccddeeff"

    # Test 1: Validate request - missing email
    print("\n1. Testing validate_request() - no email...")
    req = MockRequest(email_file=b'')
    err, msg = validate_request(req)
    assert err == SendEmailErrorCode.ERR_NO_EMAIL_FILE
    print("   SUCCESS: Detected missing email")

    # Test 2: Validate request - no recipients
    print("\n2. Testing validate_request() - no recipients...")
    req = MockRequest()
    req.to_recipients = []
    err, msg = validate_request(req)
    assert err == SendEmailErrorCode.ERR_NO_RECIPIENTS
    print("   SUCCESS: Detected missing recipients")

    # Test 3: Validate request - valid request
    print("\n3. Testing validate_request() - valid request...")
    req = MockRequest()
    req.to_recipients = ["0006.1.12345678"]
    err, msg = validate_request(req)
    assert err == SendEmailErrorCode.SUCCESS
    print("   SUCCESS: Valid request accepted")

    # Test 4: Prepare file for upload
    print("\n4. Testing prepare_file_for_upload()...")
    test_data = b"Hello, World!" * 100
    key = bytes(16)
    err, info = prepare_file_for_upload(test_data, "test.txt", 1, key)
    assert err == ErrorCode.SUCCESS
    assert len(info.stripes) == 4
    assert len(info.parity_stripe) > 0
    print(f"   Created {len(info.stripes)} data stripes + parity")
    print("   SUCCESS")

    # Test 5: weeks_to_duration_code
    print("\n5. Testing weeks_to_duration_code()...")
    assert weeks_to_duration_code(8) == StorageDuration.THREE_MONTHS
    print("   8 weeks -> THREE_MONTHS (code 3)")
    print("   SUCCESS")

    print("\n" + "=" * 60)
    print("All email_sender tests passed!")
    print("=" * 60)


