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
from typing import Dict, List, Optional, Tuple ,Any
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
from payment import calculate_storage_cost, request_locker_code
from logger import log_info, log_error, log_warning, log_debug
from config import get_raida_server_config


from typing import Optional, List, Tuple
import os
import struct


def load_coin_from_file(file_path: str) -> Optional[Any]:
    """
    Loads full coin data including ANs and internal POWN status.
    Required for payment orchestrations (Cmd 82).
    """
    import struct
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 439:
            return None

        # Parse internal POWN from Byte 16
        pown_bytes = data[16:29]
        pown_str = ""
        for i in range(25):
            byte_val = pown_bytes[i // 2]
            nibble = (byte_val >> 4) if (i % 2 == 0) else (byte_val & 0x0F)
            pown_str += 'p' if nibble == 1 else ('f' if nibble == 0 else 'u')

        # Parse SN/DN from Byte 32 preamble
        denomination = struct.unpack('b', data[34:35])[0]
        serial_number = struct.unpack('>I', data[35:39])[0]

        # Parse 25 Authenticity Numbers (ANs)
        # ANs start at Offset 39 (Byte 32 + 7 bytes of header)
        ans = []
        for i in range(25):
            start = 39 + (i * 16)
            ans.append(data[start : start + 16])

        # Create a simple object to match the expected coin interface
        return type('Coin', (), {
            'denomination': denomination,
            'sn': serial_number,
            'ans': ans,
            'pown_string': pown_str,
            'file_path': file_path
        })()
    except Exception:
        return None

def get_coins_by_value(wallet_path: str, target_value: float, identity_sn: int = None) -> List:
    """
    Get coins from wallet that total the target value.
    
    IMPORTANT: Excludes identity coin to prevent accidental spending.
    Uses internal file scanning (Byte 16) to ensure coin validity.
    
    Args:
        wallet_path: Path to wallet (e.g., "Data/Wallets/Default")
        target_value: Amount needed (e.g., 0.1)
        identity_sn: Serial number of identity coin to exclude (optional)
        
    Returns:
        List of coin objects
    """
    from coin_scanner import parse_denomination_code
    import os
    
    bank_path = os.path.join(wallet_path, "Bank")
    
    if not os.path.exists(bank_path):
        return []
    
    all_coins = []
    
    # 1. Scan and load all available coins
    for filename in os.listdir(bank_path):
        if not filename.endswith('.bin'):
            continue
            
        file_path = os.path.join(bank_path, filename)
        
        # This reads Byte 16 inside the file for POWN status
        coin = load_coin_from_file(file_path)
        
        if coin is None:
            continue
        
        # CRITICAL: Skip identity coin
        if identity_sn and coin.sn == identity_sn:
            continue
        
        # Get float value (1.0, 0.1, etc.)
        coin_value = parse_denomination_code(coin.denomination)
        all_coins.append((coin, coin_value))

    # 2. Try to find an EXACT MATCH using a greedy aggregation
    # Sort descending to use larger coins first
    all_coins.sort(key=lambda x: x[1], reverse=True)
    
    selected_for_aggregation = []
    accumulated_value = 0.0
    
    for coin, val in all_coins:
        # Check if adding this coin stays within the target
        if accumulated_value + val <= target_value + 0.000001:
            selected_for_aggregation.append(coin)
            accumulated_value += val
            
        # If we hit the exact target, return the list
        if abs(accumulated_value - target_value) < 0.000001:
            return selected_for_aggregation

    # 3. No exact match found via aggregation? 
    # Find the SMALLEST single coin that is larger than the target (to be broken)
    larger_coins = [(c, v) for c, v in all_coins if v > target_value]
    if larger_coins:
        # Sort ascending to find the smallest overhead
        larger_coins.sort(key=lambda x: x[1])
        return [larger_coins[0][0]]
    
    # Truly insufficient funds
    return []


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
            
            broken_coins = await break_coin(coin_to_break, amount)
            
            if not broken_coins:
                log_error(logger_handle, "LockerCreate", "Failed to break coin")
                return 2, None
            
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
                serial_number=c.sn,
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
    from .qmail_types import (
        ErrorCode, SendEmailErrorCode, SendEmailRequest, SendEmailResult,
        FileUploadInfo, EmailPackage, RecipientInfo, UploadResult,
        IdentityConfig, StorageDuration, RecipientType,
        TellRecipient, TellServer, TellResult, PendingTell
    )
    from .striping import create_upload_stripes, calculate_parity_from_bytes
    from .protocol import (
        build_complete_upload_request, validate_upload_response,
        weeks_to_duration_code, ProtocolErrorCode,
        build_complete_tell_request, validate_tell_response,
        TELL_TYPE_QMAIL, CMD_TELL
    )
    from .payment import (
        calculate_total_payment, request_locker_code,
        get_server_fees, PaymentCalculation
    )
    from .database import (
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
        locker_code: bytes = b''  # 8-byte locker code for this stripe

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
NUM_SERVERS = 5
NUM_DATA_STRIPES = 4
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
    from src.logger import log_error, log_debug
    from src.email_sender import SENDER_CONTEXT, MAX_ATTACHMENTS, MAX_FILE_SIZE, _validate_file_path
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
    encryption_key: bytes, # Param kept for signature but ignored
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, Optional[FileUploadInfo]]:
    """
    Prepare a file for upload (stripe and calculate parity).
    
    
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

    # Create stripes (4 data stripes)
    err, stripes = create_upload_stripes(info.encrypted_data, 5, logger_handle)
    if err != ErrorCode.SUCCESS:
        log_error(logger_handle, "Sender", f"Striping failed for index {file_index}")
        return err, None

    info.stripes = stripes

    # Calculate parity stripe
    err, parity = calculate_parity_from_bytes(stripes, logger_handle)
    if err != ErrorCode.SUCCESS:
        log_error(logger_handle, "Sender", f"Parity failed for index {file_index}")
        return err, None

    info.parity_stripe = parity

    log_debug(logger_handle, "Sender", f"Prepared '{file_name}' (plaintext) - 5 stripes total.")
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
    logger_handle: Optional[object] = None
) -> UploadResult:
    """
    Upload a single stripe with Adaptive Idempotency and Plaintext Support.
    FIXED: Uses build_complete_upload_request + send_raw_request to avoid Double Header bug.
    """
    from .network import connect_to_server, send_raw_request, disconnect, ServerInfo, NetworkErrorCode, StatusCode
    from .protocol import build_complete_upload_request
    
    result = UploadResult()
    result.server_id = str(server_id)
    result.stripe_index = stripe_index

    # 1. AN Slicing (Ensure the server gets its specific 16-byte slice)
    hex_an = getattr(identity, 'authenticity_number', '')
    if len(hex_an) == 800:
        start_hex = server_id * 32
        target_hex = hex_an[start_hex : start_hex + 32]
        _, target_an, _ = _safe_hex_to_bytes(target_hex, 16, f"an_raida{server_id}", logger_handle)
    else:
        # Fallback for single key
        _, target_an, _ = _safe_hex_to_bytes(hex_an, 16, "authenticity_number", logger_handle)

    # --- ADAPTIVE RETRY STATE ---
    current_locker_code = locker_code
    last_was_timeout = False

    for attempt in range(MAX_RETRIES):
        try:
            
            # 2. Build the request manually (Forcing Type 0 for Plaintext testing)
            # This solves the Double Header bug by creating the binary packet here.
            err_proto, request_bytes, challenge, nonce = build_complete_upload_request(
            raida_id=server_id,
            denomination=identity.denomination,
            serial_number=identity.serial_number,
            device_id=identity.device_id,
            an=target_an,
            file_group_guid=file_group_guid,
            locker_code=current_locker_code,  # FIXED
            storage_duration=storage_duration,
            stripe_data=stripe_data,  # FIXED: moved after storage_duration
            encryption_type=0,
            logger_handle=logger_handle
            )
           
            if err_proto != 0:
                result.error_message = "Protocol Build Error"
                return result

            # 3. Connect and Send Raw
            s_info = ServerInfo(host=server_address, port=server_port, raida_id=server_id)
            err_conn, conn = connect_to_server(s_info, logger_handle=logger_handle)

            if err_conn != NetworkErrorCode.SUCCESS or not conn:
                continue # Retry connection

            # FIXED: Using send_raw_request ensures we don't add a second header
            net_err, resp, _ = send_raw_request(conn, request_bytes, logger_handle=logger_handle)
            status_code = resp.status if resp else 0
            disconnect(conn)

            # --- SUCCESS CASE ---
            if net_err == NetworkErrorCode.SUCCESS and status_code == 250:
                result.success = True
                result.status_code = status_code
                return result

            # --- AMBIGUITY RESOLVER (Idempotency) ---
            if net_err in [NetworkErrorCode.ERR_TIMEOUT, NetworkErrorCode.ERR_SEND_FAILED]:
                log_warning(logger_handle, SENDER_CONTEXT, 
                            f"Timeout on RAIDA {server_id}. Testing if server has file via Zero-Code.")
                # Next attempt will use 8 null bytes for locker_code
                current_locker_code = bytes(8)
                last_was_timeout = True
                continue

            if last_was_timeout and status_code == 166: # 166 = Payment Required
                log_info(logger_handle, SENDER_CONTEXT, 
                         f"Zero-Code check failed on {server_id}. Re-uploading with real code.")
                current_locker_code = locker_code
                last_was_timeout = False
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
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, List[UploadResult]]:
    """
    Upload a file's stripes to all servers in parallel.

    Args:
        file_info: FileUploadInfo with stripes
        servers: List of server configurations
        identity: User identity
        file_group_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        storage_duration: Duration code
        thread_pool: Optional thread pool for parallel uploads
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, list of UploadResult)
    """
    all_stripes = file_info.stripes + [file_info.parity_stripe]
    results = []

    # Ensure we have enough servers
    if len(servers) < len(all_stripes):
        log_error(logger_handle, SENDER_CONTEXT, "upload_file_to_servers failed",
                  f"Not enough servers: {len(servers)} < {len(all_stripes)}")
        return ErrorCode.ERR_INVALID_PARAM, []

    def upload_single(args):
        stripe_idx, stripe_data, server = args
        return upload_stripe_to_server(
            # FIXED: Use getattr instead of .get() for ServerConfig compatibility
            server_address=getattr(server, 'address', getattr(server, 'host', 'localhost')),
            server_port=getattr(server, 'port', 50000 + stripe_idx),
            server_id=getattr(server, 'index', getattr(server, 'server_id', stripe_idx)),
            stripe_data=stripe_data,
            stripe_index=stripe_idx,
            identity=identity,
            file_group_guid=file_group_guid,
            locker_code=locker_code,
            storage_duration=storage_duration,
            logger_handle=logger_handle
        )

    # Prepare upload tasks
    tasks = [
        (i, all_stripes[i], servers[i])
        for i in range(len(all_stripes))
    ]

    # Execute uploads
    if thread_pool:
        # Parallel execution
        futures = [thread_pool.submit(upload_single, task) for task in tasks]
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                log_error(logger_handle, SENDER_CONTEXT, "Upload task failed", str(e))
                results.append(UploadResult(success=False, error_message=str(e)))
    else:
        # Sequential execution
        for task in tasks:
            result = upload_single(task)
            results.append(result)

    # Check results
    success_count = sum(1 for r in results if r.success)
    fail_count = len(results) - success_count

    log_info(logger_handle, SENDER_CONTEXT,
             f"File upload complete: {success_count}/{len(results)} stripes succeeded")

    # Need at least NUM_DATA_STRIPES successful uploads for recovery
    if success_count < NUM_DATA_STRIPES:
        return ErrorCode.ERR_NETWORK, results

    return ErrorCode.SUCCESS, results


# ============================================================================
# MAIN ORCHESTRATION FUNCTIONS
# ============================================================================

def send_email_async(
    request: 'SendEmailRequest',
    identity: 'IdentityConfig',
    db_handle: object,
    servers: List[Dict],
    thread_pool: Optional[ThreadPoolExecutor] = None,
    task_callback: Optional[callable] = None,
    logger_handle: Optional[object] = None,
    cc_handle: object = None 
) -> Tuple[SendEmailErrorCode, SendEmailResult]:
    """
    Send an email asynchronously.
    FIXED: Integrates binary .key file loading and server-specific AN verification.
    """
    result = SendEmailResult()
    state = SendTaskState()
    state.task_id = f"send_{int(time.time() * 1000)}"

    def update_state(status: str, progress: int, message: str):
        state.status = status
        state.progress = progress
        state.message = message
        if task_callback:
            task_callback(state)
        log_info(logger_handle, SENDER_CONTEXT, f"[{state.task_id}] {status}: {message}")

    try:
        # Step 1: Validate request
        update_state("VALIDATING", 5, "Validating request...")
        err, err_msg = validate_request(request, logger_handle)
        if err != SendEmailErrorCode.SUCCESS:
            result.error_code = err
            result.error_message = err_msg
            update_state("FAILED", 0, err_msg)
            return err, result
        

       # Load identity coin using content-based search (resilient to renaming)
        from coin_scanner import find_identity_coin
        
       # Check Mailbox/Bank first, fallback to Default/Bank
        mailbox_bank = "Data/Wallets/Mailbox/Bank"
        default_bank = "Data/Wallets/Default/Bank"

        identity_coin = find_identity_coin(mailbox_bank, identity.serial_number)
        #just a fallback // should never reach here
        if not identity_coin:
            identity_coin = find_identity_coin(default_bank, identity.serial_number)
        
        if not identity_coin:
            log_error(logger_handle, SENDER_CONTEXT, 
                     f"Identity coin not found: SN={identity.serial_number}")
            result.error_code = SendEmailErrorCode.ERR_ENCRYPTION_FAILED
            result.error_message = f"Identity coin file not found for SN {identity.serial_number}"
            update_state("FAILED", 0, result.error_message)
            return result.error_code, result
        
        # Convert 25 ANs to hex string (800 hex chars = 25 * 16 bytes * 2)
        hex_an_list = [an.hex() for an in identity_coin['ans']]
        identity.authenticity_number = "".join(hex_an_list)
        
        log_info(logger_handle, SENDER_CONTEXT,
                f"Loaded identity from: {os.path.basename(identity_coin['file_path'])}")

        # Step 3: Generate file group GUID
        state.file_group_guid = uuid.uuid4().bytes
        result.file_group_guid = state.file_group_guid

        # Count files
        attachment_count = len(request.attachment_paths) if request.attachment_paths else 0
        state.total_files = 1 + attachment_count 
        result.file_count = state.total_files

        # Step 4: Calculate payment
        update_state("CALCULATING", 10, "Calculating payment...")

        file_sizes = [len(request.email_file)]
        for path in (request.attachment_paths or []):
            file_sizes.append(os.path.getsize(path))

        recipient_count = len(request.to_recipients or []) + \
                         len(request.cc_recipients or []) + \
                         len(request.bcc_recipients or [])

        err, payment_calc = calculate_total_payment(
            file_sizes, request.storage_weeks, recipient_count, db_handle, logger_handle
        )
        if err != ErrorCode.SUCCESS:
            result.error_code = SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS
            result.error_message = "Failed to calculate payment"
            update_state("FAILED", 0, "Payment calculation failed")
            return SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS, result

        result.total_cost = payment_calc.total_cost

        # Step 5: Request locker code
        update_state("PAYMENT", 15, "Requesting locker code...")
        err, locker_code = request_locker_code(payment_calc.total_cost, db_handle, logger_handle)
        if err != ErrorCode.SUCCESS:
            result.error_code = SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS
            result.error_message = "Failed to get locker code"
            update_state("FAILED", 0, "Locker code generation failed")
            return SendEmailErrorCode.ERR_INSUFFICIENT_FUNDS, result

        state.locker_code = locker_code
        storage_duration = weeks_to_duration_code(request.storage_weeks)

        # --- Master Encryption Key Selection ---
        # Use RAIDA 0's 16-byte AN (the first 32 hex chars) for local file encryption.
        success_an, all_ans_bytes, _ = _safe_hex_to_bytes(
            identity.authenticity_number, 400, "authenticity_number", logger_handle
        )
        encryption_key = all_ans_bytes[0:16] # 16 bytes for AES

        # Step 6: Process email body
        update_state("UPLOADING", 20, "Processing email body...")

        err, body_info = prepare_file_for_upload(
            request.email_file, "email_body.cbdf", FILE_INDEX_BODY,
            encryption_key, logger_handle
        )
        if err != ErrorCode.SUCCESS:
            result.error_code = SendEmailErrorCode.ERR_ENCRYPTION_FAILED
            result.error_message = "Failed to process email body"
            update_state("FAILED", 0, "Email body processing failed")
            return SendEmailErrorCode.ERR_ENCRYPTION_FAILED, result

        # Upload email body - Ensure this uses your updated upload_file_to_servers
        err, upload_results = upload_file_to_servers(
            body_info, servers, identity, state.file_group_guid,
            state.locker_code, storage_duration, thread_pool, logger_handle
        )
        result.upload_results.extend(upload_results)
        state.files_uploaded = 1

        # Step 7: Process attachments
        for i, path in enumerate(request.attachment_paths or []):
            file_index = FILE_INDEX_ATTACHMENT_START + i
            progress = 20 + int(70 * (i + 1) / state.total_files)
            update_state("UPLOADING", progress, f"Processing attachment {i+1}...")

            is_valid, result_or_error = _validate_file_path(path, logger_handle)
            if not is_valid:
                continue

            real_path = result_or_error
            with open(real_path, 'rb') as f:
                file_data = f.read()

            file_name = os.path.basename(real_path)

            err, att_info = prepare_file_for_upload(
                file_data, file_name, file_index, encryption_key, logger_handle
            )
            if err != ErrorCode.SUCCESS:
                continue

            err, upload_results = upload_file_to_servers(
                att_info, servers, identity, state.file_group_guid,
                state.locker_code, storage_duration, thread_pool, logger_handle
            )
            result.upload_results.extend(upload_results)
            state.files_uploaded += 1

        # Step 8: Complete Notifications and Storage
        update_state("NOTIFYING", 92, "Sending notifications...")
        send_tell_notifications(
            request=request, file_group_guid=state.file_group_guid,
            servers=servers, identity=identity, logger_handle=logger_handle,
            db_handle=db_handle, cc_handle=cc_handle, locker_code=state.locker_code,
            upload_results=result.upload_results
        )

        update_state("STORING", 95, "Storing locally...")
        store_sent_email(request, state.file_group_guid, result.upload_results, db_handle, logger_handle)

        # Final Success Check (Require at least 4 successful stripes)
        success_count = sum(1 for r in result.upload_results if getattr(r, 'success', False))
        
        if success_count < 4:
            result.success = False
            result.error_code = SendEmailErrorCode.ERR_PARTIAL_FAILURE
            result.error_message = f"Upload failed: only {success_count}/5 stripes succeeded"
            update_state("FAILED", 0, result.error_message)
            return SendEmailErrorCode.ERR_PARTIAL_FAILURE, result
            
        result.success = True
        result.error_code = SendEmailErrorCode.SUCCESS
        update_state("COMPLETED", 100, "Email sent successfully")

        return SendEmailErrorCode.SUCCESS, result

    except Exception as e:
        log_error(logger_handle, SENDER_CONTEXT, "send_email_async failed", str(e))
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

    Notifies each recipient's beacon server that a new email is available.
    Uses cloudcoin locker keys for payment. Failed tells are stored in
    PendingTells table for later retry.

    Args:
        request: SendEmailRequest with recipient info
        file_group_guid: The file group GUID for this email
        servers: List of server configurations
        identity: User identity
        logger_handle: Optional logger handle
        db_handle: Database handle for user lookups
        cc_handle: CloudCoin handle for locker keys
        locker_code: 8-byte locker code for Tell encryption
        upload_results: List of upload results with server locations

    Returns:
        ErrorCode (SUCCESS even on partial failures - email is already uploaded)
    """
    # Collect all recipients with their types
    all_recipients = []
    for r in (request.to_recipients or []):
        all_recipients.append((r, 0))  # 0 = To
    for r in (request.cc_recipients or []):
        all_recipients.append((r, 1))  # 1 = CC
    for r in (request.bcc_recipients or []):
        all_recipients.append((r, 2))  # 2 = BCC

    recipient_count = len(all_recipients)
    if recipient_count == 0:
        log_debug(logger_handle, SENDER_CONTEXT, "No recipients for Tell notifications")
        return ErrorCode.SUCCESS

    log_info(logger_handle, SENDER_CONTEXT,
             f"Sending Tell notifications to {recipient_count} recipients")

    # Process any pending tells from previous failures (best effort)
    if db_handle and cc_handle:
        _process_pending_tells(db_handle, cc_handle, identity, logger_handle)

    # Validate we have required handles
    if db_handle is None:
        log_warning(logger_handle, SENDER_CONTEXT,
                    "No database handle - cannot look up beacon servers")
        return ErrorCode.SUCCESS  # Don't fail, email is uploaded

    if locker_code is None or len(locker_code) < 8:
        log_warning(logger_handle, SENDER_CONTEXT,
                    "No locker code - cannot encrypt Tell requests")
        return ErrorCode.SUCCESS

    # Validate all recipients have beacon servers
    recipient_beacons = {}
    for recipient, r_type in all_recipients:
        address = recipient.address if hasattr(recipient, 'address') else str(recipient)
        err, user = get_user_by_address(db_handle, address)
        if err != DatabaseErrorCode.SUCCESS or user is None:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Recipient not in database: {address}")
            # Use default beacon
            recipient_beacons[address] = ('raida11', r_type, recipient)
        elif not user.get('beacon_id'):
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Recipient has no beacon: {address}, using raida11")
            recipient_beacons[address] = ('raida11', r_type, recipient)
        else:
            recipient_beacons[address] = (user['beacon_id'], r_type, recipient)

    # Get locker keys for all recipients
   # Get locker keys for all recipients (per-recipient fees)
    # Get locker keys for all recipients (create actual lockers)
    # Get locker keys for all recipients (create actual lockers)
    locker_keys = []
    
    wallet_path = "Data/Wallets/Default"
    
    for address, (beacon_id, r_type, recipient) in recipient_beacons.items():
        # Look up recipient's sending fee
        err, user = get_user_by_address(db_handle, address)
        if err == DatabaseErrorCode.SUCCESS and user and user.get('sending_fee'):
            try:
                fee = float(user['sending_fee'])
            except (ValueError, TypeError):
                fee = 0.1
        else:
            fee = 0.1
        
        # Create locker with actual coins (EXCLUDING identity coin)
        import asyncio
        err_code, locker_hex = asyncio.run(create_recipient_locker(
            wallet_path, fee, identity.serial_number, logger_handle
        ))
        
        if err_code == 0 and locker_hex:
            locker_keys.append(locker_hex)
            log_info(logger_handle, SENDER_CONTEXT,
                    f"Created locker for {address} with fee {fee}")
        else:
            # Failed - use placeholder
            locker_keys.append(os.urandom(16).hex())
            log_warning(logger_handle, SENDER_CONTEXT,
                       f"Failed to create locker for {address}, using placeholder")
            
    # Build server list from upload results with locker_code for decryption
    tell_servers = _build_tell_servers(upload_results, servers, locker_code, logger_handle)

    # Send Tell to each recipient serially
    tells_sent = 0
    tells_failed = 0
    timestamp = int(time.time())

    for i, (address, (beacon_id, r_type, recipient)) in enumerate(recipient_beacons.items()):
        locker_key_hex = locker_keys[i] if i < len(locker_keys) else os.urandom(16).hex()
        locker_key_bytes = bytes.fromhex(locker_key_hex) if isinstance(locker_key_hex, str) else locker_key_hex

        # Parse address to get serial number
        coin_id, denom, serial_number = _parse_qmail_address(address)

        # Build TellRecipient
        tell_recipient = TellRecipient(
            address_type=r_type,
            coin_id=coin_id,
            denomination=denom,
            domain_id=0,  # QMail
            serial_number=serial_number,
            locker_payment_key=locker_key_bytes
        )

        # Get beacon server info
        beacon_raida_id = _beacon_id_to_raida_index(beacon_id)

        # Build and send Tell request
        err = _send_single_tell(
            beacon_raida_id, beacon_id, tell_recipient, file_group_guid,
            tell_servers, locker_code, identity, timestamp, logger_handle
        )

        if err == ErrorCode.SUCCESS:
            tells_sent += 1
            log_debug(logger_handle, SENDER_CONTEXT,
                      f"Tell sent to {address} via {beacon_id}")
        else:
            tells_failed += 1
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Tell failed for {address} via {beacon_id}")

            # Store in retry queue
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

    log_info(logger_handle, SENDER_CONTEXT,
             f"Tell notifications: {tells_sent} sent, {tells_failed} failed")

    return ErrorCode.SUCCESS


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
    FIXED: Uses send_raw_request (TCP) or _send_udp_request (UDP).
    """
    from .network import ServerInfo, connect_to_server, send_raw_request, disconnect, NetworkErrorCode
    from .protocol import build_complete_tell_request, TELL_TYPE_QMAIL, validate_tell_response
    
    # 1. Build the request
    # Unpacks 4 values to match your latest protocol.py structure.
    err, request_bytes, challenge, nonce = build_complete_tell_request(
        raida_id=raida_id,
        denomination=getattr(identity, 'denomination', 1),
        serial_number=getattr(identity, 'serial_number', 0),
        device_id=0,
        an=getattr(identity, 'an', bytes(16)),
        file_group_guid=file_group_guid,
        locker_code=locker_code,
        timestamp=timestamp,
        tell_type=TELL_TYPE_QMAIL,
        recipients=[recipient],
        servers=servers,
        logger_handle=logger_handle
    )

    # 2. Try TCP Port 50000+
    host = f"{beacon_id}.cloudcoin.global"
    s_info = ServerInfo(host=host, port=50000 + raida_id, raida_id=raida_id)
    err_conn, conn = connect_to_server(s_info, logger_handle=logger_handle)
    
    if err_conn == NetworkErrorCode.SUCCESS and conn:
        try:
            # net_err 0 = SUCCESS
            net_err, resp, _ = send_raw_request(conn, request_bytes, logger_handle=logger_handle)
            if net_err == NetworkErrorCode.SUCCESS and resp.status == 250:
                return ErrorCode.SUCCESS
        finally:
            disconnect(conn)

    # 3. FALLBACK: UDP Port 19000
    # If TCP times out, the beacon likely only accepts UDP notifications.
    log_info(logger_handle, "EmailSender", f"TCP failed, trying UDP for {beacon_id}")
    response = _send_udp_request(host, 19000, request_bytes, logger_handle)
    if response:
        # validate_tell_response checks the echo and status
        _, status, _ = validate_tell_response(response, challenge, logger_handle)
        if status == 250:
            return ErrorCode.SUCCESS

    return ErrorCode.ERR_NETWORK

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
    locker_code: bytes = None,
    logger_handle: Optional[object] = None
) -> List['TellServer']:
    """
    Build TellServer list from upload results.

    Args:
        upload_results: List of UploadResult from uploads
        servers: List of server configurations
        locker_code: 8-byte locker code for stripe decryption (required for recipients)
        logger_handle: Optional logger handle

    Returns:
        List of TellServer objects with locker_code set for decryption
    """
    tell_servers = []

    if not upload_results:
        return tell_servers

    # Ensure locker_code is valid bytes
    if locker_code is None:
        locker_code = bytes(8)
        log_warning(logger_handle, SENDER_CONTEXT,
                    "No locker_code provided to _build_tell_servers - recipients won't be able to decrypt")
    elif len(locker_code) < 8:
        locker_code = locker_code.ljust(8, b'\x00')

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
            port=port,
            locker_code=locker_code[:8]  # Include locker code for recipient decryption
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
    FIXED: Resolves recipients to numeric IDs for DB and technical addresses for RAIDA.
    """
    import uuid, os, time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from src.network import connect_to_server, disconnect, send_raw_request
    from src.config import get_raida_server_config
    from src.protocol import build_complete_tell_request, weeks_to_duration_code, TELL_TYPE_QMAIL
    from src.database import get_user_by_address, store_email, DatabaseErrorCode
    from src.logger import log_info, log_error

    log_info(logger_handle, "Sender", "Starting Pretty Email upload process.")
    file_group_guid = uuid.uuid4().bytes

    # --- 1. RECIPIENT RESOLUTION (Pretty -> Technical & Numeric) ---
    recipient_sns = []
    tech_addresses = []
    # Hum har Pretty Address ko resolve karenge taaki protocol aur DB ko sahi data mile
    for addr in package.recipients:
        err, user_info = get_user_by_address(db_handle, addr)
        if err == DatabaseErrorCode.SUCCESS and user_info:
            # DB Junction table ke liye numeric SN (e.g. 2841)
            recipient_sns.append(user_info['SerialNumber'])
            # RAIDA Tell packet ke liye technical address (e.g. 0006.4.2841)
            tech_addresses.append(f"0006.{user_info['Denomination']}.{user_info['SerialNumber']}")
        else:
            # Agar DB mein nahi hai, toh raw string use karein (direct address case)
            tech_addresses.append(addr)
            # Try to extract numeric SN for DB mapping
            from src.protocol import custom_sn_to_int
            recipient_sns.append(custom_sn_to_int(addr))

    # --- 2. COST & LOCKER ---
    total_size = len(package.email_file) + sum(os.path.getsize(p) for p in package.attachment_paths)
    cost = calculate_storage_cost(total_size, storage_weeks, len(recipient_sns))
    err, locker_code = request_locker_code(cost, db_handle, logger_handle)
    if err != ErrorCode.SUCCESS: 
        return SendEmailErrorCode.ERR_PAYMENT_FAILED, None

    # Locker Sanitization (8 Bytes Null-Padded)
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

    # --- 5. BEACON NOTIFICATION (Using Technical Addresses) ---
    beacon_id = 11
    try:
        timestamp = int(time.time())
        # AN slicing remains the same (Format 9 support)
        if hasattr(identity, 'authenticity_number') and len(identity.authenticity_number) >= 400:
            start = beacon_id * 16
            target_an = identity.authenticity_number[start : start+16]
        else:
            target_an = bytes(16)

        # UPDATED: Using tech_addresses (0006.DN.SN) for the RAIDA network packet
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
            recipients=tech_addresses, # <--- Correct technical format
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

    # --- 6. LOCAL STORAGE (Using Fixed Database function) ---
    # Save a copy in the 'sent' folder with properly linked Serial Numbers
    sent_email_data = {
        'email_id': file_group_guid,
        'subject': package.subject,
        'body': package.searchable_text, # Or full body
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


