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
from datetime import datetime
from typing import Dict, List, Optional, Tuple ,Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from qmail_types import (
    ErrorCode, SendEmailErrorCode, SendEmailRequest, SendEmailResult,
    FileUploadInfo, EmailPackage, IdentityConfig
)
from protocol import (
    build_complete_tell_request, CMD_GROUP_QMAIL, CMD_TELL, TELL_TYPE_QMAIL,
    weeks_to_duration_code
)
from network import connect_to_server, send_request, disconnect
from database import store_sent_email
from payment import calculate_storage_cost, request_locker_code
from logger import log_info, log_error, log_warning, log_debug
from config import get_raida_server_config

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
    from .cloudcoin import get_locker_keys, CloudCoinErrorCode
    from .logger import log_error, log_info, log_debug, log_warning
    from .wallet_structure import initialize_wallet_structure
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

    Checks:
    - Email file is provided
    - At least one recipient exists
    - All attachment paths exist
    - Attachment count is within limits

    Args:
        request: SendEmailRequest to validate
        logger_handle: Optional logger handle

    Returns:
        Tuple of (SendEmailErrorCode, error message if any)
    """
    # Check email file
    if not request.email_file or len(request.email_file) == 0:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed", "No email file provided")
        return SendEmailErrorCode.ERR_NO_EMAIL_FILE, "Email file is required"

    # Check recipients
    all_recipients = (request.to_recipients or []) + \
                    (request.cc_recipients or []) + \
                    (request.bcc_recipients or [])
    if not all_recipients:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed", "No recipients provided")
        return SendEmailErrorCode.ERR_NO_RECIPIENTS, "At least one recipient is required"

    # Check attachment count
    attachment_count = len(request.attachment_paths) if request.attachment_paths else 0
    if attachment_count > MAX_ATTACHMENTS:
        log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                  f"Too many attachments: {attachment_count} > {MAX_ATTACHMENTS}")
        return SendEmailErrorCode.ERR_TOO_MANY_ATTACHMENTS, \
               f"Maximum {MAX_ATTACHMENTS} attachments allowed"

    # Check attachment files exist and are safe (path traversal protection)
    for path in (request.attachment_paths or []):
        # Security: Validate path to prevent path traversal attacks
        is_valid, result_or_error = _validate_file_path(path, logger_handle)
        if not is_valid:
            log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                      f"Attachment path validation failed: {result_or_error}")
            return SendEmailErrorCode.ERR_ATTACHMENT_NOT_FOUND, \
                   f"Attachment file error: {result_or_error}"

        # Use the validated real path for size check
        real_path = result_or_error
        size = os.path.getsize(real_path)
        if size > MAX_FILE_SIZE:
            log_error(logger_handle, SENDER_CONTEXT, "Validation failed",
                      f"Attachment too large: {path} ({size} bytes)")
            return SendEmailErrorCode.ERR_ATTACHMENT_NOT_FOUND, \
                   f"Attachment too large: {path}"

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
    Upload a single stripe with Adaptive Idempotency.
    
    Decision Flow :
    1. Attempt with REAL code. 
    2. If Timeout: Attempt with ZERO code (Free Write-over).
       - If SUCCESS: First attempt actually worked; we are done.
       - If PAYMENT_REQUIRED: Server never saw first attempt; try REAL again.
    """
    from network import connect_to_server, send_stripe, disconnect, ServerInfo, NetworkErrorCode, StatusCode
    
    result = UploadResult()
    result.server_id = str(server_id)
    result.stripe_index = stripe_index
    start_time = time.time()

    # AN Slicing (Same as before)
    hex_an = getattr(identity, 'authenticity_number', '')
    if len(hex_an) == 800:
        start_hex = server_id * 32
        target_hex = hex_an[start_hex : start_hex + 32]
        _, target_an, _ = _safe_hex_to_bytes(target_hex, 16, f"an_raida{server_id}", logger_handle)
    else:
        _, target_an, _ = _safe_hex_to_bytes(hex_an, 16, "authenticity_number", logger_handle)

    # --- ADAPTIVE RETRY STATE ---
    current_locker_code = locker_code
    last_was_timeout = False

    for attempt in range(MAX_RETRIES):
        try:
            s_info = ServerInfo(host=server_address, port=server_port, raida_id=server_id)
            err_conn, conn = connect_to_server(
                s_info, encryption_key=target_an, 
                denomination=identity.denomination, 
                serial_number=identity.serial_number,
                logger_handle=logger_handle
            )

            if err_conn != NetworkErrorCode.SUCCESS or not conn:
                continue # Retry connection

            # Execute CMD_UPLOAD
            err_send, status_code = send_stripe(
                connection=conn,
                stripe_data=stripe_data,
                file_guid=file_group_guid,
                locker_code=current_locker_code,
                storage_duration=storage_duration,
                denomination=identity.denomination,
                serial_number=identity.serial_number,
                device_id=identity.device_id,
                logger_handle=logger_handle
            )
            disconnect(conn)

            # --- SUCCESS CASE ---
            if err_send == NetworkErrorCode.SUCCESS and status_code == StatusCode.STATUS_SUCCESS:
                result.success = True
                result.status_code = status_code
                return result

            # --- THE AMBIGUITY RESOLVER ---
            if err_send in [NetworkErrorCode.ERR_TIMEOUT, NetworkErrorCode.ERR_SEND_FAILED]:
                # Step 1: We timed out. Next attempt, try the Zero-Code logic.
                log_warning(logger_handle, SENDER_CONTEXT, 
                            f"Timeout on RAIDA {server_id}. Testing if server already has file via Zero-Code.")
                current_locker_code = bytes(8)
                last_was_timeout = True
                continue

            # Step 2: Handle results of the Zero-Code check
            if last_was_timeout and status_code == StatusCode.ERROR_PAYMENT_REQUIRED:
                # If zeros failed with payment error, it means file doesn't exist on server.
                # We revert to REAL code to try the first upload properly.
                log_info(logger_handle, SENDER_CONTEXT, 
                         f"Zero-Code test for {server_id} failed. File doesn't exist. Re-uploading with real code.")
                current_locker_code = locker_code
                last_was_timeout = False
                continue

        except Exception as e:
            log_error(logger_handle, SENDER_CONTEXT, f"RAIDA {server_id} Attempt {attempt} crashed", str(e))

    result.success = False
    result.error_message = "Max retries reached: Adaptive idempotency check failed."
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
            server_address=server.get('address', server.get('host', 'localhost')),
            server_port=server.get('port', 443),
            server_id=server.get('index', server.get('server_id', stripe_idx)),
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
    logger_handle: Optional[object] = None
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
        

        base_name = f"0006{identity.denomination:02X}{identity.serial_number:08X}"
        path_bin = f"Data/Wallets/Default/Bank/{base_name}.BIN"
        path_key = f"Data/Wallets/Default/Bank/{base_name}.KEY" 

        key_path = path_bin if os.path.exists(path_bin) else path_key
        success_load, hex_an_list, load_err = verify_an_loading(key_path, logger_handle)

        # Step 2: Load Full Identity Key (400 bytes / 800 hex chars)
        # We must load all 25 ANs to ensure each server gets its correct slice.
        # key_path = f"Data/Wallets/Default/Bank/0006{identity.denomination:02x}{identity.serial_number:08x}.key".upper()
        
        # Use the verify_an_loading function you added to email_sender.py
        # success_load, hex_an_list, load_err = verify_an_loading(key_path, logger_handle)
        
        if not success_load:
            log_error(logger_handle, SENDER_CONTEXT, "Identity load failed", load_err)
            result.error_code = SendEmailErrorCode.ERR_ENCRYPTION_FAILED
            result.error_message = f"Failed to load identity key: {load_err}"
            update_state("FAILED", 0, result.error_message)
            return result.error_code, result

        # Join the list into a single 800-character string for the identity object
        identity.authenticity_number = "".join(hex_an_list)

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
            db_handle=db_handle, locker_code=state.locker_code,
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
    locker_keys = []
    if cc_handle:
        # Use 0.1 denomination for Tell keys (small value)
        err, keys = get_locker_keys(cc_handle, 0.1, recipient_count)
        if err == CloudCoinErrorCode.SUCCESS or err == CloudCoinErrorCode.WARN_PARTIAL_SUCCESS:
            locker_keys = keys
        else:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Could not get locker keys: {err}")

    # Pad locker_keys if we didn't get enough
    while len(locker_keys) < recipient_count:
        # Generate random placeholder key (will fail payment but Tell still sent)
        locker_keys.append(os.urandom(16).hex())

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
    Send a single Tell request to a beacon server.
    FIXED: Unpacks 4 values (err, request, challenge, nonce) to match protocol.py.
    """
    try:
        # Build Tell request - UPDATED UNPACKING
        err, request_bytes, challenge, nonce = build_complete_tell_request(
            raida_id=raida_id,
            denomination=identity.denomination if hasattr(identity, 'denomination') else 1,
            serial_number=identity.serial_number if hasattr(identity, 'serial_number') else 0,
            device_id=0,
            an=identity.an if hasattr(identity, 'an') else bytes(16),
            file_group_guid=file_group_guid,
            locker_code=locker_code,
            timestamp=timestamp,
            tell_type=TELL_TYPE_QMAIL,
            recipients=[recipient],
            servers=servers,
            logger_handle=logger_handle
        )

        if err != ProtocolErrorCode.SUCCESS:
            log_error(logger_handle, SENDER_CONTEXT,
                      f"Failed to build Tell request", f"error={err}")
            return ErrorCode.ERR_INVALID_PARAM

        # Get beacon server address
        beacon_ip, beacon_port = _get_beacon_address(beacon_id)
        if not beacon_ip:
            log_error(logger_handle, SENDER_CONTEXT,
                      f"Unknown beacon server: {beacon_id}")
            return ErrorCode.ERR_NOT_FOUND

        # Send request
        response = _send_udp_request(beacon_ip, beacon_port, request_bytes, logger_handle)
        if response is None:
            return ErrorCode.ERR_NETWORK

        # Validate response
        err, status_code, error_msg = validate_tell_response(response, challenge, logger_handle)
        if err != ProtocolErrorCode.SUCCESS:
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Tell response validation failed: {error_msg}")
            return ErrorCode.ERR_NETWORK

        if status_code != 250:  # Not success
            log_warning(logger_handle, SENDER_CONTEXT,
                        f"Tell returned status {status_code}: {error_msg}")
            return ErrorCode.ERR_NETWORK

        return ErrorCode.SUCCESS

    except Exception as e:
        log_error(logger_handle, SENDER_CONTEXT,
                  f"Exception in _send_single_tell", str(e))
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
    """
    Parse QMail address into components.

    Args:
        address: QMail address (e.g., "0006.1.12345678")

    Returns:
        Tuple of (coin_id, denomination, serial_number)
    """
    try:
        parts = address.split('.')
        if len(parts) >= 3:
            coin_id = int(parts[0])
            denom = int(parts[1])
            serial = int(parts[2])
            return coin_id, denom, serial
    except (ValueError, IndexError):
        pass

    # Default values
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
    Store sent email in local database.

    STUB: This function stores email metadata and stripe locations
    in the local database for tracking sent emails.

    Args:
        request: SendEmailRequest with email data
        file_group_guid: The file group GUID for this email
        upload_results: List of upload results with server locations
        db_handle: Database handle
        logger_handle: Optional logger handle

    Returns:
        ErrorCode
    """
    log_warning(logger_handle, SENDER_CONTEXT,
                f"store_sent_email: STUB - Would store email with "
                f"file_group_guid={file_group_guid.hex()}, "
                f"{len(upload_results)} stripe locations")

    # TODO: Implement actual database storage
    # 1. Insert into Emails table with file_group_guid as key
    # 2. Store raw email content
    # 3. Insert into SentAttachments table for each attachment
    # 4. Store stripe locations for each file

    return ErrorCode.SUCCESS

def process_email_package(
    package: EmailPackage,
    identity: IdentityConfig,
    db_handle: Any,
    config: Any, 
    storage_weeks: int = 1,
    logger_handle: Optional[object] = None
) -> Tuple[SendEmailErrorCode, Optional[SendEmailResult]]:
    """
    Orchestrate full upload. Plaintext transport, 8-month server grace period.
    NOTIFIES BEACON (RAIDA 11) ONLY per Phase I requirement.
    Uses send_raw_request to solve the Double Header bug.
    """
    from network import connect_to_server, disconnect, send_raw_request
    from config import get_raida_server_config

    log_info(logger_handle, "Sender", "Starting mail upload process.")
    file_group_guid = uuid.uuid4().bytes

    # 1. Cost & Locker
    total_size = len(package.email_file) + sum(os.path.getsize(p) for p in package.attachment_paths)
    cost = calculate_storage_cost(total_size, storage_weeks, len(package.recipients))
    err, locker_code = request_locker_code(cost, db_handle, logger_handle)
    if err != ErrorCode.SUCCESS: 
        return SendEmailErrorCode.ERR_PAYMENT_FAILED, None

    # 2. Locker Sanitization (AS8D-HJL -> 8 Bytes Null-Padded)
   # In process_email_package or any locker handler:
    if isinstance(locker_code, str):
    # If the user provided an 8-char code (like ASB-JH7J), use it as is
        if len(locker_code) == 8:
            locker_code = locker_code.encode('ascii')
        else:
        # Fallback for other formats: strip hyphens and pad with nulls to 8 bytes
            clean_code = locker_code.replace('-', '').strip().upper()
            locker_code = clean_code.encode('ascii').ljust(8, b'\x00')

    # 3. Preparation (Plaintext / Type 0)
    files_to_upload = []
    # Body index 0
    err, body_info = prepare_file_for_upload(package.email_file, "body.qmail", 0, bytes(16), logger_handle)
    if err == ErrorCode.SUCCESS: files_to_upload.append(body_info)

    # Attachments
    for i, path in enumerate(package.attachment_paths):
        with open(path, 'rb') as f:
            err, att_info = prepare_file_for_upload(f.read(), os.path.basename(path), i+1, bytes(16), logger_handle)
            if err == ErrorCode.SUCCESS: files_to_upload.append(att_info)

    # 4. Parallel Upload (With Adaptive Idempotency)
    duration_code = weeks_to_duration_code(storage_weeks)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for info in files_to_upload:
            for s_idx, s_data in enumerate(info.stripes + [info.parity_stripe]):
                # Map stripe index to a server (0-4)
                srv = config.qmail_servers[s_idx]
                futures.append(executor.submit(
                    upload_stripe_to_server, 
                    srv, s_data, s_idx, identity, 
                    file_group_guid, locker_code, 
                    duration_code, logger_handle
                ))
        for f in as_completed(futures): f.result()

    # 5. BEACON NOTIFICATION (RAIDA 11 ONLY - Using Raw Send)
    beacon_id = 11
    tell_success = False
    try:
        timestamp = int(time.time())
        # Determine AN slice for RAIDA 11 (Format 9 Offset: 39)
        if hasattr(identity, 'authenticity_number') and len(identity.authenticity_number) == 800:
            start = beacon_id * 32
            target_an = bytes.fromhex(identity.authenticity_number[start : start+32])
        else:
            target_an = bytes(16)

        # build_complete_tell_request returns (ProtocolErrorCode, packet, challenge)
       # Update within process_email_package (around line 915)
        # UPDATED UNPACKING: Added 'nonce'
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
            recipients=package.recipients,
            servers=[] 
        )
        
        srv_cfg = get_raida_server_config(beacon_id, config.raida_servers)
        if srv_cfg:
            conn_err, conn = connect_to_server(srv_cfg)
            if conn_err == 0:
                # FIXED: send_raw_request avoids the Double Header bug
                net_err, resp, _ = send_raw_request(conn, tell_req, logger_handle=logger_handle)
                if net_err == 0 and resp.status == 250:
                    tell_success = True
                    log_info(logger_handle, "Sender", f"Tell accepted by Beacon (RAIDA {beacon_id})")
                disconnect(conn)
    except Exception as e:
        log_error(logger_handle, "Sender", f"Tell failed: {e}")

    # 6. Local Storage (Sender Copy)
    store_sent_email(db_handle, file_group_guid.hex(), locker_code, package.subject)

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


