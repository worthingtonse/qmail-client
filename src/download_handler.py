"""
download_handler.py - Download Email Handler for QMail Client Core

This module orchestrates the download of emails and attachments from QMail servers.
It handles parallel stripe downloads, parity recovery, and reassembly.

Original Stub Author: Gemini
Completed by: Claude Opus 4.5
Version: 1.0.0

Flow:
    1. Fetch tell metadata from database (file_guid, locker_code, server list)
    2. Generate decryption keys from locker code
    3. Download stripes in parallel from servers
    4. Handle pagination for large files (64KB pages)
    5. Perform parity recovery if any stripe fails
    6. Reassemble stripes using bit-interleaved striping
    7. Decrypt and return final data
"""

import asyncio
import os
import struct
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass

# Import from package
try:
    from . import database
    from . import key_manager
    from . import network_async
    from . import parity
    from . import striping
    from .protocol import (
        build_complete_download_request, validate_download_response,
        decrypt_payload, DOWNLOAD_PAGE_SIZE, ProtocolErrorCode
    )
    from logger import log_error, log_info, log_debug, log_warning
    from network import ServerInfo
    from qmail_types import Stripe
    from wallet_structure import initialize_wallet_structure
except ImportError:
    # Fallback for standalone testing
    import database
    import key_manager
    import network_async
    import parity
    import striping
    from protocol import (
        build_complete_download_request, validate_download_response,
        decrypt_payload, DOWNLOAD_PAGE_SIZE, ProtocolErrorCode
    )
    from dataclasses import dataclass as Stripe

    def log_error(h, c, m, r=None): print(f"[ERROR] [{c}] {m}: {r}")
    def log_info(h, c, m): print(f"[INFO] [{c}] {m}")
    def log_debug(h, c, m): print(f"[DEBUG] [{c}] {m}")
    def log_warning(h, c, m): print(f"[WARNING] [{c}] {m}")

    @dataclass
    class ServerInfo:
        host: str
        port: int
        raida_id: int = 0

    from wallet_structure import initialize_wallet_structure


DOWNLOAD_CONTEXT = "DownloadHandler"


@dataclass
class DownloadResult:
    success: bool
    data: bytes = b''
    status: int = 0  # Added to track RAIDA status (e.g., 250 or 200)
    error_message: str = ''
    stripes_downloaded: int = 0
    stripes_recovered: int = 0


@dataclass
class StripeDownloadResult:
    """Result from downloading a single stripe."""
    server_id: int
    stripe_index: int
    success: bool
    data: bytes = b''
    error_message: str = ''


async def download_file(
    db_handle: database.DatabaseHandle,
    file_guid: str,
    file_type: int = 0,
    denomination: int = 1,
    serial_number: int = 0,
    device_id: int = 0,
    an: bytes = None
) -> Tuple[bytes, int]:
    """
    Orchestrates the download.
    FIXED: Returns (data, status) to match api_handlers.py expectations.
    """
    log_info(db_handle.logger, DOWNLOAD_CONTEXT, f"Starting download: {file_guid}")

    # 1. Fetch Metadata (IP and Port parsed from the Tell Notification)
    err, tell_info = database.get_received_tell_by_guid(db_handle, file_guid)
    if err != database.DatabaseErrorCode.SUCCESS or tell_info is None:
        return b'', 404

    locker_code = tell_info['locker_code']
    if isinstance(locker_code, str):
        # Preserve case and hyphen for Go compatibility
        locker_code = locker_code.strip().encode('ascii')

    err, stripes_info = database.get_stripes_for_tell(db_handle, tell_info['id'])

    # 2. Build server list using ports from the Tell
    servers = []
    for stripe in stripes_info:
        server_info = ServerInfo(
            host=stripe['server_ip'],
            port=stripe['port'],  # Use port from Tell metadata
            raida_id=stripe['stripe_id']
        )
        servers.append({
            'info': server_info,
            'stripe_id': stripe['stripe_id'],
            'is_parity': stripe.get('is_parity', False)
        })

    # 3. Download Stripes (Encryption Type 0 / Plaintext)
    file_guid_bytes = bytes.fromhex(file_guid.replace('-', ''))
    
    result = await download_all_stripes(
        data_servers=[s for s in servers if not s['is_parity']],
        parity_servers=[s for s in servers if s['is_parity']],
        file_guid=file_guid_bytes,
        locker_code=locker_code,
        file_type=file_type,
        denomination=denomination,
        serial_number=serial_number,
        device_id=device_id,
        an=an or bytes(400), # Expecting full keyring block
        logger_handle=db_handle.logger
    )

    if not result.success:
        return b'', result.status

    return result.data, result.status


async def download_all_stripes(
    data_servers: List[Dict],
    parity_servers: List[Dict],
    file_guid: bytes,
    locker_code: bytes,
    file_type: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    logger_handle: Optional[object] = None
) -> DownloadResult:
    """
    Downloads all stripes in parallel and reassembles the file.
    FIXED: Implements XOR parity recovery and propagates status codes for healing.
    """
    result = DownloadResult(success=False, status=250)
    all_stripe_data = {}
    failed_stripes = []
    
    # 1. Parallel Execution of Data Stripe Downloads
    download_tasks = []
    for server in data_servers:
        task = download_stripe_with_pagination(
            server_info=server['info'],
            file_guid=file_guid,
            locker_code=locker_code,
            file_type=file_type,
            denomination=denomination,
            serial_number=serial_number,
            device_id=device_id,
            an=an,
            stripe_id=server['stripe_id'],
            logger_handle=logger_handle
        )
        download_tasks.append((server['stripe_id'], task))

    # Collect Results
    for stripe_id, task in download_tasks:
        try:
            stripe_res = await task
            if stripe_res.success:
                all_stripe_data[stripe_id] = stripe_res.data
                result.stripes_downloaded += 1
            else:
                # CRITICAL: If any server returns 200 (Invalid AN), track it
                if stripe_res.status == 200:
                    result.status = 200
                failed_stripes.append(stripe_id)
                log_warning(logger_handle, DOWNLOAD_CONTEXT, 
                            f"Stripe {stripe_id} failed with status {stripe_res.status}")
        except Exception as e:
            failed_stripes.append(stripe_id)
            log_error(logger_handle, DOWNLOAD_CONTEXT, f"Stripe {stripe_id} exception: {e}")

    # 2. Parity Recovery: If exactly one data stripe is missing
    if len(failed_stripes) == 1 and parity_servers:
        log_info(logger_handle, DOWNLOAD_CONTEXT, f"Attempting recovery for missing stripe {failed_stripes[0]}")
        
        # Download the parity stripe
        parity_server = parity_servers[0]
        p_res = await download_stripe_with_pagination(
            server_info=parity_server['info'],
            file_guid=file_guid,
            locker_code=locker_code,
            file_type=file_type,
            denomination=denomination,
            serial_number=serial_number,
            device_id=device_id,
            an=an,
            stripe_id=parity_server['stripe_id'],
            logger_handle=logger_handle
        )
        
        if p_res.success:
            missing_id = failed_stripes[0]
            # Perform XOR Recovery Math
            recovered = await recover_stripe_with_parity(
                available_stripes=all_stripe_data,
                parity_data=p_res.data,
                missing_stripe_id=missing_id,
                total_data_stripes=len(data_servers),
                logger_handle=logger_handle
            )
            
            if recovered:
                all_stripe_data[missing_id] = recovered
                result.stripes_recovered += 1
                log_info(logger_handle, DOWNLOAD_CONTEXT, f"Stripe {missing_id} successfully recovered.")
        else:
            log_error(logger_handle, DOWNLOAD_CONTEXT, "Parity server also failed. Cannot recover.")

    # 3. Final Reassembly (Bit-Interleaving)
    if len(all_stripe_data) >= len(data_servers):
        # Sort stripes by index (0, 1, 2, 3) for the Weaver
        sorted_stripes = [all_stripe_data[sid] for sid in sorted(all_stripe_data.keys())]
        
        # Estimate size (sum of all data stripes)
        est_size = sum(len(s) for s in sorted_stripes)
        
        # Call the bit-interleaved reassembler from striping.py
        err, reassembled = striping.reassemble_upload_stripes(sorted_stripes, est_size, logger_handle)
        
        if err == striping.ErrorCode.SUCCESS:
            result.success = True
            result.data = reassembled
            # If we reached this point, we didn't have a fatal authentication error
            if result.status != 200:
                result.status = 250 
        else:
            result.error_message = f"Reassembly failed with error {err}"
    else:
        result.error_message = f"Insufficient stripes: {len(all_stripe_data)}/{len(data_servers)}"

    return result


async def download_stripe_with_pagination(
    server_info: ServerInfo,
    file_guid: bytes,
    locker_code: bytes,
    file_type: int,
    denomination: int,
    serial_number: int,
    device_id: int,
    an: bytes,
    stripe_id: int,
    logger_handle: Optional[object] = None
) -> Any:
    """Handles Encryption Type 0 (Plaintext) download and AN Slicing."""
    from dataclasses import make_dataclass
    Res = make_dataclass("Res", [("success", bool), ("data", bytes), ("status", int)])
    
    all_pages = []
    page_number = 0
    more_pages = True
    final_status = 250

    # 1. AN SLICING (Prove ownership to this specific RAIDA)
    server_an = an[stripe_id * 16 : (stripe_id + 1) * 16] if len(an) >= 400 else an[:16]

    while more_pages:
        # 2. Build Request (Encryption Type 0 / Plaintext)
        err, request, challenge, _ = build_complete_download_request(
            raida_id=stripe_id,
            denomination=denomination,
            serial_number=serial_number,
            device_id=device_id,
            an=server_an,
            file_group_guid=file_guid,
            locker_code=locker_code,
            file_type=file_type,
            page_number=page_number,
            encryption_type=0, # FORCE PLAINTEXT
            logger_handle=logger_handle
        )

        try:
            response = await send_download_request(server_info, request)
            if not response: return Res(False, b'', 0)

            # 3. Validate Response (Status check at Byte 2)
            err, status, data_len, payload = validate_download_response(response, challenge)
            final_status = status
            
            if status != 250:
                return Res(False, b'', status)

            # 4. DECRYPTION BYPASS (Type 0 returns raw bytes from fread)
            all_pages.append(payload)

            if data_len < DOWNLOAD_PAGE_SIZE:
                more_pages = False
            else:
                page_number += 1
        except Exception:
            return Res(False, b'', 0)

    return Res(True, b''.join(all_pages), 250)

async def send_download_request(
    server_info: ServerInfo,
    request: bytes,
    timeout_ms: int = 30000,
    logger_handle: Optional[object] = None
) -> Optional[bytes]:
    """
    Send a download request to a server and receive the response.

    Args:
        server_info: Server to connect to
        request: Complete request bytes
        timeout_ms: Timeout in milliseconds
        logger_handle: Optional logger handle

    Returns:
        Response bytes or None on error
    """
    timeout_s = timeout_ms / 1000.0

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server_info.host, server_info.port),
            timeout=timeout_s
        )

        # Send request
        writer.write(request)
        await writer.drain()

        # Read response (header + body)
        # First read the header (32 bytes)
        header = await asyncio.wait_for(
            reader.readexactly(32),
            timeout=timeout_s
        )

        # Parse body length from header (bytes 22-23 for 128-bit encryption)
        body_length = struct.unpack('>H', header[22:24])[0]
        if body_length == 0xFFFF:
            # Extended length - read 4 more bytes
            ext_len = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=timeout_s
            )
            body_length = struct.unpack('>I', ext_len)[0]

        # Read body
        body = b''
        if body_length > 0:
            body = await asyncio.wait_for(
                reader.readexactly(body_length),
                timeout=timeout_s
            )

        # Close connection
        writer.close()
        await writer.wait_closed()

        return header + body

    except asyncio.TimeoutError:
        log_error(logger_handle, DOWNLOAD_CONTEXT,
                  f"Timeout connecting to {server_info.host}:{server_info.port}")
        return None
    except asyncio.IncompleteReadError:
        log_error(logger_handle, DOWNLOAD_CONTEXT,
                  f"Incomplete response from {server_info.host}:{server_info.port}")
        return None
    except Exception as e:
        log_error(logger_handle, DOWNLOAD_CONTEXT,
                  f"Connection error to {server_info.host}:{server_info.port}", str(e))
        return None


async def recover_stripe_with_parity(
    available_stripes: Dict[int, bytes],
    parity_data: bytes,
    missing_stripe_id: int,
    total_data_stripes: int,
    logger_handle: Optional[object] = None
) -> Optional[bytes]:
    """
    Recover a missing stripe using XOR parity.

    Args:
        available_stripes: Dict of stripe_id -> data for available stripes
        parity_data: The parity stripe data
        missing_stripe_id: ID of the missing stripe to recover
        total_data_stripes: Total number of data stripes expected
        logger_handle: Optional logger handle

    Returns:
        Recovered stripe data or None on failure
    """
    # Verify we have all but one stripe
    if len(available_stripes) != total_data_stripes - 1:
        log_error(logger_handle, DOWNLOAD_CONTEXT,
                  f"Cannot recover: have {len(available_stripes)} stripes, need {total_data_stripes - 1}")
        return None

    # XOR recovery: missing = parity XOR all_other_stripes
    max_len = len(parity_data)
    recovered = bytearray(parity_data)

    for stripe_id, stripe_data in available_stripes.items():
        if stripe_id == missing_stripe_id:
            continue
        # Pad shorter stripes
        padded = stripe_data + b'\x00' * (max_len - len(stripe_data)) if len(stripe_data) < max_len else stripe_data
        for i in range(max_len):
            recovered[i] ^= padded[i]

    log_info(logger_handle, DOWNLOAD_CONTEXT,
             f"Recovered stripe {missing_stripe_id}: {len(recovered)} bytes")

    return bytes(recovered)


def download_file_sync(*args, **kwargs) -> Tuple[bytes, int]:
    """Sync wrapper returning (bytes, status)."""
    return asyncio.run(download_file(*args, **kwargs))


def clean_locker_code(locker_code_16bytes: bytes) -> str:
    """
    Strip null padding from 16-byte locker code to get 8-char human code.
    
    Input: b'XF92KL7P\x00\x00\x00\x00\x00\x00\x00\x00'
    Output: "XF92KL7P"
    """
    # Strip trailing nulls
    cleaned = locker_code_16bytes.rstrip(b'\x00')
    
    # Decode to ASCII string
    return cleaned.decode('ascii', errors='ignore')

async def download_locker_payment(
    app_ctx,
    file_guid: str,
    logger_handle
) -> Tuple[int, Optional[List]]:
    """
    Download the locker payment for a received email.
    FIXED: Uses stake_locker_identity for Go-style naming and target wallet separation.
    """
    from database import get_received_tell_by_guid
    from task_manager import stake_locker_identity
    # from src.locker_download import clean_locker_code
    import os
    
    try:
        # 1. Get tell from database
        err, tell_info = get_received_tell_by_guid(app_ctx.db_handle, file_guid)
        
        if err != 0 or not tell_info:
            log_error(logger_handle, "DownloadHandler", f"Tell not found for GUID: {file_guid}")
            return 1, None
        
        # 2. Extract locker code (16 bytes hex string stored in DB)
        locker_code_hex = tell_info.get('locker_code')
        if not locker_code_hex:
            log_error(logger_handle, "DownloadHandler", "No locker code in tell")
            return 1, None
        
        # 3. Clean to get 8-byte human code
        locker_code_bytes = bytes.fromhex(locker_code_hex)
        # clean_locker_code should return the 8-byte code (e.g. FG9YUE3\0)
        locker_code_8char = clean_locker_code(locker_code_bytes)
        
        # log_info(logger_handle, "DownloadHandler", f"Receiving payment from locker: {locker_code_8char.decode('ascii', 'ignore')}")
        log_info(logger_handle, "DownloadHandler", f"Receiving payment from locker: {locker_code_8char}")
        
        # 4. EXECUTE STAKING (Targeting Default Wallet)
        # We use stake_locker_identity because it handles the 439-byte Format 9 saving
        # and Go-style naming automatically.
        success = stake_locker_identity(
            locker_code_bytes=locker_code_8char,
            app_context=app_ctx,
            target_wallet="Default",  # CRITICAL: Payments go to Default wallet
            logger=logger_handle
        )
        
        if not success:
            log_error(logger_handle, "DownloadHandler", "Consensus failed during payment download.")
            return 2, None
        
        log_info(logger_handle, "DownloadHandler", "✓ Payment coins downloaded and saved to Default/Bank")
        return 0, [] # Return empty list as coins are handled internally by task_manager
        
    except Exception as e:
        log_error(logger_handle, "DownloadHandler", f"Exception downloading payment: {e}")
        return 2, None
# ============================================================================
# BACKGROUND INDEXING STUBS (for future implementation)
# ============================================================================

def index_email_content(email_data: bytes, file_guid: str, db_handle) -> bool:
    """
    Stub for background email indexing.

    TODO: Parse email content (CBDF format) and index:
    - Subject, body text for FTS search
    - Sender/recipient addresses
    - Timestamps
    - Attachment metadata

    Args:
        email_data: Raw email bytes
        file_guid: Email GUID
        db_handle: Database handle

    Returns:
        True on success
    """
    # TODO: Implement email parsing and indexing
    log_debug(db_handle.logger, DOWNLOAD_CONTEXT,
              f"Stub: index_email_content for {file_guid}")
    return True


def extract_attachment_text(attachment_data: bytes, file_type: str) -> str:
    """
    Stub for text extraction from attachments.

    TODO: Implement extraction for:
    - PDF: Use PyPDF2 or pdfplumber
    - Word (.docx): Use python-docx
    - Excel (.xlsx): Use openpyxl

    Args:
        attachment_data: Raw attachment bytes
        file_type: File extension (pdf, docx, xlsx)

    Returns:
        Extracted text for FTS indexing
    """
    # TODO: Implement text extraction
    return ""


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("=" * 60)
    print("download_handler.py - Download Handler Module")
    print("=" * 60)
    print("\nThis module provides async download functionality for QMail.")
    print("Use download_file_sync() for synchronous calls.")
    print("\nStub functions for background indexing are provided:")
    print("  - index_email_content()")
    print("  - extract_attachment_text()")
    print("\nFull testing requires a database with tell information")
    print("and active QMail servers.")
    print("=" * 60)
