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
    from .logger import log_error, log_info, log_debug, log_warning
    from .network import ServerInfo
    from .qmail_types import Stripe
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


DOWNLOAD_CONTEXT = "DownloadHandler"


@dataclass
class DownloadResult:
    """Result from a download operation."""
    success: bool
    data: bytes = b''
    error_message: str = ''
    stripes_downloaded: int = 0
    stripes_recovered: int = 0
    pages_downloaded: int = 0


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
) -> bytes:
    """
    Orchestrates the download of a file from QMail servers.

    Args:
        db_handle: An active database handle.
        file_guid: The file group GUID of the file to download.
        file_type: Type of file (0=email, 10+=attachments)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        an: 16-byte Authenticity Number

    Returns:
        The raw bytes of the reassembled and decrypted file.

    Raises:
        FileNotFoundError: If the tell information for the file is not in the database.
        Exception: For various download, network, or reconstruction errors.
    """
    log_info(db_handle.logger, DOWNLOAD_CONTEXT, f"Starting download for file_guid: {file_guid}")

    # 1. Fetch Metadata
    # =================
    err, tell_info = database.get_received_tell_by_guid(db_handle, file_guid)
    if err != database.DatabaseErrorCode.SUCCESS or tell_info is None:
        raise FileNotFoundError(f"Tell information for file_guid {file_guid} not found in the database.")

    tell_id = tell_info['id']
    locker_code = tell_info['locker_code']

    # Convert locker_code if it's a string (from database)
    if isinstance(locker_code, str):
        locker_code = bytes.fromhex(locker_code)

    err, stripes_info = database.get_stripes_for_tell(db_handle, tell_id)
    if err != database.DatabaseErrorCode.SUCCESS:
        raise Exception(f"Could not retrieve stripe information for tell_id {tell_id}")

    log_info(db_handle.logger, DOWNLOAD_CONTEXT, f"Found {len(stripes_info)} stripes for file {file_guid}")

    # 2. Get Keys
    # ===========
    try:
        decryption_keys = key_manager.get_keys_from_locker_code(locker_code)
    except ValueError as e:
        log_error(db_handle.logger, DOWNLOAD_CONTEXT, f"Failed to generate keys from locker code: {e}")
        raise Exception("Invalid locker code, cannot generate decryption keys.") from e

    # 3. Build server list from stripes info
    # =======================================
    servers = []
    for stripe in stripes_info:
        server_info = ServerInfo(
            host=stripe['server_ip'],
            port=50000,  # Default QMail port
            raida_id=stripe['stripe_id']
        )
        servers.append({
            'info': server_info,
            'stripe_id': stripe['stripe_id'],
            'is_parity': stripe['is_parity']
        })

    # Separate data servers from parity server
    data_servers = [s for s in servers if not s['is_parity']]
    parity_servers = [s for s in servers if s['is_parity']]

    # 4. Download stripes in parallel
    # ================================
    file_guid_bytes = bytes.fromhex(file_guid.replace('-', ''))

    result = await download_all_stripes(
        data_servers=data_servers,
        parity_servers=parity_servers,
        file_guid=file_guid_bytes,
        locker_code=locker_code,
        file_type=file_type,
        denomination=denomination,
        serial_number=serial_number,
        device_id=device_id,
        an=an or bytes(16),
        decryption_keys=decryption_keys,
        logger_handle=db_handle.logger
    )

    if not result.success:
        raise Exception(f"Download failed: {result.error_message}")

    log_info(db_handle.logger, DOWNLOAD_CONTEXT,
             f"Download complete: {len(result.data)} bytes, "
             f"{result.stripes_downloaded} stripes, {result.stripes_recovered} recovered")

    return result.data


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
    decryption_keys: List[bytes],
    logger_handle: Optional[object] = None
) -> DownloadResult:
    """
    Download all stripes in parallel with parity recovery.

    Args:
        data_servers: List of data server info dicts
        parity_servers: List of parity server info dicts
        file_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        file_type: Type of file (0=email, 10+=attachments)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        an: 16-byte Authenticity Number
        decryption_keys: List of 25 decryption keys
        logger_handle: Optional logger handle

    Returns:
        DownloadResult with reassembled data
    """
    result = DownloadResult(success=False)
    all_stripe_data = {}  # stripe_id -> data
    failed_stripes = []

    # 1. Download data stripes in parallel
    # =====================================
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
            decryption_key=decryption_keys[server['stripe_id']] if server['stripe_id'] < len(decryption_keys) else None,
            logger_handle=logger_handle
        )
        download_tasks.append((server['stripe_id'], task))

    # Execute all downloads concurrently
    for stripe_id, task in download_tasks:
        try:
            stripe_result = await task
            if stripe_result.success:
                all_stripe_data[stripe_id] = stripe_result.data
                result.stripes_downloaded += 1
                log_debug(logger_handle, DOWNLOAD_CONTEXT,
                          f"Downloaded stripe {stripe_id}: {len(stripe_result.data)} bytes")
            else:
                failed_stripes.append(stripe_id)
                log_warning(logger_handle, DOWNLOAD_CONTEXT,
                            f"Failed to download stripe {stripe_id}: {stripe_result.error_message}")
        except Exception as e:
            failed_stripes.append(stripe_id)
            log_error(logger_handle, DOWNLOAD_CONTEXT,
                      f"Exception downloading stripe {stripe_id}", str(e))

    # 2. Parity recovery if needed
    # ============================
    if failed_stripes:
        if len(failed_stripes) > 1:
            result.error_message = f"Cannot recover {len(failed_stripes)} failed stripes (max 1 recoverable)"
            return result

        if not parity_servers:
            result.error_message = "No parity server available for recovery"
            return result

        # Download parity stripe
        parity_server = parity_servers[0]
        try:
            parity_result = await download_stripe_with_pagination(
                server_info=parity_server['info'],
                file_guid=file_guid,
                locker_code=locker_code,
                file_type=file_type,
                denomination=denomination,
                serial_number=serial_number,
                device_id=device_id,
                an=an,
                stripe_id=parity_server['stripe_id'],
                decryption_key=decryption_keys[parity_server['stripe_id']] if parity_server['stripe_id'] < len(decryption_keys) else None,
                logger_handle=logger_handle
            )

            if not parity_result.success:
                result.error_message = f"Failed to download parity stripe: {parity_result.error_message}"
                return result

            # Recover the failed stripe using XOR parity
            missing_stripe_id = failed_stripes[0]
            recovered_data = await recover_stripe_with_parity(
                available_stripes=all_stripe_data,
                parity_data=parity_result.data,
                missing_stripe_id=missing_stripe_id,
                total_data_stripes=len(data_servers),
                logger_handle=logger_handle
            )

            if recovered_data:
                all_stripe_data[missing_stripe_id] = recovered_data
                result.stripes_recovered += 1
                log_info(logger_handle, DOWNLOAD_CONTEXT,
                         f"Recovered stripe {missing_stripe_id} using parity")
            else:
                result.error_message = f"Failed to recover stripe {missing_stripe_id}"
                return result

        except Exception as e:
            result.error_message = f"Parity recovery failed: {str(e)}"
            return result

    # 3. Reassemble stripes
    # =====================
    if len(all_stripe_data) == 0:
        result.error_message = "No stripes downloaded"
        return result

    # Sort stripes by ID and extract data
    sorted_stripe_ids = sorted(all_stripe_data.keys())
    sorted_stripes = [all_stripe_data[sid] for sid in sorted_stripe_ids]

    # Calculate original file size from stripe sizes
    # All stripes should be the same size (padded during upload)
    stripe_size = len(sorted_stripes[0]) if sorted_stripes else 0
    num_stripes = len(sorted_stripes)

    # The original file size can be estimated from stripe sizes
    # With bit-interleaving, each byte is spread across stripes
    original_size_estimate = stripe_size * num_stripes

    # Reassemble using bit-interleaving (inverse of create_upload_stripes)
    err, reassembled_data = striping.reassemble_upload_stripes(
        sorted_stripes,
        original_size_estimate,
        logger_handle
    )

    if err != striping.ErrorCode.SUCCESS:
        result.error_message = f"Failed to reassemble stripes: {err}"
        return result

    result.success = True
    result.data = reassembled_data
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
    decryption_key: Optional[bytes],
    logger_handle: Optional[object] = None
) -> StripeDownloadResult:
    """
    Download a complete stripe with pagination support.

    Handles large files by downloading in 64KB pages.

    Args:
        server_info: Server to download from
        file_guid: 16-byte file group GUID
        locker_code: 8-byte locker code
        file_type: Type of file
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        an: 16-byte Authenticity Number
        stripe_id: ID of the stripe to download
        decryption_key: Key for this stripe (from MD5 derivation)
        logger_handle: Optional logger handle

    Returns:
        StripeDownloadResult with complete stripe data
    """
    result = StripeDownloadResult(
        server_id=stripe_id,
        stripe_index=stripe_id,
        success=False
    )

    all_pages = []
    page_number = 0
    more_pages = True

    while more_pages:
        # Build download request
        err, request, challenge, nonce = build_complete_download_request(
            raida_id=stripe_id,
            denomination=denomination,
            serial_number=serial_number,
            device_id=device_id,
            an=an,
            file_group_guid=file_guid,
            locker_code=locker_code,
            file_type=file_type,
            page_number=page_number,
            logger_handle=logger_handle
        )

        if err != ProtocolErrorCode.SUCCESS:
            result.error_message = f"Failed to build download request: {err}"
            return result

        # Send request to server
        try:
            response = await send_download_request(
                server_info=server_info,
                request=request,
                timeout_ms=30000,
                logger_handle=logger_handle
            )

            if response is None:
                result.error_message = f"No response from server {server_info.host}"
                return result

            # Validate and parse response
            err, status, data_len, encrypted_data = validate_download_response(
                response, challenge, logger_handle
            )

            if err != ProtocolErrorCode.SUCCESS:
                result.error_message = f"Invalid response: {err}"
                return result

            if status != 250:
                result.error_message = f"Server returned status {status}"
                return result

            # Decrypt the data with stripe_id as raida_id for proper key derivation
            if encrypted_data and decryption_key:
                err, decrypted_data = decrypt_payload(
                    encrypted_data, locker_code, nonce, stripe_id, logger_handle
                )
                if err != ProtocolErrorCode.SUCCESS:
                    result.error_message = f"Decryption failed: {err}"
                    return result
                all_pages.append(decrypted_data)
            elif encrypted_data:
                all_pages.append(encrypted_data)

            # Check if there are more pages
            if data_len < DOWNLOAD_PAGE_SIZE:
                more_pages = False
            else:
                page_number += 1

            # Safety limit on pages
            if page_number > 1000:
                log_warning(logger_handle, DOWNLOAD_CONTEXT,
                            f"Page limit reached for stripe {stripe_id}")
                more_pages = False

        except Exception as e:
            result.error_message = f"Network error: {str(e)}"
            return result

    # Combine all pages
    result.data = b''.join(all_pages)
    result.success = True
    log_debug(logger_handle, DOWNLOAD_CONTEXT,
              f"Downloaded stripe {stripe_id}: {len(result.data)} bytes in {page_number + 1} pages")

    return result


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


def download_file_sync(
    db_handle: database.DatabaseHandle,
    file_guid: str,
    file_type: int = 0,
    denomination: int = 1,
    serial_number: int = 0,
    device_id: int = 0,
    an: bytes = None
) -> bytes:
    """
    Synchronous wrapper for download_file.

    Use this from non-async code.

    Args:
        Same as download_file()

    Returns:
        The raw bytes of the reassembled and decrypted file.
    """
    return asyncio.run(download_file(
        db_handle, file_guid, file_type,
        denomination, serial_number, device_id, an
    ))


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
