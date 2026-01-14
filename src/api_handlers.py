"""
api_handlers.py - REST API Endpoint Handlers for QMail Client Core

This module contains handler functions for all REST API endpoints.
Handlers are written to match the signature expected by api_server.py:
    handler(request_handler: RequestHandler, context: RequestContext) -> None

Phase I: Stub implementations returning placeholder responses.
Phase II: Replace stubs with real implementations integrating other src/ modules.

Author: Claude Opus 4.5
Date: 2025-12-16
Updated: 2025-12-16 - Added database integration for contacts, list, search
"""

from task_manager import create_task, start_task, complete_task, fail_task
import socket
import time
import json
import re
import socket
from math import ceil
from typing import Any, List, Optional, Tuple, Dict, Union
from task_manager import create_task, start_task, TaskErrorCode
# from aiohttp import web
import os
import threading
import time
import re
import asyncio

# Database imports for real implementations
from database import (
    get_popular_contacts,
    list_emails,
    search_emails,
    get_email_count,
    search_users,
    get_all_servers,
    get_parity_server,
    set_parity_server,
    DatabaseErrorCode,
    # Email management functions
    get_email_metadata,
    get_folder_counts,
    delete_email,
    update_email_flags,
    # Attachment functions
    get_attachments_for_email,
    get_attachment_data,
    # Contact management functions
    get_all_contacts,
    get_contact_by_id,
    delete_contact,
    check_email_exists,
    store_contact,
    # Draft management functions
    update_draft,
    list_drafts,
    store_email,
    retrieve_email
)

# Data sync imports
from data_sync import sync_all, SyncErrorCode, check_client_version

# Wallet structure imports
from wallet_structure import initialize_wallet_structure

# Beacon imports
from beacon import do_peek
from network import NetworkErrorCode

# Download imports
from download_handler import download_file_sync
from database import get_received_tell_by_guid 
from database import DatabaseErrorCode
from logger import log_info, log_error
import os

# Task manager imports
from task_manager import get_task_status, cancel_task, TaskErrorCode
from task_manager import create_task, start_task, complete_task, fail_task, stake_locker_identity

# Note: These handlers receive:
#   - request_handler: Has send_json_response(), send_text_response(), send_error()
#   - context: RequestContext with method, path, query_params, path_params, body, json, headers
#
# Handlers access the database via: request_handler.server_instance.app_context.db_handle


# ============================================================================
# HEALTH / STATUS ENDPOINTS
# ============================================================================

def handle_health(request_handler, context):
    """
    GET /api/health - Health check endpoint

    Returns server status and version information.
    """
    response = {
        "status": "healthy",
        "service": "QMail Client Core",
        "version": "1.0.0-phase1",
        "timestamp": int(time.time())
    }
    request_handler.send_json_response(200, response)


def handle_account_identity(request_handler, context):
    """
    GET /api/account/identity - Get the user's own identity/email address

    Returns the configured identity including the pretty email address.
    """
    app_ctx = request_handler.server_instance.app_context
    identity = app_ctx.config.identity

    # Check if identity is configured
    if not identity.serial_number:
        return request_handler.send_json_response(404, {
            "error": "Identity not configured",
            "message": "Use POST /api/setup/import-credentials to set up your identity"
        })

    # If email_address is not set, try to look it up from the database
    email_address = identity.email_address
    if not email_address and identity.serial_number:
        from src.database import execute_query
        err, rows = execute_query(
            app_ctx.db_handle,
            "SELECT auto_address FROM Users WHERE SerialNumber = ?",
            (identity.serial_number,)
        )
        if err == 0 and rows:
            email_address = rows[0]['auto_address']
            # Update runtime config
            identity.email_address = email_address

    return request_handler.send_json_response(200, {
        "serial_number": identity.serial_number,
        "denomination": identity.denomination,
        "email_address": email_address,
        "device_id": identity.device_id,
        "configured": True
    })


def handle_version_check(request_handler, request_context):
    """
    GET /api/admin/version-check - Check if a new client version is available.
    """
    # Import from config.py - single source of truth
    from config import (
        CLIENT_VERSION,
        DOWNLOAD_URL_WINDOWS,
        DOWNLOAD_URL_MAC,
        DOWNLOAD_URL_LINUX
    )

    app_ctx = request_handler.server_instance.app_context
    logger = app_ctx.logger

    try:
        # data_sync.py wala helper call karo
        update_needed, latest = check_client_version(logger)

        return request_handler.send_json_response(200, {
            "status": "success",
            "current_version": CLIENT_VERSION,
            "latest_version": latest,
            "update_available": update_needed,
            "message": "Mandatory update available!" if update_needed else "Up to date",
            "download_url_windows": DOWNLOAD_URL_WINDOWS,
            "download_url_mac": DOWNLOAD_URL_MAC,
            "download_url_linux": DOWNLOAD_URL_LINUX
        })
    except Exception as e:
        return request_handler.send_json_response(500, {"error": str(e)})


def handle_ping(request_handler, context):
    """
    GET /api/qmail/ping - Manual deep-level Beacon check.
    FIXED: Corrects 'NoneType' errors and removes stale imports.
    """
    import asyncio
    import time
    # Internal imports to avoid start-up crashes
    from src.protocol import build_complete_ping_request, parse_tell_response, custom_sn_to_int
    from src.network_async import connect_async, disconnect_async, send_raw_request_async, NetworkErrorCode
    from src.network import ServerInfo
    from src.logger import log_error, log_info

    app_ctx = getattr(request_handler.server_instance, 'app_context', None)
    if not app_ctx:
        return request_handler.send_json_response(500, {"error": "context_not_found"})

    logger = app_ctx.logger
    identity = getattr(app_ctx.config, 'identity', None)
    if not identity:
        return request_handler.send_json_response(401, {"error": "no_identity_found"})

    # 1. RESOLVE SN (C23 -> 2841)
    numeric_sn = custom_sn_to_int(identity.serial_number) 
    target_raida_index = 11

    try:
        # 2. GET AN BLOCK
        an_block = _get_an_for_download(app_ctx)
        
        # Safe Slicing
        start = target_raida_index * 16
        an_bytes = an_block[start : start + 16] if len(an_block) >= (start + 16) else an_block[:16]
            
    except Exception as e:
        from src.app import move_identity_to_fracked
        log_error(logger, "API", f"Identity AN load failure: {str(e)}. Moving to Fracked.")
        move_identity_to_fracked(identity, app_ctx.beacon_handle, logger)
        return request_handler.send_json_response(401, {"status": "healing", "details": str(e)})

    async def perform_ping_task():
        raida_servers = getattr(app_ctx.config, 'raida_servers', [])
        server_entry = next((s for s in raida_servers if getattr(s, 'index', -1) == target_raida_index), None)
        
        host = getattr(server_entry, 'address', f"raida{target_raida_index}.cloudcoin.global")
        port = getattr(server_entry, 'port', 50011)
        server_info = ServerInfo(host=host, port=port, raida_id=target_raida_index)

        err_conn, conn = await connect_async(server_info, config=app_ctx.config)
        if err_conn != NetworkErrorCode.SUCCESS:
            return {"status": "error", "message": "raida_offline"}

        try:
            # Command 62 - PING
            err_proto, req, _, _ = build_complete_ping_request(
                target_raida_index, identity.denomination, numeric_sn, 0, an_bytes, 0)

            net_err, resp_h, resp_b = await send_raw_request_async(conn, req)

            if net_err != NetworkErrorCode.SUCCESS:
                return {"status": "error", "message": "network_failure"}

            if resp_h.status == 200:
                from src.app import move_identity_to_fracked
                move_identity_to_fracked(identity, app_ctx.beacon_handle, logger)
                return {"status": "healing", "message": "auth_failed"}

            # Parse 
            err_parse, notifications = parse_tell_response(resp_b, logger)
            return {
                "status": "ok",
                "notification_count": len(notifications),
                "messages": [n.to_dict() if hasattr(n, 'to_dict') else str(n) for n in notifications],
                "timestamp": int(time.time())
            }
        finally:
            await disconnect_async(conn)

    try:
        result = asyncio.run(perform_ping_task())
        request_handler.send_json_response(200, result)
    except Exception as e:
        log_error(logger, "API", f"Ping crash: {e}")
        request_handler.send_json_response(500, {"error": str(e)})
# ============================================================================


def handle_mail_send(request_handler, context):
    """
    POST /api/mail/send - Send an email
    RESOLVES: Pretty Addresses (Sean.Worthington@CEO#C23.Giga) to numeric IDs for binary protocol.
    """
    from email_sender import send_email_async, SendEmailErrorCode, validate_request
    from qmail_types import SendEmailRequest
    from task_manager import create_task, start_task, update_task_progress, complete_task, fail_task
    from logger import log_info, log_error
    from database import get_user_by_address, DatabaseErrorCode

    app_ctx = request_handler.server_instance.app_context
    content_type = context.headers.get('Content-Type', '')
    email_data = context.json if context.json else {}
    request_obj = SendEmailRequest()

    # --- 1. FULL PARSING LOGIC (Multipart vs JSON) ---
    if 'multipart/form-data' in content_type.lower():
        form_data = email_data
        request_obj.email_file = form_data.get('email_file', b'')
        request_obj.searchable_text = form_data.get('searchable_text', '')
        request_obj.subject = form_data.get('subject', '')
        raw_recipients = form_data.get('to', [])
        request_obj.attachment_paths = form_data.get('attachments', [])
    else:
        if not email_data.get("to") or not email_data.get("subject"):
            return request_handler.send_json_response(400, {"error": "Missing 'to' or 'subject'", "status": "error"})
        
        body_text = email_data.get('body', '')
        request_obj.email_file = body_text.encode('utf-8') if body_text else b''
        request_obj.searchable_text = body_text
        request_obj.subject = email_data.get('subject', '')
        raw_recipients = email_data.get('to', [])
        request_obj.storage_weeks = int(email_data.get('storage_weeks', 8))

    # --- 2. PRETTY ADDRESS RESOLUTION ---
    # Convert "Pretty Name" into actual QMail technical addresses for the protocol
    if isinstance(raw_recipients, str): raw_recipients = [raw_recipients]
    resolved_to = []
    
    for addr in raw_recipients:
        # DB lookup for Sean.Worthington@CEO#C23.Giga
        err, user_info = get_user_by_address(app_ctx.db_handle, addr)
        if err == DatabaseErrorCode.SUCCESS and user_info:
            # FIXED: Use lowercase keys 'denomination' and 'serial_number' matching database.py
            # Use .get() for safety against capitalization changes
            denom = user_info.get('denomination', user_info.get('Denomination', 0))
            sn = user_info.get('serial_number', user_info.get('SerialNumber', 0))
            
            # Pass Technical Address (0006.D.SN) so email_sender can parse it easily
            tech_addr = f"0006.{denom}.{sn}"
            resolved_to.append(tech_addr)
        else:
            resolved_to.append(addr) # Fallback to raw string
    
    request_obj.to_recipients = resolved_to

    # --- 3. VALIDATION & IDENTITY ---
    err, err_msg = validate_request(request=request_obj)
    if err != SendEmailErrorCode.SUCCESS:
        return request_handler.send_json_response(400, {"error": err_msg, "error_code": int(err), "status": "error"})

    identity = app_ctx.config.identity
    try:
        # Borrow full 400-byte AN for multi-stripe upload
        identity.authenticity_number = _get_an_for_download(app_ctx)
    except Exception as e:
        log_error(app_ctx.logger, "API", f"Failed to borrow identity AN: {e}")
        return request_handler.send_json_response(403, {"error": "Identity coin missing", "status": "error"})

    # --- 4. ASYNC TASK EXECUTION ---
    _, task_id = create_task(app_ctx.task_manager, "send", {"subject": request_obj.subject})
    start_task(app_ctx.task_manager, task_id, "Initializing send process")

    def process_send():
        try:
            from database import get_stripe_servers, get_parity_server
            err_stripe, stripe_servers = get_stripe_servers(app_ctx.db_handle)
            err_parity, parity_server = get_parity_server(app_ctx.db_handle)

            if err_stripe != DatabaseErrorCode.SUCCESS or not stripe_servers:
                fail_task(app_ctx.task_manager, task_id, "No stripe servers available", "Server configuration error")
                return

            all_servers = stripe_servers.copy()
            if parity_server: all_servers.append(parity_server)

            log_info(app_ctx.logger, "API", f"Using {len(all_servers)} servers for upload")

            err, result = send_email_async(
                request_obj, identity, app_ctx.db_handle, all_servers,
                app_ctx.thread_pool.executor,
                lambda s: update_task_progress(app_ctx.task_manager, task_id, s.progress, s.message),
                app_ctx.logger,
                cc_handle=app_ctx.cc_handle
            )

            if result and getattr(result, 'success', False):
                complete_task(app_ctx.task_manager, task_id, {"success": True}, "Email sent successfully")
            else:
                # Reactive Healing check
                is_fracked = any(getattr(r, 'status', 0) == 200 for r in (result.upload_results or []))
                if is_fracked:
                    from src.app import move_identity_to_fracked
                    move_identity_to_fracked(identity, app_ctx.beacon_handle, app_ctx.logger)

                fail_task(app_ctx.task_manager, task_id, result.error_message, "Email sending failed")
        except Exception as e:
            log_error(app_ctx.logger, "API", f"Background send crash: {e}")
            fail_task(app_ctx.task_manager, task_id, str(e), "Internal thread crash")

    app_ctx.thread_pool.executor.submit(process_send)
    return request_handler.send_json_response(202, {"status": "accepted", "task_id": task_id, "message": "Email queued"})
def handle_mail_download(request_handler, context):
    """
    GET /api/mail/download/{id} - Download email by ID
    STRICT VERSION: Now handles Status 200 to trigger Reactive Healing.
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle
    logger = app_ctx.logger

    file_guid = context.path_params.get('id', '').replace('-', '').strip()
    if len(file_guid) != 32:
        request_handler.send_json_response(
            400, {"error": "Invalid file_guid format"})
        return

    # Get credentials
    try:
        identity = app_ctx.config.identity
        an = _get_an_for_download(app_ctx)
    except Exception as e:
        request_handler.send_json_response(
            500, {"error": "Configuration error", "details": str(e)})
        return

    # Download file
    try:
        file_bytes, status = download_file_sync(
            db_handle=db_handle,
            file_guid=file_guid,
            denomination=identity.denomination,
            serial_number=identity.serial_number,
            device_id=getattr(identity, 'device_id', 0),
            an=an
        )

        # --- REACTIVE HEALING INTEGRATION ---
        if status == 200:
            from src.app import move_identity_to_fracked
            log_error(logger, "API",
                      "Download failed (200). Initiating healing.")
            move_identity_to_fracked(identity, app_ctx.beacon_handle, logger)
            request_handler.send_json_response(
                401, {"error": "Authentication failed - Coin fracked"})
            return

        # Success: Return raw bytes
        request_handler.send_response(200)
        request_handler.send_header('Content-Type', 'application/octet-stream')
        request_handler.send_header('Content-Length', str(len(file_bytes)))
        request_handler.send_header(
            'Content-Disposition', f'attachment; filename="{file_guid}.bin"')
        request_handler.end_headers()
        request_handler.wfile.write(file_bytes)

    except Exception as e:
        log_error(logger, "API", f"Download failed: {e}")
        request_handler.send_json_response(
            500, {"error": "Download failed", "details": str(e)})

# DONT DELETE

# def _get_an_for_download(app_ctx):
#     """
#     Get the Authenticity Number (AN) for download operations.

#     Tries multiple sources in order:
#     1. Beacon handle encryption_key (if beacon is initialized)
#     2. Config identity.an (if configured)
#     3. Key file (Data/keys.txt)

#     Returns:
#         bytes: 16-byte AN

#     Raises:
#         ValueError: If AN cannot be found
#     """
#     # Try beacon handle first (most reliable if beacon is running)
#     if app_ctx.beacon_handle and hasattr(app_ctx.beacon_handle, 'encryption_key'):
#         an = app_ctx.beacon_handle.encryption_key
#         if an is not None:
#             return an

#     # Try config
#     identity = app_ctx.config.identity
#     an = getattr(identity, 'an', None)
#     if an is not None:
#         return an if isinstance(an, bytes) else bytes.fromhex(an)

#     # Try key file
#     key_file_path = "Data/keys.txt"
#     if os.path.exists(key_file_path):
#         with open(key_file_path, 'r') as f:
#             keys = [line.strip() for line in f.readlines() if line.strip()]

#         # Use the beacon server's key index
#         beacon_index = getattr(app_ctx.config.beacon, 'server_index', 0)
#         if beacon_index < len(keys):
#             return bytes.fromhex(keys[beacon_index])

#     raise ValueError("Authenticity Number (AN) not found in beacon, config, or key file")


def handle_mail_payment_download(request_handler, context):
    """
    GET /api/mail/payment/{id}
    Get locker code for downloading payment coins for a received email.
    Returns both ASCII and hex formats for user convenience.
    """
    from src.logger import log_error

    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Get file_guid from path parameter
    file_guid = context.path_params.get('id', '').replace('-', '').strip()

    if len(file_guid) != 32:
        request_handler.send_json_response(400, {
            "error": "Invalid file_guid format",
            "details": "Expected 32 hex characters",
            "status": "error"
        })
        return

    # Query database for locker code
    try:
        cursor = db_handle.connection.cursor()
        cursor.execute("""
            SELECT locker_code 
            FROM received_tells 
            WHERE file_guid = ?
        """, (file_guid,))

        row = cursor.fetchone()

        if not row:
            request_handler.send_json_response(404, {
                "error": "Email not found",
                "file_guid": file_guid,
                "status": "error"
            })
            return

        locker_code = row['locker_code']

        if not locker_code:
            request_handler.send_json_response(404, {
                "error": "No payment attached to this email",
                "file_guid": file_guid,
                "note": "The sender did not include a payment with this email",
                "status": "error"
            })
            return

        # Convert to bytes if stored as string
        if isinstance(locker_code, str):
            try:
                locker_bytes = bytes.fromhex(locker_code)
            except ValueError:
                locker_bytes = locker_code.encode('ascii')
        else:
            locker_bytes = locker_code

        # Check if it's all zeros (no payment)
        if locker_bytes == b'\x00' * len(locker_bytes):
            request_handler.send_json_response(200, {
                "status": "no_payment",
                "locker_code": None,
                "has_payment": False,
                "message": "No recipient payment attached",
                "note": "The sender paid for storage but did not include a recipient payment. You can still download and read this email."
            })
            return

        # Convert to hex (remove trailing nulls)
        locker_hex = locker_bytes.hex().rstrip('0')
        if len(locker_hex) % 2 != 0:
            locker_hex += '0'  # Ensure even number of hex chars

        # Convert to ASCII if printable
        try:
            # Try to decode as ASCII (strip null padding)
            locker_ascii = locker_bytes.rstrip(b'\x00').decode('ascii')
            # Check if all characters are printable
            if all(32 <= ord(c) <= 126 for c in locker_ascii):
                locker_code_display = locker_ascii
            else:
                locker_code_display = locker_hex
        except (UnicodeDecodeError, AttributeError):
            locker_code_display = locker_hex

        request_handler.send_json_response(200, {
            "status": "success",
            "locker_code": locker_code_display,
            "locker_code_hex": locker_hex,
            "message": "Use this code to download payment coins from RAIDA",
            "note": "You can use either the locker_code or locker_code_hex format"
        })

    except Exception as e:
        log_error(app_ctx.logger, "API", f"Error getting payment locker: {e}")
        request_handler.send_json_response(500, {
            "error": "Database error",
            "details": str(e),
            "status": "error"
        })


def _get_an_for_download(app_ctx):
    """
    FIXED: Added Non-empty checks to prevent 'NoneType' subscript errors.
    """
    from src.coin_scanner import find_identity_coin
    from src.protocol import custom_sn_to_int

    identity = app_ctx.config.identity
    numeric_sn = custom_sn_to_int(identity.serial_number)

    # 1. Loaded Identity check
    if hasattr(identity, 'authenticity_number') and identity.authenticity_number:
        an_data = identity.authenticity_number
        an_bytes = bytes.fromhex(an_data) if isinstance(an_data, str) else an_data
        if an_bytes and len(an_bytes) >= 400:
            return an_bytes[:400]

    # 2. Scanner check
    for bank in ["Data/Wallets/Mailbox/Bank", "Data/Wallets/Default/Bank"]:
        coin = find_identity_coin(bank, numeric_sn)
        if coin:
            # Standardize based on what scanner returns (dict or object)
            raw_ans = coin.get('ans') if isinstance(coin, dict) else getattr(coin, 'ans', None)
            
            # FIXED: Prevent NoneType is not subscriptable
            if raw_ans is not None and len(raw_ans) >= 25:
                an_block = b''.join(raw_ans[:25])
                if len(an_block) >= 400:
                    return an_block

    # 3. Beacon Fallback
    if app_ctx.beacon_handle and hasattr(app_ctx.beacon_handle, 'encryption_key'):
        return app_ctx.beacon_handle.encryption_key

    raise ValueError(f"Could not find valid 400-byte AN for SN {numeric_sn}")

def handle_mail_list(request_handler, context):
    """
    GET /api/mail/list - List emails with Pretty Addresses
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    folder = context.query_params.get('folder', ['inbox'])[0]
    if folder not in ['inbox', 'sent', 'drafts', 'trash']: folder = 'inbox'

    try:
        limit = int(context.query_params.get('limit', ['50'])[0])
        offset = int(context.query_params.get('offset', ['0'])[0])
    except:
        limit, offset = 50, 0

    # list_emails ab join karke 'contact_pretty' la raha hai
    from src.database import list_emails, get_email_count, DatabaseErrorCode
    err, emails = list_emails(db_handle, folder=folder, limit=limit, offset=offset)

    if err != DatabaseErrorCode.SUCCESS:
        return request_handler.send_json_response(500, {"error": "Database error"})

    # Hexify IDs for JSON
    for email in emails:
        if isinstance(email.get('EmailID'), bytes):
            email['EmailID'] = email['EmailID'].hex()

    _, total_count = get_email_count(db_handle, folder=folder)

    return request_handler.send_json_response(200, {
        "folder": folder,
        "emails": emails, # Includes contact_pretty (e.g. Sean.Worthington...)
        "total_count": total_count
    })

# src/api_handlers.py

def handle_import_credentials(request_handler, request_context):
    """
    POST /api/setup/import-credentials - Establish identity by staking a locker code.
    First-time setup: Downloads user credentials from RAIDA using a locker key.

    Request body:
        {"locker_code": "ABC-1234"}

    The locker code must be exactly 8 characters in format XXX-XXXX (hyphen at index 3).
    """
    from src.task_manager import stake_locker_identity
    from src.coin_scanner import find_identity_coin
    from src.logger import log_info, log_error
    import re, os, json

    app_ctx = request_handler.server_instance.app_context
    logger = app_ctx.logger

    # Parse JSON body
    try:
        data = json.loads(request_context.body.decode('utf-8'))
        raw_code = data.get('locker_code', '').strip()
    except Exception as e:
        log_error(logger, "ImportCredentials", f"Failed to parse JSON body: {e}")
        return request_handler.send_json_response(400, {"error": "Invalid JSON payload"})

    # Preserve original case to match Go implementation
    locker_code = raw_code

    # Validate format: exactly 8 chars, hyphen at index 3 (XXX-XXXX)
    if len(locker_code) != 8:
        return request_handler.send_json_response(400, {
            "error": "Invalid locker code format. Must be exactly 8 characters (e.g., ABC-1234)"
        })

    if locker_code[3] != '-':
        return request_handler.send_json_response(400, {
            "error": "Invalid locker code format. Hyphen must be at position 4 (e.g., ABC-1234)"
        })

    # Validate alphanumeric parts (XXX and XXXX)
    parts = locker_code.split('-')
    if len(parts) != 2 or not re.match(r'^[A-Z0-9]{3}$', parts[0]) or not re.match(r'^[A-Z0-9]{4}$', parts[1]):
        return request_handler.send_json_response(400, {
            "error": "Invalid locker code format. Must be alphanumeric XXX-XXXX (e.g., ABC-1234)"
        })

    try:
        # 1. EXECUTE STAKING - pass the code WITH hyphen
        log_info(logger, "ImportCredentials", f"Importing credentials from locker code: {locker_code}")
        success = stake_locker_identity(
            locker_code_bytes=locker_code,  # Pass as string with hyphen
            app_context=app_ctx,
            target_wallet="Mailbox",
            logger=logger
        )

        if not success:
            return request_handler.send_json_response(404, {"error": "Locker is empty or consensus failed"})

        # 2. DISCOVER COIN & NUMERIC DATA
        mailbox_bank = "Data/Wallets/Mailbox/Bank"
        identity_coin = find_identity_coin(mailbox_bank, None)

        if not identity_coin:
            return request_handler.send_json_response(500, {"error": "Identity coin file not found on disk."})

       # FIX: Use .get() with fallback or correct key names
        sn = int(identity_coin.get('serial_number', identity_coin.get('sn', 0)))
        dn = int(identity_coin.get('denomination', identity_coin.get('dn', 0)))

        # 3. PRETTY IDENTITY RESOLUTION (Lookup in Directory)
        from src.database import execute_query
        err, rows = execute_query(app_ctx.db_handle, "SELECT auto_address FROM Users WHERE SerialNumber = ?", (sn,))

        if err == 0 and rows:
            email_address = rows[0]['auto_address']
        else:
            # Fallback if sync hasn't happened yet
            email_address = f"0006.{dn}.{sn}"

        # 4. UPDATE RUNTIME CONFIG AND SAVE TO FILE
        try:
            # Update runtime config
            app_ctx.config.identity.serial_number = sn
            app_ctx.config.identity.denomination = dn
            app_ctx.config.identity.email_address = email_address

            # Save config to file using config module's save_config
            from src.config import save_config
            config_path = "config/qmail.toml"
            if save_config(app_ctx.config, config_path):
                log_info(logger, "ImportCredentials", f"Config saved with identity: {email_address}")
            else:
                log_error(logger, "ImportCredentials", "Failed to save config to file")
        except Exception as e:
            log_error(logger, "ImportCredentials", f"Failed to update config: {e}")

        return request_handler.send_json_response(200, {
            "status": "success",
            "message": "Credentials imported successfully.",
            "email_address": email_address,
            "serial_number": sn,
            "denomination": dn
        })

    except Exception as e:
        log_error(logger, "ImportCredentials", f"Import process failed: {e}")
        return request_handler.send_json_response(500, {"error": str(e)})
# ============================================================================
# DATA ENDPOINTS
# ============================================================================


def handle_get_contacts(request_handler, context):
    """
    GET /api/data/contacts - Get contacts with Pretty Addresses and filtering.
    Supports query params: search, limit, page.
    """
    from src.database import get_all_contacts, DatabaseErrorCode
    
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # 1. PARSE QUERY PARAMETERS
    try:
        limit = int(context.query_params.get('limit', ['50'])[0])
        limit = max(1, min(limit, 200))
        
        page = int(context.query_params.get('page', ['1'])[0])
        page = max(1, page)
        
        search_term = context.query_params.get('search', [None])[0]
    except (ValueError, TypeError, IndexError):
        limit = 50
        page = 1
        search_term = None

    # 2. QUERY DATABASE
    # This function returns contacts where 'auto_address' is the Pretty Format
    err, contacts, total_count = get_all_contacts(
        db_handle, 
        page=page, 
        limit=limit, 
        search=search_term
    )

    if err != DatabaseErrorCode.SUCCESS:
        return request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })

    # 3. CONSTRUCT RESPONSE
    # Frontend will use 'auto_address' to show Sean.Worthington@CEO#C23.Giga
    response = {
        "status": "success",
        "contacts": contacts,
        "pagination": {
            "total_count": total_count,
            "page": page,
            "limit": limit,
            "total_pages": (total_count + limit - 1) // limit
        },
        "search_term": search_term
    }
    
    return request_handler.send_json_response(200, response)


def handle_search_emails(request_handler, context):
    """
    GET /api/data/emails/search - Search emails with Pretty Context
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    query = context.query_params.get('q', [''])[0]
    if not query.strip():
        return request_handler.send_json_response(400, {"error": "Missing query"})

    try:
        limit = int(context.query_params.get('limit', ['50'])[0])
        offset = int(context.query_params.get('offset', ['0'])[0])
    except:
        limit, offset = 50, 0

    from src.database import search_emails, DatabaseErrorCode
    err, results = search_emails(db_handle, query.strip(), limit=limit, offset=offset)

    if err != DatabaseErrorCode.SUCCESS:
        return request_handler.send_json_response(500, {"error": "Search failed"})

    for result in results:
        if isinstance(result.get('EmailID'), bytes):
            result['EmailID'] = result['EmailID'].hex()

    return request_handler.send_json_response(200, {
        "query": query,
        "results": results, # Includes sender_pretty
        "count": len(results)
    })

def handle_search_users(request_handler, context):
    """
    GET /api/data/users/search - Search users for autocomplete (Pretty Format)
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    query = context.query_params.get('q', [''])[0]
    if not query.strip():
        return request_handler.send_json_response(400, {"error": "Missing query"})

    # Hum get_all_contacts ki logic use karenge search filter ke sath
    from src.database import get_all_contacts, DatabaseErrorCode
    err, users, _ = get_all_contacts(db_handle, page=1, limit=20, search=query.strip())

    if err != DatabaseErrorCode.SUCCESS:
        return request_handler.send_json_response(500, {"error": "Search failed"})

    # Frontend ko 'auto_address' (Pretty Format) return karenge
    formatted_users = []
    for u in users:
        formatted_users.append({
            "name": f"{u['first_name']} {u['last_name']}",
            "email": u['auto_address'], # Sean.Worthington@CEO#C23.Giga
            "serial_number": u['serial_number'],
            "class": u['class']
        })

    return request_handler.send_json_response(200, {
        "query": query,
        "users": formatted_users,
        "count": len(formatted_users)
    })

def handle_get_servers(request_handler, context):
    """
    GET /api/data/servers - Get all QMail servers

    Query parameters:
        include_unavailable: if "true", include servers marked unavailable (default: false)

    Returns list of QMail servers with their status and configuration.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse query parameters
    # include_unavailable=true means available_only=false
    include_unavailable = context.query_params.get(
        'include_unavailable', ['false'])[0].lower() == 'true'
    available_only = not include_unavailable

    # Get servers from database
    err, servers = get_all_servers(db_handle, available_only=available_only)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    response = {
        "servers": servers,
        "count": len(servers),
        "include_unavailable": include_unavailable
    }
    request_handler.send_json_response(200, response)


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

def handle_sync(request_handler, context):
    """
    POST /api/admin/sync - Trigger manual data sync from RAIDA

    Syncs users and servers from the configured RAIDA server.
    Returns the number of records synced.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle
    config = app_ctx.config
    logger = app_ctx.logger

    # Perform sync
    sync_err, sync_result = sync_all(
        db_handle,
        config.sync.users_url,
        config.sync.servers_url,
        config.sync.timeout_sec,
        logger
    )

    if sync_err == SyncErrorCode.SUCCESS:
        # Refresh server cache after successful sync (fixes stale cache issue)
        if hasattr(app_ctx, 'refresh_server_cache'):
            app_ctx.refresh_server_cache()

        response = {
            "status": "success",
            "users_synced": sync_result['users'],
            "servers_synced": sync_result['servers'],
            "timestamp": int(time.time())
        }
        request_handler.send_json_response(200, response)
    else:
        response = {
            "status": "error",
            "error_code": int(sync_err),
            "error": f"Sync failed with error code {sync_err}",
            "users_synced": sync_result.get('users', 0),
            "servers_synced": sync_result.get('servers', 0)
        }
        request_handler.send_json_response(500, response)


def handle_get_parity_server(request_handler, context):
    """
    GET /api/admin/servers/parity - Get current parity server configuration

    Returns the server currently designated for parity stripes.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Get parity server from database
    err, parity_server = get_parity_server(db_handle)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    if parity_server is None:
        response = {
            "status": "not_configured",
            "parity_server": None,
            "message": "No parity server is currently configured"
        }
    else:
        response = {
            "status": "configured",
            "parity_server": parity_server
        }
    request_handler.send_json_response(200, response)


def handle_set_parity_server(request_handler, context):
    """
    POST /api/admin/servers/parity - Set parity server

    Expected JSON body:
    {
        "server_id": "RAIDA1"  // The server ID to use for parity
    }

    Designates a server for storing parity stripes.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse request body
    data = context.json if context.json else {}

    server_id = data.get("server_id")
    if not server_id:
        request_handler.send_json_response(400, {
            "error": "Missing required field: 'server_id'",
            "status": "error"
        })
        return

    # Set parity server in database
    err = set_parity_server(db_handle, server_id)

    if err != DatabaseErrorCode.SUCCESS:
        if err == DatabaseErrorCode.ERR_NOT_FOUND:
            request_handler.send_json_response(404, {
                "error": f"Server '{server_id}' not found",
                "status": "error"
            })
        else:
            request_handler.send_json_response(500, {
                "error": "Database error",
                "code": int(err),
                "status": "error"
            })
        return

    response = {
        "status": "success",
        "server_id": server_id,
        "message": f"Server '{server_id}' set as parity server"
    }
    request_handler.send_json_response(200, response)


# ============================================================================
# TASK ENDPOINTS
# ============================================================================

# def handle_task_status(request_handler, context):
#     """
#     GET /api/task/status/{id} - Get async task status

#     Path parameter:
#         id: The task ID to check

#     Returns:
#         - 200 with task status on success
#         - 400 if task_id is missing
#         - 404 if task not found
#         - 500 if task manager not initialized
#     """
#     # Get app context
#     app_ctx = request_handler.server_instance.app_context

#     # Validate task_id
#     task_id = context.path_params.get('id')
#     if not task_id:
#         request_handler.send_json_response(400, {
#             "error": "Missing task_id",
#             "status": "error"
#         })
#         return

#     # Check if task manager is initialized
#     if app_ctx.task_manager is None:
#         request_handler.send_json_response(500, {
#             "error": "Task manager not initialized",
#             "status": "error"
#         })
#         return

#     # Get task status
#     err, status = get_task_status(app_ctx.task_manager, task_id)

#     if err == TaskErrorCode.ERR_NOT_FOUND:
#         request_handler.send_json_response(404, {
#             "error": "Task not found",
#             "task_id": task_id,
#             "status": "error"
#         })
#         return

#     if err == TaskErrorCode.ERR_INVALID_PARAM:
#         request_handler.send_json_response(400, {
#             "error": "Invalid task_id parameter",
#             "task_id": task_id,
#             "status": "error"
#         })
#         return

#     if err != TaskErrorCode.SUCCESS:
#         request_handler.send_json_response(500, {
#             "error": f"Failed to get task status: {err}",
#             "task_id": task_id,
#             "status": "error"
#         })
#         return


#     res_data = status.result
#     if isinstance(res_data, dict):
#         res_data = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in res_data.items()}

#     # Build response from TaskStatus
#     response = {
#         "task_id": status.task_id,
#         "state": status.state,
#         "progress": status.progress,
#         "message": status.message,
#         "result": res_data,
#         "error": status.error,
#         "created_at": status.created_timestamp,
#         "started_at": status.started_timestamp,
#         "completed_at": status.completed_timestamp,
#         "is_finished": status.is_finished,
#         "is_successful": status.is_successful
#     }
#     request_handler.send_json_response(200, response)

def handle_task_status(request_handler, context):
    """
    GET /api/task/status/{id} - Get async task status
    """
    app_ctx = request_handler.server_instance.app_context
    task_id = context.path_params.get('id')
    err, status = get_task_status(app_ctx.task_manager, task_id)

    if err != TaskErrorCode.SUCCESS:
        request_handler.send_json_response(
            404, {"error": "Task not found", "status": "error"})
        return

    # FIX: Ensure result data is JSON-serializable (converts hex if dict has bytes)
    res_data = res_data = status.result
    if isinstance(res_data, dict):
        res_data = {k: (v.hex() if isinstance(v, bytes) else v)
                    for k, v in res_data.items()}

    response = {
        "task_id": status.task_id,
        "state": status.state,
        "progress": status.progress,
        "message": status.message,
        "result": res_data,
        "error": status.error,
        "is_finished": status.is_finished,
        "is_successful": status.is_successful,
        "created_at": str(status.created_timestamp),
        "started_at": str(status.started_timestamp),
        "completed_at": str(status.completed_timestamp) if status.completed_timestamp else None
    }
    request_handler.send_json_response(200, response)


def handle_task_cancel(request_handler, context):
    """
    POST /api/task/cancel/{id} - Cancel an async task

    Path parameter:
        id: The task ID to cancel

    Returns:
        - 200 with cancelled status on success
        - 400 if task_id is missing or task already finished
        - 404 if task not found
        - 500 if task manager not initialized
    """
    # Get app context
    app_ctx = request_handler.server_instance.app_context

    # Validate task_id
    task_id = context.path_params.get('id')
    if not task_id:
        request_handler.send_json_response(400, {
            "error": "Missing task_id",
            "status": "error"
        })
        return

    # Check if task manager is initialized
    if app_ctx.task_manager is None:
        request_handler.send_json_response(500, {
            "error": "Task manager not initialized",
            "status": "error"
        })
        return

    # Attempt to cancel the task
    err = cancel_task(app_ctx.task_manager, task_id, "Cancelled via API")

    if err == TaskErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Task not found",
            "task_id": task_id,
            "status": "error"
        })
        return

    if err == TaskErrorCode.ERR_ALREADY_FINISHED:
        request_handler.send_json_response(400, {
            "error": "Task already finished",
            "task_id": task_id,
            "status": "error",
            "details": "Cannot cancel a task that has already completed, failed, or been cancelled"
        })
        return

    if err == TaskErrorCode.ERR_INVALID_STATE:
        request_handler.send_json_response(400, {
            "error": "Invalid task state for cancellation",
            "task_id": task_id,
            "status": "error"
        })
        return

    if err == TaskErrorCode.ERR_INVALID_PARAM:
        request_handler.send_json_response(400, {
            "error": "Invalid task_id parameter",
            "task_id": task_id,
            "status": "error"
        })
        return

    if err != TaskErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": f"Failed to cancel task: {err}",
            "task_id": task_id,
            "status": "error"
        })
        return

    # Success - task was cancelled
    response = {
        "task_id": task_id,
        "status": "cancelled",
        "message": "Task cancellation requested successfully"
    }
    request_handler.send_json_response(200, response)


# ============================================================================
# EMAIL MANAGEMENT ENDPOINTS
# ============================================================================

# Valid folders for email organization
VALID_FOLDERS = ['inbox', 'sent', 'drafts', 'trash']


def _validate_email_id(email_id_str):
    """
    Validate email ID format (32 hex chars, dashes allowed).

    Returns:
        Tuple of (is_valid, clean_hex_string, error_message)
    """
    if not email_id_str:
        return False, None, "Missing email_id"

    clean_id = email_id_str.replace('-', '').strip()
    if len(clean_id) != 32:
        return False, None, "Expected 32 hex characters"

    try:
        bytes.fromhex(clean_id)
        return True, clean_id, None
    except ValueError:
        return False, None, "Must be valid hexadecimal"


def handle_mail_get(request_handler, context):
    """
    GET /api/mail/{id} - Get email metadata (Pretty Format aware)
    """
    from src.logger import log_error
    from src.database import get_email_metadata, DatabaseErrorCode

    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        return request_handler.send_json_response(400, {"error": "Invalid id", "details": error_msg})

    # 1. Try downloaded emails
    err, metadata = get_email_metadata(db_handle, clean_id)

    if err == DatabaseErrorCode.SUCCESS:
        # metadata ab 'sender_pretty' aur 'recipients_pretty' fields return karega
        return request_handler.send_json_response(200, metadata)

    # 2. Check pending tells
    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        try:
            cursor = db_handle.connection.cursor()
            cursor.execute("SELECT file_guid, created_at, locker_code FROM received_tells WHERE file_guid = ?", (clean_id,))
            row = cursor.fetchone()
            if row:
                locker_code = row['locker_code']
                locker_hex = locker_code.hex() if isinstance(locker_code, bytes) else str(locker_code)

                return request_handler.send_json_response(200, {
                    "EmailID": row['file_guid'],
                    "Subject": f"New Mail ({row['file_guid'][:8]})",
                    "ReceivedTimestamp": row['created_at'],
                    "is_read": False,
                    "downloaded": False,
                    "locker_code": locker_hex,
                    "folder": "inbox"
                })
        except Exception as e:
            log_error(app_ctx.logger, "API", f"Error checking tells: {e}")
            return request_handler.send_json_response(500, {"error": "Database error"})

    return request_handler.send_json_response(404, {"error": "Email not found"})

def handle_mail_delete(request_handler, context):
    """
    DELETE /api/mail/{id} - Soft delete an email (move to trash)

    Path parameter:
        id: The email ID (hex string, 32 chars)

    Returns:
        - 200 with success message
        - 400 for invalid id format
        - 404 if email not found
        - 500 for database errors
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Validate email_id
    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "details": error_msg,
            "status": "error"
        })
        return

    # Delete email (soft delete)
    err, was_modified = delete_email(db_handle, clean_id)

    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Email not found",
            "email_id": email_id,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    response = {
        "status": "deleted",
        "email_id": clean_id,
        "message": "Email moved to trash" if was_modified else "Email already in trash"
    }
    request_handler.send_json_response(200, response)


def handle_mail_move(request_handler, context):
    """
    PUT /api/mail/{id}/move - Move email to another folder

    Path parameter:
        id: The email ID (hex string, 32 chars)

    JSON body:
        {"folder": "drafts"}

    Returns:
        - 200 with success message
        - 400 for invalid id format or invalid folder
        - 404 if email not found
        - 500 for database errors
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Validate email_id
    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "details": error_msg,
            "status": "error"
        })
        return

    # Get folder from JSON body
    body = context.json if context.json else {}
    new_folder = body.get('folder')

    if not new_folder:
        request_handler.send_json_response(400, {
            "error": "Missing required field: 'folder'",
            "status": "error"
        })
        return

    if new_folder not in VALID_FOLDERS:
        request_handler.send_json_response(400, {
            "error": f"Invalid folder: '{new_folder}'",
            "valid_folders": VALID_FOLDERS,
            "status": "error"
        })
        return

    # Get current folder for response
    err, metadata = get_email_metadata(db_handle, clean_id)
    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Email not found",
            "email_id": email_id,
            "status": "error"
        })
        return

    previous_folder = metadata.get(
        'folder', 'unknown') if metadata else 'unknown'

    # Build flags to update
    flags = {'folder': new_folder}

    # If moving to trash, also set is_trashed=1
    if new_folder == 'trash':
        flags['is_trashed'] = True
    # If moving from trash to another folder, set is_trashed=0
    elif metadata and metadata.get('is_trashed'):
        flags['is_trashed'] = False

    # Update the email
    success = update_email_flags(db_handle, clean_id, flags)

    if not success:
        request_handler.send_json_response(500, {
            "error": "Failed to move email",
            "status": "error"
        })
        return

    response = {
        "status": "moved",
        "email_id": clean_id,
        "folder": new_folder,
        "previous_folder": previous_folder
    }
    request_handler.send_json_response(200, response)


def handle_mail_read(request_handler, context):
    """
    PUT /api/mail/{id}/read - Mark email as read or unread

    Path parameter:
        id: The email ID (hex string, 32 chars)

    JSON body:
        {"is_read": true} or {"is_read": false}

    Returns:
        - 200 with success message
        - 400 for invalid id format or missing is_read
        - 404 if email not found
        - 500 for database errors
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Validate email_id
    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "details": error_msg,
            "status": "error"
        })
        return

    # Get is_read from JSON body
    body = context.json if context.json else {}

    if 'is_read' not in body:
        request_handler.send_json_response(400, {
            "error": "Missing required field: 'is_read'",
            "status": "error"
        })
        return

    is_read = bool(body.get('is_read'))

    # Check if email exists first
    err, metadata = get_email_metadata(db_handle, clean_id)
    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Email not found",
            "email_id": email_id,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    # Update the email
    success = update_email_flags(db_handle, clean_id, {'is_read': is_read})

    if not success:
        request_handler.send_json_response(500, {
            "error": "Failed to update email",
            "status": "error"
        })
        return

    response = {
        "status": "updated",
        "email_id": clean_id,
        "is_read": is_read
    }
    request_handler.send_json_response(200, response)


def handle_mail_folders(request_handler, context):
    """
    GET /api/mail/folders - List available mail folders
    """
    response = {
        "status": "success",
        "folders": [
            {"name": "inbox", "display_name": "Inbox", "icon": "inbox"},
            {"name": "sent", "display_name": "Sent", "icon": "send"},
            {"name": "drafts", "display_name": "Drafts", "icon": "edit"},
            {"name": "trash", "display_name": "Trash", "icon": "delete"}
        ]
    }
    request_handler.send_json_response(200, response)


def handle_mail_count(request_handler, context):
    """
    GET /api/mail/count - Get unread/total counts per folder
    """
    from src.database import get_folder_counts, DatabaseErrorCode
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    err, counts = get_folder_counts(db_handle)

    if err != DatabaseErrorCode.SUCCESS:
        return request_handler.send_json_response(500, {"error": "Database error", "status": "error"})

    # Aggregate totals
    total_emails = sum(f['total'] for f in counts.values())
    total_unread = sum(f['unread'] for f in counts.values())

    response = {
        "status": "success",
        "counts": counts,
        "summary": {
            "total_emails": total_emails,
            "total_unread": total_unread
        }
    }
    request_handler.send_json_response(200, response)


# ============================================================================
# ATTACHMENT ENDPOINTS
# ============================================================================

# MIME type mapping for common file extensions
MIME_TYPES = {
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'bmp': 'image/bmp',
    'webp': 'image/webp',
    'svg': 'image/svg+xml',
    'txt': 'text/plain',
    'csv': 'text/csv',
    'html': 'text/html',
    'htm': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'xml': 'application/xml',
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
    '7z': 'application/x-7z-compressed',
    'tar': 'application/x-tar',
    'gz': 'application/gzip',
    'mp3': 'audio/mpeg',
    'wav': 'audio/wav',
    'mp4': 'video/mp4',
    'avi': 'video/x-msvideo',
    'mov': 'video/quicktime',
}


def _get_mime_type(file_extension: str) -> str:
    """Get MIME type for file extension, defaulting to application/octet-stream."""
    if file_extension:
        ext = file_extension.lower().lstrip('.')
        return MIME_TYPES.get(ext, 'application/octet-stream')
    return 'application/octet-stream'


def handle_mail_attachments(request_handler, context):
    """
    GET /api/mail/{id}/attachments - List all attachments for an email

    Path parameter:
        id: The email ID (hex string, 32 chars)

    Returns:
        - 200 with list of attachments (metadata only)
        - 400 for invalid id format
        - 404 if email not found
        - 500 for database errors
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Validate email_id
    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "details": error_msg,
            "status": "error"
        })
        return

    # Get attachments for email
    err, attachments = get_attachments_for_email(db_handle, clean_id)

    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Email not found",
            "email_id": email_id,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    response = {
        "email_id": clean_id,
        "attachments": attachments,
        "count": len(attachments)
    }
    request_handler.send_json_response(200, response)


def handle_mail_attachment_download(request_handler, context):
    """
    GET /api/mail/{id}/attachment/{n} - Download a specific attachment

    Path parameters:
        id: The email ID (hex string, 32 chars)
        n: The attachment ID (integer)

    Returns:
        - 200 with binary file data and appropriate headers
        - 400 for invalid id or attachment_id format
        - 404 if email or attachment not found
        - 500 for database or file read errors
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Validate email_id
    email_id = context.path_params.get('id')
    is_valid, clean_id, error_msg = _validate_email_id(email_id)
    if not is_valid:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "details": error_msg,
            "status": "error"
        })
        return

    # Validate attachment_id
    attachment_id_str = context.path_params.get('n')
    if not attachment_id_str:
        request_handler.send_json_response(400, {
            "error": "Missing attachment_id",
            "status": "error"
        })
        return

    try:
        attachment_id = int(attachment_id_str)
        if attachment_id < 1:
            raise ValueError("Must be positive")
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "Invalid attachment_id format",
            "details": "Must be a positive integer",
            "status": "error"
        })
        return

    # Get attachment data
    err, attachment = get_attachment_data(db_handle, attachment_id)

    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Attachment not found",
            "attachment_id": attachment_id,
            "status": "error"
        })
        return

    if err == DatabaseErrorCode.ERR_IO:
        request_handler.send_json_response(500, {
            "error": "Attachment file not accessible",
            "attachment_id": attachment_id,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    # Security: Verify attachment belongs to the specified email
    if attachment.get('email_id') != clean_id:
        request_handler.send_json_response(404, {
            "error": "Attachment not found",
            "details": "Attachment does not belong to specified email",
            "status": "error"
        })
        return

    # Get file data
    file_data = attachment.get('data')
    if file_data is None:
        request_handler.send_json_response(500, {
            "error": "Attachment data not available",
            "status": "error"
        })
        return

    # Determine MIME type and filename
    file_extension = attachment.get('file_extension', '')
    mime_type = _get_mime_type(file_extension)
    filename = attachment.get('name', f'attachment_{attachment_id}')

    # Send binary response
    request_handler.send_response(200)
    request_handler.send_header('Content-Type', mime_type)
    request_handler.send_header('Content-Length', str(len(file_data)))
    request_handler.send_header(
        'Content-Disposition', f'attachment; filename="{filename}"')
    request_handler.send_header('X-Attachment-ID', str(attachment_id))
    request_handler.send_header('X-Email-ID', clean_id)
    request_handler.end_headers()
    request_handler.wfile.write(file_data)


# ============================================================================
# CONTACT MANAGEMENT VALIDATION HELPERS
# ============================================================================

# Validation constants
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
MAX_NAME_LENGTH = 100
MAX_EMAIL_LENGTH = 255
MAX_CONTACTS_LIMIT = 200


def _validate_email_format(email: str) -> bool:
    """Validate email format using regex."""
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    return EMAIL_REGEX.match(email) is not None


def _normalize_email(email: str) -> str:
    """Normalize email to lowercase and strip whitespace."""
    return email.strip().lower()


def _validate_contact_name(name, field_name: str, required: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Validate a name field for contacts.

    Args:
        name: The name value to validate
        field_name: Field name for error messages
        required: Whether this field is required

    Returns:
        Tuple of (is_valid, error_message)
    """
    if name is None:
        if required:
            return False, f"{field_name} is required"
        return True, None  # Optional and not provided

    if not isinstance(name, str):
        return False, f"{field_name} must be a string"

    stripped = name.strip()
    if required and not stripped:
        return False, f"{field_name} cannot be empty"

    if len(stripped) > MAX_NAME_LENGTH:
        return False, f"{field_name} exceeds maximum length of {MAX_NAME_LENGTH}"

    return True, None


# ============================================================================
# DRAFT MANAGEMENT VALIDATION HELPERS
# ============================================================================

MAX_SUBJECT_LENGTH = 500
MAX_BODY_LENGTH = 1000000  # 1MB
MAX_DRAFTS_LIMIT = 200


def _validate_draft_subject(subject: Any, required: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate draft subject.

    Args:
        subject: Subject to validate
        required: Whether subject is required

    Returns:
        Tuple of (is_valid, error_message_or_none)
    """
    if subject is None:
        if required:
            return False, "subject is required"
        return True, None

    if not isinstance(subject, str):
        return False, "subject must be a string"

    # Allow empty subject (feedback: requirements didn't mandate required)
    if len(subject) > MAX_SUBJECT_LENGTH:
        return False, f"subject exceeds maximum length of {MAX_SUBJECT_LENGTH}"

    return True, None


def _validate_draft_body(body: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate draft body.

    Args:
        body: Body to validate

    Returns:
        Tuple of (is_valid, error_message_or_none)
    """
    if body is None:
        return True, None

    if not isinstance(body, str):
        return False, "body must be a string"

    if len(body) > MAX_BODY_LENGTH:
        return False, f"body exceeds maximum length of {MAX_BODY_LENGTH}"

    return True, None


def _validate_recipient_ids(recipients: Any, field_name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate recipient ID list.

    Args:
        recipients: List of recipient IDs to validate
        field_name: Name of the field for error messages

    Returns:
        Tuple of (is_valid, error_message_or_none)
    """
    if recipients is None:
        return True, None

    if not isinstance(recipients, list):
        return False, f"{field_name} must be a list"

    for r in recipients:
        if not isinstance(r, int) or r <= 0:
            return False, f"{field_name} must contain positive integers"

    return True, None


# ============================================================================
# CONTACT MANAGEMENT HANDLERS
# ============================================================================

def handle_contacts_list(request_handler, context):
    """
    GET /api/contacts - List all contacts with optional pagination and search.

    Query Parameters:
        page: int (default 1, min 1)
        limit: int (default 50, max 200)
        q: string (optional search query)

    Response (200):
    {
        "contacts": [...],
        "pagination": {
            "page": 1,
            "limit": 50,
            "total": 150,
            "total_pages": 3
        }
    }
    """
    # Get database handle
    db_handle = request_handler.server_instance.app_context.db_handle
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Parse query parameters
    query_params = context.query_params

    # Parse page parameter
    try:
        page = int(query_params.get('page', '1'))
        if page < 1:
            request_handler.send_json_response(400, {
                "error": "page must be a positive integer",
                "status": "error"
            })
            return
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "page must be a positive integer",
            "status": "error"
        })
        return

    # Parse limit parameter
    try:
        limit = int(query_params.get('limit', '50'))
        if limit < 1 or limit > MAX_CONTACTS_LIMIT:
            request_handler.send_json_response(400, {
                "error": f"limit must be between 1 and {MAX_CONTACTS_LIMIT}",
                "status": "error"
            })
            return
    except ValueError:
        request_handler.send_json_response(400, {
            "error": f"limit must be between 1 and {MAX_CONTACTS_LIMIT}",
            "status": "error"
        })
        return

    # Get optional search query
    search = query_params.get('q', None)

    # Call database function
    err, contacts, total = get_all_contacts(
        db_handle, page=page, limit=limit, search=search)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "status": "error"
        })
        return

    # Calculate total pages
    total_pages = ceil(total / limit) if limit > 0 else 0

    request_handler.send_json_response(200, {
        "contacts": contacts,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages
        }
    })


def handle_contacts_add(request_handler, context):
    """
    POST /api/contacts - Add a new contact.

    Request Body:
    {
        "first_name": "John",           // REQUIRED
        "auto_address": "john@qmail",   // REQUIRED (unique, valid format)
        "last_name": "Doe",             // OPTIONAL
        "middle_name": "M",             // optional
        "description": "Work friend",   // optional
        "sending_fee": "0.001",         // optional
        "beacon_id": "abc123"           // optional
    }

    Response (201):
    {
        "status": "created",
        "contact": { ... }
    }
    """
    # Get database handle
    db_handle = request_handler.server_instance.app_context.db_handle
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Parse JSON body
    body = context.json
    if body is None:
        request_handler.send_json_response(400, {
            "error": "Request body must be valid JSON",
            "status": "error"
        })
        return

    # Validate first_name (required)
    valid, err_msg = _validate_contact_name(
        body.get('first_name'), 'first_name', required=True)
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate last_name (optional)
    valid, err_msg = _validate_contact_name(
        body.get('last_name'), 'last_name', required=False)
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate auto_address (required)
    auto_address = body.get('auto_address')
    if auto_address is None or not isinstance(auto_address, str):
        request_handler.send_json_response(400, {
            "error": "auto_address is required",
            "status": "error"
        })
        return

    auto_address = auto_address.strip()
    if not auto_address:
        request_handler.send_json_response(400, {
            "error": "auto_address cannot be empty",
            "status": "error"
        })
        return

    # Validate email format
    if not _validate_email_format(auto_address):
        request_handler.send_json_response(400, {
            "error": "Invalid email format",
            "status": "error"
        })
        return

    # Normalize email to lowercase
    normalized_email = _normalize_email(auto_address)

    # Check if email already exists
    err, exists = check_email_exists(db_handle, normalized_email)
    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "status": "error"
        })
        return

    if exists:
        request_handler.send_json_response(409, {
            "error": "Email already exists",
            "auto_address": normalized_email,
            "status": "error"
        })
        return

    # Build contact dict for store_contact
    contact_data = {
        'first_name': body.get('first_name', '').strip(),
        'last_name': body.get('last_name', '').strip() if body.get('last_name') else None,
        'middle_name': body.get('middle_name', '').strip() if body.get('middle_name') else None,
        'auto_address': normalized_email,
        'description': body.get('description', '').strip() if body.get('description') else None,
        'sending_fee': body.get('sending_fee'),
        'beacon_id': body.get('beacon_id')
    }

    # Store the contact
    err, user_id = store_contact(db_handle, contact_data)

    if err == DatabaseErrorCode.ERR_CONSTRAINT:
        # Backstop for race condition: if duplicate slipped past check_email_exists
        # or if UNIQUE index is added to auto_address column later
        request_handler.send_json_response(409, {
            "error": "Email already exists",
            "auto_address": normalized_email,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Failed to create contact",
            "status": "error"
        })
        return

    # Get the created contact to return
    err, created_contact = get_contact_by_id(db_handle, user_id)

    if err != DatabaseErrorCode.SUCCESS or created_contact is None:
        # Contact was created but couldn't retrieve it - still success
        request_handler.send_json_response(201, {
            "status": "created",
            "user_id": user_id,
            "contact": {
                "user_id": user_id,
                "first_name": contact_data['first_name'],
                "last_name": contact_data['last_name'],
                "auto_address": normalized_email
            }
        })
        return

    request_handler.send_json_response(201, {
        "status": "created",
        "contact": created_contact
    })


def handle_contacts_delete(request_handler, context):
    """
    DELETE /api/contacts/{id} - Delete a contact by ID (hard delete).

    Path Parameter:
        id: User ID (positive integer)

    Response (204 No Content):
        Empty body on success
    """
    # Get database handle
    db_handle = request_handler.server_instance.app_context.db_handle
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Get user_id from path parameters
    user_id_str = context.path_params.get('id', '')

    # Validate user_id
    try:
        user_id = int(user_id_str)
        if user_id < 1:
            request_handler.send_json_response(400, {
                "error": "user_id must be a positive integer",
                "status": "error"
            })
            return
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "user_id must be a positive integer",
            "status": "error"
        })
        return

    # Delete the contact
    err = delete_contact(db_handle, user_id)

    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Contact not found",
            "user_id": user_id,
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "status": "error"
        })
        return

    # Return 204 No Content (per REST convention)
    request_handler.send_response(204)
    request_handler.end_headers()


# ============================================================================
# DRAFT MANAGEMENT HANDLERS
# ============================================================================
def handle_drafts_list(request_handler, context):
    """
    GET /api/mail/drafts - List all drafts with pagination.
    FIXED: Uses context.query_params (dot notation) for RequestContext dataclass.
    """
    import math
    from src.database import DatabaseErrorCode, list_drafts
    from src.logger import log_info, log_error

    app_ctx = getattr(request_handler.server_instance, 'app_context', None)
    if not app_ctx:
        return request_handler.send_json_response(500, {"error": "Internal context missing"})

    db_handle = app_ctx.db_handle
    logger = app_ctx.logger
    
    # RequestContext is a dataclass, use dot notation
    q_params = context.query_params 

    try:
        # 1. Parse pagination parameters from query_params dictionary
        try:
            # query_params values are lists
            page_val = q_params.get('page', ['1'])[0]
            limit_val = q_params.get('limit', ['50'])[0]
            page = max(1, int(page_val))
            limit = max(1, min(int(limit_val), 200))
        except (ValueError, IndexError, KeyError):
            page, limit = 1, 50

        log_info(logger, "API", f"Listing drafts: Page {page}, Limit {limit}")

        # 2. Database Fetch
        err, drafts, total = list_drafts(db_handle, page=page, limit=limit)

        if err != DatabaseErrorCode.SUCCESS:
            log_error(logger, "API", f"Database error in list_drafts: {err}")
            return request_handler.send_json_response(500, {"error": "Database retrieval failed"})

        # 3. Final Response
        return request_handler.send_json_response(200, {
            "status": "success",
            "drafts": drafts,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": math.ceil(total / limit) if total > 0 else 1
            }
        })

    except Exception as e:
        log_error(logger, "API", f"Draft list crash: {str(e)}")
        return request_handler.send_json_response(500, {"error": "Internal Server Error", "details": str(e)})
    
def handle_draft_save(request_handler, context):
    """
    POST /api/mail/draft - Save a new draft.
    PROFESSIONAL VERSION: Uses pre-parsed context to avoid blocking hangs.
    """
    import os
    import time
    from src.database import DatabaseErrorCode, store_email
    from src.logger import log_info, log_error

    # 1. Access Shared Resources
    app_ctx = getattr(request_handler.server_instance, 'app_context', None)
    if not app_ctx:
        return request_handler.send_json_response(500, {"error": "Internal context missing"})

    db_handle = app_ctx.db_handle
    logger = app_ctx.logger

    try:
        # 2. DATA SOURCE: Framework already parsed the body into context.json
        # Reading rfile again here causes the Postman hang!
        body = context.json if context.json else {}
        
        # 3. Metadata Generation
        # EmailID must be 16 bytes for the BLOB primary key in SQLite
        email_id_bytes = os.urandom(16)
        email_id_hex = email_id_bytes.hex()
        now_ts = int(time.time())

        # 4. Construct Email Object
        # Aligns with store_email() requirements in database.py
        email_data = {
            'email_id': email_id_bytes,
            'subject': body.get('subject', '(No Subject)'),
            'body': body.get('body', ''),
            'received_timestamp': now_ts,
            'sent_timestamp': now_ts,
            'recipient_sns': body.get('recipient_ids', []), # List of SN integers
            'cc_sns': body.get('cc_ids', []),
            'folder': 'drafts',
            'is_read': 1 # Drafts are marked as read by default
        }

        # 5. Database Execution
        # store_email handles the 'Emails' and 'Junction_Email_Users' tables
        err, _ = store_email(db_handle, email_data)

        if err == DatabaseErrorCode.SUCCESS:
            log_info(logger, "API", f"Draft saved successfully: {email_id_hex}")
            
            # 6. RETURN RESPONSE: send_json_response handles socket flushing correctly
            return request_handler.send_json_response(201, {
                "status": "success",
                "id": email_id_hex,
                "message": "Draft created successfully",
                "draft": {
                    "subject": email_data['subject'],
                    "timestamp": now_ts
                }
            })
        else:
            log_error(logger, "API", f"Database error during draft save: {err}")
            return request_handler.send_json_response(500, {
                "error": "Failed to save to database",
                "code": int(err)
            })

    except Exception as e:
        log_error(logger, "API", f"Critical crash in handle_draft_save: {str(e)}")
        return request_handler.send_json_response(500, {"error": "Internal Server Error", "details": str(e)})


def handle_draft_update(request_handler, context):
    """
    PUT /api/mail/draft/{id} - Update an existing draft.
    FIXED: Uses correct case-sensitive keys (Subject, Body) from database response.
    """
    import time
    from src.database import DatabaseErrorCode, update_draft
    from src.logger import log_info, log_error

    app_ctx = getattr(request_handler.server_instance, 'app_context', None)
    db_handle = app_ctx.db_handle
    logger = app_ctx.logger

    # 1. Get ID from path
    email_id_str = context.path_params.get('id')
    if not email_id_str:
        return request_handler.send_json_response(400, {"error": "Missing email ID in path"})

    try:
        # 2. Convert Hex to Binary for DB
        clean_id_hex = email_id_str.replace('-', '').strip()
        email_id_bytes = bytes.fromhex(clean_id_hex)

        # 3. Get update data from body
        body = context.json if context.json else {}
        
        update_data = {}
        if 'subject' in body: update_data['subject'] = body['subject']
        if 'body' in body: update_data['body'] = body['body']
        if 'recipient_ids' in body: update_data['recipient_ids'] = body['recipient_ids']
        if 'cc_ids' in body: update_data['cc_ids'] = body['cc_ids']

        # 4. Database execution
        err, updated_raw = update_draft(db_handle, email_id_bytes, update_data)

        if err == DatabaseErrorCode.SUCCESS and updated_raw:
            log_info(logger, "API", f"Updated draft: {clean_id_hex}")

            # --- THE FIX: Match database column case (Subject, Body, SentTimestamp) ---
            response_draft = {
                "id": clean_id_hex,
                "subject": updated_raw.get('Subject') or "(No Subject)", # Capital 'S'
                "body": updated_raw.get('Body') or "",                   # Capital 'B'
                "last_modified": updated_raw.get('SentTimestamp'),       # Capital 'S'
                "folder": updated_raw.get('folder', 'drafts')
            }

            return request_handler.send_json_response(200, {
                "status": "success",
                "message": "Draft updated",
                "draft": response_draft
            })
        else:
            return request_handler.send_json_response(404, {"error": "Draft not found or update failed"})

    except Exception as e:
        log_error(logger, "API", f"Draft update crash: {str(e)}")
        return request_handler.send_json_response(400, {"error": "Invalid request format", "details": str(e)})
# ============================================================================
# WALLET BALANCE ENDPOINTS
# ============================================================================

def handle_wallet_balance(request_handler, context):
    """
    GET /api/wallet/balance - Get wallet balance for Default wallet

    No parameters needed - QMail uses fixed wallet location at Data/Wallets/Default.
    Scans Bank, Fracked, and Limbo folders for .bin CloudCoin files.

    Returns:
        200 with JSON balance information:
        {
            "status": "success",
            "type": "wallet-balance",
            "wallet_path": "Data/Wallets/Default",
            "wallet_name": "Default",
            "total_coins": 247,
            "total_value": 1250.5,
            "folders": {
                "bank_coins": 200,
                "bank_value": 1000.0,
                "fracked_coins": 45,
                "fracked_value": 225.5,
                "limbo_coins": 2,
                "limbo_value": 25.0
            },
            "denominations": {
                "bank": {"1": 50, "100": 10, "0.1": 5, ...},
                "fracked": {"1": 10, "100": 1, ...},
                "limbo": {"1": 2, ...}
            }
        }

        500 if wallet structure doesn't exist or scan fails
    """
    from src.wallet_structure import get_wallet_subfolder, get_wallet_path, DEFAULT_WALLET
    from src.coin_scanner import scan_wallet_folders

    app_ctx = request_handler.server_instance.app_context
    logger = app_ctx.logger_handle if hasattr(
        app_ctx, 'logger_handle') else None

    try:
        # Get wallet paths - QMail uses fixed "Default" wallet
        wallet_name = DEFAULT_WALLET
        wallet_base_path = get_wallet_path(wallet_name)

        # Build folder paths
        bank_path = get_wallet_subfolder(wallet_name, "Bank")
        fracked_path = get_wallet_subfolder(wallet_name, "Fracked")
        limbo_path = get_wallet_subfolder(wallet_name, "Limbo")

        # Check if wallet exists
        if not os.path.exists(wallet_base_path):
            request_handler.send_json_response(500, {
                "status": "error",
                "error": "Wallet not initialized",
                "details": f"Wallet directory not found: {wallet_base_path}",
                "suggestion": "Initialize wallet structure first"
            })
            return

        # Validate critical folder structure
        missing_folders = []
        warnings = []

        for folder_name, folder_path in [("Bank", bank_path), ("Fracked", fracked_path), ("Limbo", limbo_path)]:
            if not os.path.exists(folder_path):
                missing_folders.append(folder_name)
                if logger:
                    from src.logger import log_warning
                    log_warning(
                        logger, "API", f"Missing wallet folder: {folder_name} at {folder_path}")

        # If critical folders are missing, warn but continue (will return 0 balance for those folders)
        if missing_folders:
            warnings.append(
                f"Missing folders: {', '.join(missing_folders)}. Wallet may not be properly initialized.")

        # Scan all folders
        balance_info = scan_wallet_folders(
            bank_path, fracked_path, limbo_path, logger)

        # Build response matching C API format
        response = {
            "status": "success",
            "type": "wallet-balance",
            "wallet_path": wallet_base_path,
            "wallet_name": wallet_name,
            "total_coins": balance_info["total_coins"],
            "total_value": balance_info["total_value"],
            "folders": balance_info["folders"],
            "denominations": balance_info["denominations"]
        }

        # Add warnings if any folders are missing
        if warnings:
            response["warnings"] = warnings

        request_handler.send_json_response(200, response)

    except Exception as e:
        # Log error and return 500
        if logger:
            from src.logger import log_error
            log_error(logger, "API", f"Wallet balance error: {e}")

        request_handler.send_json_response(500, {
            "status": "error",
            "error": "Failed to calculate wallet balance",
            "details": str(e)
        })


def handle_stake_mailbox(request_handler, context):
    """
    POST /api/mail/stake - Manual Staking Flow (First Login)
    Required to establish identity before the client can send mail.
    """
    import asyncio
    from src.locker_download import download_from_locker, LockerDownloadResult
    from src.wallet_structure import get_wallet_path, DEFAULT_WALLET
    from src.heal_file_io import move_coin_file

    app_ctx = request_handler.server_instance.app_context
    data = context.json or {}

    # 1. Capture and Clean Locker Code (AS8D-HJL)
    raw_code = data.get('locker_code', '')
    if not raw_code:
        return request_handler.send_json_response(400, {"error": "Locker code required."})

    # Preserve case and hyphen for Go compatibility
    clean_code = raw_code.strip()
    locker_bytes = clean_code.encode('ascii')

    # 2. Call Command 91 (Download)
    # NOTE: If this fails with insufficient responses, it confirms servers lack CCV3.
    wallet_path = get_wallet_path(DEFAULT_WALLET)
    try:
        result, coins = asyncio.run(download_from_locker(
            locker_code=locker_bytes,
            wallet_path=wallet_path,
            db_handle=app_ctx.db_handle
        ))
    except Exception as e:
        return request_handler.send_json_response(500, {"error": f"Staking process crashed: {e}"})

    if result != LockerDownloadResult.SUCCESS:
        return request_handler.send_json_response(502, {
            "error": "RAIDA Infrastructure Error",
            "details": "Command 91 failed. Ensure CCV3 is rolled out on all RAIDAs."
        })

    # 3. Activate Identity: Move coin to Bank and update config
    if coins:
        target_path = os.path.join(wallet_path, "Bank")
        move_coin_file(coins[0], target_path)

        # Immediate update so user doesn't have to restart to send mail
        app_ctx.config.identity.serial_number = coins[0].serial_number
        app_ctx.config.identity.denomination = coins[0].denomination

        return request_handler.send_json_response(200, {
            "status": "success",
            "serial_number": coins[0].serial_number,
            "message": "Mailbox successfully staked."
        })

    return request_handler.send_json_response(404, {"error": "The provided locker was empty."})


# ============================================================================
# LOCKER DOWNLOAD ENDPOINT
# ============================================================================

def handle_locker_download(request_handler, context):
    """
    POST /api/locker/download - Download CloudCoins from a RAIDA locker

    Downloads coins using a locker code received from a Tell notification.
    Coins are saved to the Fracked folder in the default wallet.

    Request body:
        {
            "locker_code": "0102030405060708"  # 16 hex chars (8 bytes)
        }

    Returns:
        200 with JSON success response:
        {
            "status": "success",
            "type": "locker-download",
            "coins_downloaded": 5,
            "total_value": 127.0,
            "coins": [
                {
                    "serial_number": 12345678,
                    "denomination": 1,
                    "value": 1.0,
                    "pown": "ppppppppppppppppppppppppp",
                    "pass_count": 25
                },
                ...
            ]
        }

        400 if locker_code is missing or invalid
        500 if download fails
    """
    import asyncio
    from src.locker_download import download_from_locker, LockerDownloadResult
    from src.wallet_structure import get_wallet_path, DEFAULT_WALLET

    app_ctx = request_handler.server_instance.app_context
    logger = app_ctx.logger_handle if hasattr(
        app_ctx, 'logger_handle') else None
    db_handle = app_ctx.db_handle if hasattr(app_ctx, 'db_handle') else None

    # Get request body
    body = context.json if context.json else {}

    # Validate locker_code
    locker_code_hex = body.get('locker_code', '')
    if not locker_code_hex:
        request_handler.send_json_response(400, {
            "status": "error",
            "error": "Missing locker_code",
            "details": "Request body must include 'locker_code' as 16-character hex string"
        })
        return

    # Parse locker code
    try:
        locker_code = bytes.fromhex(locker_code_hex)
        if len(locker_code) < 8:
            raise ValueError("Locker code must be at least 8 bytes")
    except ValueError as e:
        request_handler.send_json_response(400, {
            "status": "error",
            "error": "Invalid locker_code format",
            "details": str(e)
        })
        return

    # Get wallet path
    wallet_path = get_wallet_path(DEFAULT_WALLET)

    # Run the async download function
    try:
        result, coins = asyncio.run(download_from_locker(
            locker_code=locker_code,
            wallet_path=wallet_path,
            db_handle=db_handle,
            logger_handle=logger
        ))
    except Exception as e:
        if logger:
            log_error(logger, "API", f"Locker download exception: {e}")
        request_handler.send_json_response(500, {
            "status": "error",
            "error": "Locker download failed",
            "details": str(e)
        })
        return

    # Handle result
    if result == LockerDownloadResult.SUCCESS:
        # Build coin list for response
        coin_list = []
        total_value = 0.0
        for coin in coins:
            # Calculate value from denomination
            value = 10.0 ** coin.denomination if coin.denomination != 11 else 0.0
            total_value += value
            pass_count = coin.pown_string.count('p')

            coin_list.append({
                "serial_number": coin.serial_number,
                "denomination": coin.denomination,
                "value": value,
                "pown": coin.pown_string,
                "pass_count": pass_count
            })

        request_handler.send_json_response(200, {
            "status": "success",
            "type": "locker-download",
            "coins_downloaded": len(coins),
            "total_value": total_value,
            "coins": coin_list
        })

    elif result == LockerDownloadResult.ERR_LOCKER_EMPTY:
        request_handler.send_json_response(200, {
            "status": "success",
            "type": "locker-download",
            "coins_downloaded": 0,
            "total_value": 0.0,
            "coins": [],
            "message": "Locker is empty"
        })

    else:
        # Map error codes to messages
        error_messages = {
            LockerDownloadResult.ERR_INVALID_LOCKER_CODE: "Invalid locker code",
            LockerDownloadResult.ERR_LOCKER_NOT_FOUND: "Locker not found",
            LockerDownloadResult.ERR_NETWORK_ERROR: "Network error communicating with RAIDA",
            LockerDownloadResult.ERR_INSUFFICIENT_RESPONSES: "Insufficient RAIDA responses for consensus",
            LockerDownloadResult.ERR_FILE_WRITE_ERROR: "Failed to save coin files",
            LockerDownloadResult.ERR_NO_RAIDA_SERVERS: "Could not get RAIDA server list",
            LockerDownloadResult.ERR_KEY_DERIVATION_FAILED: "Key derivation failed",
            LockerDownloadResult.ERR_PROTOCOL_ERROR: "Protocol error",
        }
        error_msg = error_messages.get(result, f"Unknown error ({result})")

        request_handler.send_json_response(500, {
            "status": "error",
            "error": error_msg,
            "error_code": int(result)
        })


# ============================================================================
# ROUTE REGISTRATION HELPER
# ============================================================================

def register_all_routes(server):
    """
    Register all API routes with the server.

    Args:
        server: APIServer instance from api_server.py
    """
    # Health / Status
    server.register_route('GET', '/api/health', handle_health)
    server.register_route("GET", '/api/admin/version-check', handle_version_check)
    server.register_route('GET', '/api/qmail/ping', handle_ping)

    # Account / Identity
    server.register_route('GET', '/api/account/identity', handle_account_identity)

    # Mail operations
    server.register_route('POST', '/api/mail/send', handle_mail_send)
    server.register_route(
        'GET', '/api/mail/download/{id}', handle_mail_download)
    server.register_route(
        'GET', '/api/mail/payment/{id}', handle_mail_payment_download)
    server.register_route('GET', '/api/mail/list', handle_mail_list)
    server.register_route(
        'POST', '/api/setup/import-credentials', handle_import_credentials)

    # Email management endpoints
    server.register_route('GET', '/api/mail/folders', handle_mail_folders)
    server.register_route('GET', '/api/mail/count', handle_mail_count)
    server.register_route('GET', '/api/mail/drafts', handle_drafts_list)
    server.register_route('GET', '/api/mail/{id}', handle_mail_get)
    server.register_route('DELETE', '/api/mail/{id}', handle_mail_delete)
    server.register_route('PUT', '/api/mail/{id}/move', handle_mail_move)
    server.register_route('PUT', '/api/mail/{id}/read', handle_mail_read)

    # Attachment endpoints
    server.register_route(
        'GET', '/api/mail/{id}/attachments', handle_mail_attachments)
    server.register_route(
        'GET', '/api/mail/{id}/attachment/{n}', handle_mail_attachment_download)

    # Data operations
    server.register_route(
        'GET', '/api/data/contacts/popular', handle_get_contacts)
    server.register_route(
        'GET', '/api/data/emails/search', handle_search_emails)
    server.register_route('GET', '/api/data/users/search', handle_search_users)
    server.register_route('GET', '/api/data/servers', handle_get_servers)

    # Admin operations
    server.register_route('POST', '/api/admin/sync', handle_sync)
    server.register_route(
        'GET', '/api/admin/servers/parity', handle_get_parity_server)
    server.register_route(
        'POST', '/api/admin/servers/parity', handle_set_parity_server)

    # Wallet operations
    server.register_route('GET', '/api/wallet/balance', handle_wallet_balance)

    # Locker operations
    server.register_route('POST', '/api/locker/download',
                          handle_locker_download)

    # Task operations
    server.register_route('GET', '/api/task/status/{id}', handle_task_status)
    server.register_route('POST', '/api/task/cancel/{id}', handle_task_cancel)

    # Contact management endpoints
    server.register_route('GET', '/api/contacts', handle_contacts_list)
    server.register_route('POST', '/api/contacts', handle_contacts_add)
    server.register_route(
        'DELETE', '/api/contacts/{id}', handle_contacts_delete)

    # Draft management endpoints
    server.register_route('POST', '/api/mail/draft', handle_draft_save)
    server.register_route('PUT', '/api/mail/draft/{id}', handle_draft_update)
    


# ============================================================================
# MAIN (for standalone testing)
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("api_handlers.py - API Handlers")
    print("=" * 50)
    print("This module provides handler functions for the QMail REST API.")
    print("Run src/app.py to start the server with these handlers.")
    print("\nAvailable endpoints:")
    print("  GET  /api/health                - Health check")
    print("  GET  /api/qmail/ping            - Check for new mail")
    print("  POST /api/mail/send             - Send email")
    print("  GET  /api/mail/download/{id}    - Download email")
    print("  GET  /api/mail/list             - List emails")
    print("  POST /api/setup/import-credentials - Import credentials")
    print("  GET  /api/data/contacts/popular - Get contacts")
    print("  GET  /api/data/emails/search    - Search emails")
    print("  GET  /api/data/users/search     - Search users")
    print("  GET  /api/data/servers          - Get QMail servers")
    print("  POST /api/admin/sync            - Trigger data sync")
    print("  GET  /api/admin/servers/parity  - Get parity server")
    print("  POST /api/admin/servers/parity  - Set parity server")
    print("  GET  /api/task/status/{id}      - Task status")
    print("  POST /api/task/cancel/{id}      - Cancel task")
