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

import time
import json
import re
from math import ceil
from typing import Any, Dict, Optional, Tuple
from src.task_manager import create_task, start_task, TaskErrorCode
import time

# Database imports for real implementations
from src.database import (
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
from src.data_sync import sync_all, SyncErrorCode

# Beacon imports
from src.beacon import do_peek
from src.network import NetworkErrorCode

# Download imports
from src.download_handler import download_file_sync
from src.database import get_received_tell_by_guid
from src.logger import log_info, log_error
import os

# Task manager imports
from src.task_manager import get_task_status, cancel_task, TaskErrorCode

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


def handle_ping(request_handler, context):
    """
    GET /api/qmail/ping - Beacon check for new mail

    Returns any pending mail notifications from the beacon monitor.
    Also performs a live peek to the beacon server if available.
    """
    app_ctx = request_handler.server_instance.app_context

    # Get any cached notifications from background monitor
    cached_notifications = app_ctx.get_and_clear_notifications()

    # If beacon is available, also do a live peek
    live_notifications = []
    beacon_status = "disabled"

    if app_ctx.beacon_handle:
        err, live_notifications = do_peek(app_ctx.beacon_handle)
        if err == NetworkErrorCode.SUCCESS:
            beacon_status = "connected"
        else:
            beacon_status = f"error ({err})"

    # Combine notifications (cached from background + live peek)
    all_notifications = cached_notifications + live_notifications

    # Convert notifications to JSON-serializable format
    messages = []
    for notif in all_notifications:
        messages.append({
            "file_guid": notif.file_guid.hex() if hasattr(notif, 'file_guid') else "",
            "locker_code": notif.locker_code.hex() if hasattr(notif, 'locker_code') else "",
            "timestamp": notif.timestamp if hasattr(notif, 'timestamp') else 0,
            "tell_type": notif.tell_type if hasattr(notif, 'tell_type') else 0,
            "server_count": notif.server_count if hasattr(notif, 'server_count') else 0,
        })

    response = {
        "status": "ok",
        "timestamp": int(time.time()),
        "beacon_status": beacon_status,
        "has_mail": len(messages) > 0,
        "message_count": len(messages),
        "messages": messages
    }
    request_handler.send_json_response(200, response)


# ============================================================================
# MAIL ENDPOINTS
# ============================================================================
def handle_mail_send(request_handler, context):
    """
    POST /api/mail/send - Send an email

    Supports two formats:

    1. JSON body (simple text emails):
    {
        "to": ["recipient@address"],
        "cc": ["cc@address"],        // optional
        "bcc": ["bcc@address"],      // optional
        "subject": "Email subject",
        "body": "Email body text",
        "attachments": []            // optional - list of file paths
        "storage_weeks": 8           // optional - default 8
    }

    2. multipart/form-data (binary email files):
        - email_file: CBDF binary email file (required)
        - searchable_text: Plain text for indexing (required)
        - subject: Email subject (required)
        - subsubject: Secondary subject (optional)
        - to[]: Array of recipient addresses (required)
        - cc[]: Carbon copy recipients (optional)
        - bcc[]: Blind carbon copy recipients (optional)
        - attachments[]: Array of file paths (optional, max 200)
        - storage_weeks: Storage duration (optional, default 8)

    Returns 202 Accepted with task_id for async processing.
    """
    from src.email_sender import send_email_async, SendEmailErrorCode, validate_request
    from src.qmail_types import SendEmailRequest

    app_ctx = request_handler.server_instance.app_context

    # Parse request based on content type
    content_type = context.headers.get('Content-Type', '')
    email_data = context.json if context.json else {}

    # Build SendEmailRequest from input
    request_obj = SendEmailRequest()

    if 'multipart/form-data' in content_type.lower():
        # Handle multipart form data
        # Note: actual multipart parsing would be done by the server
        # For now, expect form fields in context.json or context.body
        form_data = email_data  # Simplified - real implementation needs multipart parsing

        request_obj.email_file = form_data.get('email_file', b'')
        request_obj.searchable_text = form_data.get('searchable_text', '')
        request_obj.subject = form_data.get('subject', '')
        request_obj.subsubject = form_data.get('subsubject')
        request_obj.to_recipients = form_data.get('to', [])
        request_obj.cc_recipients = form_data.get('cc', [])
        request_obj.bcc_recipients = form_data.get('bcc', [])
        request_obj.attachment_paths = form_data.get('attachments', [])
        request_obj.storage_weeks = form_data.get('storage_weeks', 8)
    else:
        # Handle JSON body - create CBDF from body text
        if not email_data.get("to"):
            request_handler.send_json_response(400, {
                "error": "Missing required field: 'to'",
                "status": "error"
            })
            return

        if not email_data.get("subject"):
            request_handler.send_json_response(400, {
                "error": "Missing required field: 'subject'",
                "status": "error"
            })
            return

        # Create simple CBDF-like structure from text body
        body_text = email_data.get('body', '')
        email_content = body_text.encode('utf-8') if body_text else b''
        request_obj.email_file = email_content
        request_obj.searchable_text = body_text
        request_obj.subject = email_data.get('subject', '')
        request_obj.subsubject = email_data.get('subsubject')

        # Handle recipients - can be string or list
        to_list = email_data.get('to', [])
        request_obj.to_recipients = to_list if isinstance(to_list, list) else [to_list]

        cc_list = email_data.get('cc', [])
        request_obj.cc_recipients = cc_list if isinstance(cc_list, list) else [cc_list] if cc_list else []

        bcc_list = email_data.get('bcc', [])
        request_obj.bcc_recipients = bcc_list if isinstance(bcc_list, list) else [bcc_list] if bcc_list else []

        request_obj.attachment_paths = email_data.get('attachments', [])
        request_obj.storage_weeks = email_data.get('storage_weeks', 8)

    # Validate request
    try:
        # We call it without the second argument to avoid the LoggerHandle mismatch
        err, err_msg = validate_request(request=request_obj)
    except Exception as e:
        print(f"CRITICAL: Validation crashed! Error: {e}")
        request_handler.send_json_response(500, {
            "error": f"Validation logic error: {e}",
            "status": "error"
        })
        return

    if err != SendEmailErrorCode.SUCCESS:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "error_code": int(err),
            "status": "error"
        })
        return

    # Get servers for upload
    servers = []
    if hasattr(app_ctx, 'config') and app_ctx.config:
        servers = [
            {'address': s.address, 'port': s.port, 'index': s.index}
            for s in (app_ctx.config.qmail_servers or [])
        ]

    # If no servers configured, use defaults for testing
    if not servers:
        servers = [
            {'address': f'raida{i}.cloudcoin.global', 'port': 443, 'index': i}
            for i in range(5)
        ]

    # 1. Register the task with the actual Task Manager
    try:
        err_task, task_id = create_task(
            app_ctx.task_manager,
            task_type="send",
            params={"subject": request_obj.subject}
        )
    except NameError:
        request_handler.send_json_response(500, {"error": "TaskManager functions not imported"})
        return

    # 2. Mark it as starting (transitions state from PENDING to RUNNING)
    start_task(app_ctx.task_manager, task_id, "Initializing send process")

    # Get identity from config
    identity = app_ctx.config.identity if hasattr(app_ctx, 'config') and app_ctx.config else None

    response = {
        "status": "accepted",
        "task_id": task_id,
        "message": "Email queued for sending",
        "file_group_guid": "",
        "file_count": 1 + len(request_obj.attachment_paths),
        "estimated_cost": 0.0
    }

    # If thread pool is available, submit for background processing
    if hasattr(app_ctx, 'thread_pool') and app_ctx.thread_pool:
            def process_send():
                from src.task_manager import update_task_progress, complete_task, fail_task

                # This is the "messenger" that send_email_async uses to report progress
                def update_progress(internal_state):
                    update_task_progress(app_ctx.task_manager, task_id, internal_state.progress, internal_state.message)

                err, result = send_email_async(
                    request_obj, identity, app_ctx.db_handle, servers,
                    app_ctx.thread_pool.executor, 
                    update_progress, # <--- We pass the messenger here
                    app_ctx.logger
                )
                
                # FINAL STEP: Move the task to a finished state
                if result.success:
                    # result.__dict__ stores all the final GUIDs and costs for the user to see
                    complete_task(app_ctx.task_manager, task_id, result.__dict__, "Email sent successfully")
                else:
                    fail_task(app_ctx.task_manager, task_id, result.error_message, "Email sending failed")

            app_ctx.thread_pool.executor.submit(process_send)
    else:
        response["message"] = "Email queued (no thread pool - will process on next poll)"

    request_handler.send_json_response(202, response)

def handle_mail_download(request_handler, context):
    """
    GET /api/mail/download/{id} - Download an email by ID

    Path parameter:
        id: The file GUID to download (hex string, with or without dashes)

    Query parameters (optional):
        file_type: 0 for email body (default), 10+ for attachments

    Returns:
        - 200 with raw file bytes on success
        - 400 for invalid file_guid format
        - 404 if file_guid not found in database
        - 500 on download failure
    """
    # Get app context
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle
    logger = app_ctx.logger

    # Extract and validate file_guid
    file_guid = context.path_params.get('id')
    if not file_guid:
        request_handler.send_json_response(400, {"error": "Missing file_guid"})
        return

    # Validate GUID format (32 hex chars with optional dashes)
    clean_guid = file_guid.replace('-', '').strip()
    if len(clean_guid) != 32:
        request_handler.send_json_response(400, {
            "error": "Invalid file_guid format",
            "details": "Expected 32 hex characters"
        })
        return

    try:
        bytes.fromhex(clean_guid)
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "Invalid file_guid format",
            "details": "Must be valid hexadecimal"
        })
        return

    # Extract file_type parameter
    file_type_list = context.query_params.get('file_type', ['0'])
    file_type_str = file_type_list[0] if file_type_list else '0'
    try:
        file_type = int(file_type_str)
    except ValueError:
        file_type = 0

    # Verify tell exists in database
    log_info(logger, "API", f"Download request for file_guid: {file_guid}")

    err, tell_info = get_received_tell_by_guid(db_handle, file_guid)
    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        log_error(logger, "API", f"Tell not found: {file_guid}")
        request_handler.send_json_response(404, {
            "error": "File not found",
            "file_guid": file_guid,
            "details": "No tell notification received for this file_guid"
        })
        return
    if err != DatabaseErrorCode.SUCCESS:
        log_error(logger, "API", f"Database error for {file_guid}: {err}")
        request_handler.send_json_response(500, {
            "error": "Database error",
            "details": str(err)
        })
        return

    # Get user credentials from config
    try:
        identity = app_ctx.config.identity
        denomination = identity.denomination
        serial_number = identity.serial_number
        device_id = getattr(identity, 'device_id', 0)

        # Get AN (Authenticity Number)
        an = _get_an_for_download(app_ctx)

    except AttributeError as e:
        log_error(logger, "API", f"Configuration error: {e}")
        request_handler.send_json_response(500, {
            "error": "Configuration error",
            "details": str(e)
        })
        return
    except ValueError as e:
        log_error(logger, "API", f"AN not found: {e}")
        request_handler.send_json_response(500, {
            "error": "Authentication key not configured",
            "details": str(e)
        })
        return

    # Download the file
    try:
        file_bytes = download_file_sync(
            db_handle=db_handle,
            file_guid=file_guid,
            file_type=file_type,
            denomination=denomination,
            serial_number=serial_number,
            device_id=device_id,
            an=an
        )

        log_info(logger, "API",
                 f"Download complete: {len(file_bytes)} bytes for {file_guid}")

        # Return raw bytes
        request_handler.send_response(200)
        request_handler.send_header('Content-Type', 'application/octet-stream')
        request_handler.send_header('Content-Length', str(len(file_bytes)))
        request_handler.send_header('Content-Disposition',
                                    f'attachment; filename="{file_guid}.bin"')
        request_handler.send_header('X-File-GUID', file_guid)
        request_handler.send_header('X-File-Type', str(file_type))
        request_handler.end_headers()
        request_handler.wfile.write(file_bytes)

    except FileNotFoundError as e:
        log_error(logger, "API", f"Tell not found during download: {file_guid} - {e}")
        request_handler.send_json_response(404, {
            "error": "Tell not found",
            "details": str(e)
        })
    except Exception as e:
        log_error(logger, "API", f"Download failed for {file_guid}: {e}")
        request_handler.send_json_response(500, {
            "error": "Download failed",
            "details": str(e)
        })


def _get_an_for_download(app_ctx):
    """
    Get the Authenticity Number (AN) for download operations.

    Tries multiple sources in order:
    1. Beacon handle encryption_key (if beacon is initialized)
    2. Config identity.an (if configured)
    3. Key file (Data/keys.txt)

    Returns:
        bytes: 16-byte AN

    Raises:
        ValueError: If AN cannot be found
    """
    # Try beacon handle first (most reliable if beacon is running)
    if app_ctx.beacon_handle and hasattr(app_ctx.beacon_handle, 'encryption_key'):
        an = app_ctx.beacon_handle.encryption_key
        if an is not None:
            return an

    # Try config
    identity = app_ctx.config.identity
    an = getattr(identity, 'an', None)
    if an is not None:
        return an if isinstance(an, bytes) else bytes.fromhex(an)

    # Try key file
    key_file_path = "Data/keys.txt"
    if os.path.exists(key_file_path):
        with open(key_file_path, 'r') as f:
            keys = [line.strip() for line in f.readlines() if line.strip()]

        # Use the beacon server's key index
        beacon_index = getattr(app_ctx.config.beacon, 'server_index', 0)
        if beacon_index < len(keys):
            return bytes.fromhex(keys[beacon_index])

    raise ValueError("Authenticity Number (AN) not found in beacon, config, or key file")


def handle_mail_list(request_handler, context):
    """
    GET /api/mail/list - List emails in a folder

    Query parameters:
        folder: inbox, sent, drafts, trash (default: inbox)
        limit: max results (default: 50)
        offset: pagination offset (default: 0)

    Returns paginated list of email summaries from database.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse query parameters
    folder = context.query_params.get('folder', ['inbox'])[0]

    # Validate folder
    valid_folders = ['inbox', 'sent', 'drafts', 'trash']
    if folder not in valid_folders:
        folder = 'inbox'

    try:
        limit = int(context.query_params.get('limit', ['50'])[0])
        limit = max(1, min(limit, 100))  # Clamp to 1-100
    except ValueError:
        limit = 50

    try:
        offset = int(context.query_params.get('offset', ['0'])[0])
        offset = max(0, offset)
    except ValueError:
        offset = 0

    # Get emails from database
    err, emails = list_emails(db_handle, folder=folder, limit=limit, offset=offset)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    # Get total count for pagination
    _, total_count = get_email_count(db_handle, folder=folder)

    # Convert EmailID bytes to hex strings for JSON serialization
    for email in emails:
        if email.get('EmailID') and isinstance(email['EmailID'], bytes):
            email['EmailID'] = email['EmailID'].hex()

    response = {
        "folder": folder,
        "emails": emails,
        "total_count": total_count,
        "limit": limit,
        "offset": offset
    }
    request_handler.send_json_response(200, response)


def handle_create_mailbox(request_handler, context):
    """
    POST /api/mail/create-mailbox - Create a new mailbox

    Expected JSON body:
    {
        "denomination": 1,
        "serial_number": 12345678
    }

    STUB: Returns success with provided values.
    FUTURE: Will validate against CloudCoin and configure identity.
    """
    data = context.json if context.json else {}

    denomination = data.get("denomination", 1)
    serial_number = data.get("serial_number", 0)

    # Format as QMail address
    mailbox_address = f"0006.{denomination}.{serial_number}"

    response = {
        "status": "created",
        "mailbox_address": mailbox_address,
        "denomination": denomination,
        "serial_number": serial_number,
        "message": "Mailbox creation stub - identity configuration pending"
    }
    request_handler.send_json_response(201, response)


# ============================================================================
# DATA ENDPOINTS
# ============================================================================

def handle_get_contacts(request_handler, context):
    """
    GET /api/data/contacts/popular - Get frequently contacted users

    Query parameters:
        limit: max results (default: 10)

    Returns contacts sorted by contact_count descending.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse query parameters
    try:
        limit = int(context.query_params.get('limit', ['10'])[0])
        limit = max(1, min(limit, 100))  # Clamp to 1-100
    except ValueError:
        limit = 10

    # Query database
    err, contacts = get_popular_contacts(db_handle, limit=limit)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    response = {
        "contacts": contacts,
        "count": len(contacts),
        "limit": limit
    }
    request_handler.send_json_response(200, response)


def handle_search_emails(request_handler, context):
    """
    GET /api/data/emails/search - Search emails using FTS5 full-text search

    Query parameters:
        q: search query string (required)
        limit: max results (default: 50)
        offset: pagination offset (default: 0)

    Returns search results with snippets showing match context.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse query parameters
    query = context.query_params.get('q', [''])[0]

    if not query or not query.strip():
        request_handler.send_json_response(400, {
            "error": "Missing required query parameter: 'q'",
            "status": "error"
        })
        return

    try:
        limit = int(context.query_params.get('limit', ['50'])[0])
        limit = max(1, min(limit, 100))  # Clamp to 1-100
    except ValueError:
        limit = 50

    try:
        offset = int(context.query_params.get('offset', ['0'])[0])
        offset = max(0, offset)
    except ValueError:
        offset = 0

    # Search database using FTS5
    err, results = search_emails(db_handle, query.strip(), limit=limit, offset=offset)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Search failed",
            "code": int(err),
            "status": "error"
        })
        return

    # Convert EmailID bytes to hex strings for JSON serialization
    for result in results:
        if result.get('EmailID') and isinstance(result['EmailID'], bytes):
            result['EmailID'] = result['EmailID'].hex()

    response = {
        "query": query,
        "results": results,
        "count": len(results),
        "limit": limit,
        "offset": offset
    }
    request_handler.send_json_response(200, response)


def handle_search_users(request_handler, context):
    """
    GET /api/data/users/search - Search users for recipient autocomplete

    Query parameters:
        q: search query string (required) - searches first_name, last_name, description
        limit: max results (default: 20)

    Returns matching users sorted by relevance.
    """
    # Get app context from server instance
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Parse query parameters
    query = context.query_params.get('q', [''])[0]

    if not query or not query.strip():
        request_handler.send_json_response(400, {
            "error": "Missing required query parameter: 'q'",
            "status": "error"
        })
        return

    try:
        limit = int(context.query_params.get('limit', ['20'])[0])
        limit = max(1, min(limit, 100))  # Clamp to 1-100
    except ValueError:
        limit = 20

    # Search database
    err, users = search_users(db_handle, query.strip(), limit=limit)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Search failed",
            "code": int(err),
            "status": "error"
        })
        return

    response = {
        "query": query,
        "users": users,
        "count": len(users),
        "limit": limit
    }
    request_handler.send_json_response(200, response)


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
    include_unavailable = context.query_params.get('include_unavailable', ['false'])[0].lower() == 'true'
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

def handle_task_status(request_handler, context):
    """
    GET /api/task/status/{id} - Get async task status

    Path parameter:
        id: The task ID to check

    Returns:
        - 200 with task status on success
        - 400 if task_id is missing
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

    # Get task status
    err, status = get_task_status(app_ctx.task_manager, task_id)

    if err == TaskErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Task not found",
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
            "error": f"Failed to get task status: {err}",
            "task_id": task_id,
            "status": "error"
        })
        return

    # Build response from TaskStatus
    response = {
        "task_id": status.task_id,
        "state": status.state,
        "progress": status.progress,
        "message": status.message,
        "result": status.result,
        "error": status.error,
        "created_at": status.created_timestamp,
        "started_at": status.started_timestamp,
        "completed_at": status.completed_timestamp,
        "is_finished": status.is_finished,
        "is_successful": status.is_successful
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
    GET /api/mail/{id} - Get email metadata (without body by default)

    Path parameter:
        id: The email ID (hex string, 32 chars)

    Returns:
        - 200 with email metadata
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

    # Get email metadata
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

    request_handler.send_json_response(200, metadata)


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

    previous_folder = metadata.get('folder', 'unknown') if metadata else 'unknown'

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

    Returns fixed list of folders with display names.
    """
    response = {
        "folders": [
            {"name": "inbox", "display_name": "Inbox"},
            {"name": "sent", "display_name": "Sent"},
            {"name": "drafts", "display_name": "Drafts"},
            {"name": "trash", "display_name": "Trash"}
        ]
    }
    request_handler.send_json_response(200, response)


def handle_mail_count(request_handler, context):
    """
    GET /api/mail/count - Get unread/total counts per folder

    Returns counts for all folders with summary.
    """
    app_ctx = request_handler.server_instance.app_context
    db_handle = app_ctx.db_handle

    # Get folder counts
    err, counts = get_folder_counts(db_handle)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "code": int(err),
            "status": "error"
        })
        return

    # Calculate summary
    total_emails = sum(folder['total'] for folder in counts.values())
    total_unread = sum(folder['unread'] for folder in counts.values())

    response = {
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
    request_handler.send_header('Content-Disposition', f'attachment; filename="{filename}"')
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
    err, contacts, total = get_all_contacts(db_handle, page=page, limit=limit, search=search)

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
    valid, err_msg = _validate_contact_name(body.get('first_name'), 'first_name', required=True)
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate last_name (optional)
    valid, err_msg = _validate_contact_name(body.get('last_name'), 'last_name', required=False)
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

    Query Parameters:
        page: int (default 1, min 1)
        limit: int (default 50, max 200)

    Response (200):
    {
        "drafts": [...],
        "pagination": {
            "page": 1,
            "limit": 50,
            "total": 15,
            "total_pages": 1
        }
    }
    """
    db_handle = context.get('db_handle')
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Parse query parameters
    query_params = context.get('query_params', {})

    # Parse page
    page = 1
    page_str = query_params.get('page', ['1'])[0]
    try:
        page = int(page_str)
        if page < 1:
            request_handler.send_json_response(400, {
                "error": "page must be a positive integer",
                "status": "error"
            })
            return
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "page must be a valid integer",
            "status": "error"
        })
        return

    # Parse limit
    limit = 50
    limit_str = query_params.get('limit', ['50'])[0]
    try:
        limit = int(limit_str)
        if limit < 1 or limit > MAX_DRAFTS_LIMIT:
            request_handler.send_json_response(400, {
                "error": f"limit must be between 1 and {MAX_DRAFTS_LIMIT}",
                "status": "error"
            })
            return
    except ValueError:
        request_handler.send_json_response(400, {
            "error": "limit must be a valid integer",
            "status": "error"
        })
        return

    # Get drafts
    err, drafts, total = list_drafts(db_handle, page=page, limit=limit)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "status": "error"
        })
        return

    # Calculate total pages
    total_pages = (total + limit - 1) // limit if total > 0 else 1

    request_handler.send_json_response(200, {
        "drafts": drafts,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages
        }
    })


def handle_draft_save(request_handler, context):
    """
    POST /api/mail/draft - Save a new draft.

    Request Body:
    {
        "subject": "Draft subject",
        "body": "Draft content...",
        "recipient_ids": [1, 2, 3],
        "cc_ids": [4]
    }

    Response (201):
    {
        "status": "created",
        "draft": {...}
    }
    """
    db_handle = context.get('db_handle')
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Parse request body
    try:
        body = request_handler.get_json_body()
        if body is None:
            body = {}
    except Exception:
        request_handler.send_json_response(400, {
            "error": "Invalid JSON body",
            "status": "error"
        })
        return

    # Validate subject (optional per feedback)
    subject = body.get('subject', '')
    valid, err_msg = _validate_draft_subject(subject)
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate body
    draft_body = body.get('body', '')
    valid, err_msg = _validate_draft_body(draft_body)
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate recipient_ids
    recipient_ids = body.get('recipient_ids', [])
    valid, err_msg = _validate_recipient_ids(recipient_ids, 'recipient_ids')
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Validate cc_ids
    cc_ids = body.get('cc_ids', [])
    valid, err_msg = _validate_recipient_ids(cc_ids, 'cc_ids')
    if not valid:
        request_handler.send_json_response(400, {
            "error": err_msg,
            "status": "error"
        })
        return

    # Prepare email dict for store_email
    from datetime import datetime
    now = datetime.now().isoformat()

    email_data = {
        'subject': subject,
        'body': draft_body,
        'received_timestamp': now,  # Creation time
        'sent_timestamp': now,      # Last modified time
        'recipient_ids': recipient_ids,
        'cc_ids': cc_ids,
        'folder': 'drafts',         # Set folder atomically
        'is_read': 1                # Mark as read to avoid unread count pollution
    }

    # Store the draft atomically with folder='drafts' and is_read=1
    err, email_id = store_email(db_handle, email_data)

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Failed to create draft",
            "status": "error"
        })
        return

    # Retrieve the created draft
    err, draft = retrieve_email(db_handle, email_id)

    if err != DatabaseErrorCode.SUCCESS:
        # Draft was created but retrieval failed
        request_handler.send_json_response(201, {
            "status": "created",
            "draft": {
                "email_id": email_id.hex() if email_id else None
            }
        })
        return

    # Format response
    response_draft = {
        "email_id": draft.get('email_id'),
        "subject": draft.get('subject'),
        "body": draft.get('body'),
        "recipient_ids": [r['user_id'] for r in draft.get('recipients', [])],
        "cc_ids": [c['user_id'] for c in draft.get('cc', [])],
        "folder": draft.get('folder'),
        "date_created": draft.get('received_timestamp'),
        "last_modified": draft.get('sent_timestamp')
    }

    request_handler.send_json_response(201, {
        "status": "created",
        "draft": response_draft
    })


def handle_draft_update(request_handler, context):
    """
    PUT /api/mail/draft/{id} - Update an existing draft.

    Uses JSON Merge Patch semantics:
    - Key present with value: replace field
    - Key present with []: clear field
    - Key absent: leave unchanged

    Request Body (all fields optional):
    {
        "subject": "Updated subject",
        "body": "Updated body",
        "recipient_ids": [5, 6],
        "cc_ids": []
    }

    Response (200):
    {
        "status": "updated",
        "draft": {...}
    }
    """
    db_handle = context.get('db_handle')
    if db_handle is None:
        request_handler.send_json_response(500, {
            "error": "Database not available",
            "status": "error"
        })
        return

    # Get email_id from path
    path_params = context.get('path_params', {})
    email_id_str = path_params.get('id')

    if not email_id_str:
        request_handler.send_json_response(400, {
            "error": "email_id is required",
            "status": "error"
        })
        return

    # Validate email_id format (32 hex chars or UUID with dashes)
    clean_id = email_id_str.replace('-', '')
    if len(clean_id) != 32 or not all(c in '0123456789abcdefABCDEF' for c in clean_id):
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "status": "error"
        })
        return

    # Parse request body
    try:
        body = request_handler.get_json_body()
        if body is None:
            body = {}
    except Exception:
        request_handler.send_json_response(400, {
            "error": "Invalid JSON body",
            "status": "error"
        })
        return

    # Build draft_data with only present keys (JSON Merge Patch semantics)
    draft_data = {}

    # Validate and add subject if present
    if 'subject' in body:
        valid, err_msg = _validate_draft_subject(body['subject'])
        if not valid:
            request_handler.send_json_response(400, {
                "error": err_msg,
                "status": "error"
            })
            return
        draft_data['subject'] = body['subject']

    # Validate and add body if present
    if 'body' in body:
        valid, err_msg = _validate_draft_body(body['body'])
        if not valid:
            request_handler.send_json_response(400, {
                "error": err_msg,
                "status": "error"
            })
            return
        draft_data['body'] = body['body']

    # Validate and add recipient_ids if present
    if 'recipient_ids' in body:
        valid, err_msg = _validate_recipient_ids(body['recipient_ids'], 'recipient_ids')
        if not valid:
            request_handler.send_json_response(400, {
                "error": err_msg,
                "status": "error"
            })
            return
        draft_data['recipient_ids'] = body['recipient_ids']

    # Validate and add cc_ids if present
    if 'cc_ids' in body:
        valid, err_msg = _validate_recipient_ids(body['cc_ids'], 'cc_ids')
        if not valid:
            request_handler.send_json_response(400, {
                "error": err_msg,
                "status": "error"
            })
            return
        draft_data['cc_ids'] = body['cc_ids']

    # Update the draft
    err, updated_draft = update_draft(db_handle, clean_id, draft_data)

    if err == DatabaseErrorCode.ERR_NOT_FOUND:
        request_handler.send_json_response(404, {
            "error": "Draft not found",
            "email_id": email_id_str,
            "status": "error"
        })
        return

    if err == DatabaseErrorCode.ERR_INVALID_PARAM:
        request_handler.send_json_response(400, {
            "error": "Invalid email_id format",
            "status": "error"
        })
        return

    if err != DatabaseErrorCode.SUCCESS:
        request_handler.send_json_response(500, {
            "error": "Database error",
            "status": "error"
        })
        return

    # Format response
    response_draft = {
        "email_id": updated_draft.get('email_id'),
        "subject": updated_draft.get('subject'),
        "body": updated_draft.get('body'),
        "recipient_ids": [r['user_id'] for r in updated_draft.get('recipients', [])],
        "cc_ids": [c['user_id'] for c in updated_draft.get('cc', [])],
        "folder": updated_draft.get('folder'),
        "date_created": updated_draft.get('received_timestamp'),
        "last_modified": updated_draft.get('sent_timestamp')
    }

    request_handler.send_json_response(200, {
        "status": "updated",
        "draft": response_draft
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
    server.register_route('GET', '/api/qmail/ping', handle_ping)

    # Mail operations
    server.register_route('POST', '/api/mail/send', handle_mail_send)
    server.register_route('GET', '/api/mail/download/{id}', handle_mail_download)
    server.register_route('GET', '/api/mail/list', handle_mail_list)
    server.register_route('POST', '/api/mail/create-mailbox', handle_create_mailbox)

    # Email management endpoints
    server.register_route('GET', '/api/mail/{id}', handle_mail_get)
    server.register_route('DELETE', '/api/mail/{id}', handle_mail_delete)
    server.register_route('PUT', '/api/mail/{id}/move', handle_mail_move)
    server.register_route('PUT', '/api/mail/{id}/read', handle_mail_read)
    server.register_route('GET', '/api/mail/folders', handle_mail_folders)
    server.register_route('GET', '/api/mail/count', handle_mail_count)

    # Attachment endpoints
    server.register_route('GET', '/api/mail/{id}/attachments', handle_mail_attachments)
    server.register_route('GET', '/api/mail/{id}/attachment/{n}', handle_mail_attachment_download)

    # Data operations
    server.register_route('GET', '/api/data/contacts/popular', handle_get_contacts)
    server.register_route('GET', '/api/data/emails/search', handle_search_emails)
    server.register_route('GET', '/api/data/users/search', handle_search_users)
    server.register_route('GET', '/api/data/servers', handle_get_servers)

    # Admin operations
    server.register_route('POST', '/api/admin/sync', handle_sync)
    server.register_route('GET', '/api/admin/servers/parity', handle_get_parity_server)
    server.register_route('POST', '/api/admin/servers/parity', handle_set_parity_server)

    # Task operations
    server.register_route('GET', '/api/task/status/{id}', handle_task_status)
    server.register_route('POST', '/api/task/cancel/{id}', handle_task_cancel)

    # Contact management endpoints
    server.register_route('GET', '/api/contacts', handle_contacts_list)
    server.register_route('POST', '/api/contacts', handle_contacts_add)
    server.register_route('DELETE', '/api/contacts/{id}', handle_contacts_delete)

    # Draft management endpoints
    server.register_route('GET', '/api/mail/drafts', handle_drafts_list)
    server.register_route('POST', '/api/mail/draft', handle_draft_save)
    server.register_route('PUT', '/api/mail/draft/{id}', handle_draft_update)


# ============================================================================
# MAIN (for standalone testing)
# ============================================================================

if __name__ == "__main__":
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
    print("  POST /api/mail/create-mailbox   - Create mailbox")
    print("  GET  /api/data/contacts/popular - Get contacts")
    print("  GET  /api/data/emails/search    - Search emails")
    print("  GET  /api/data/users/search     - Search users")
    print("  GET  /api/data/servers          - Get QMail servers")
    print("  POST /api/admin/sync            - Trigger data sync")
    print("  GET  /api/admin/servers/parity  - Get parity server")
    print("  POST /api/admin/servers/parity  - Set parity server")
    print("  GET  /api/task/status/{id}      - Task status")
    print("  POST /api/task/cancel/{id}      - Cancel task")
