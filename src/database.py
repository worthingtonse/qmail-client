"""
opus45_database.py - SQLite Database Operations for QMail Client Core

This module handles all SQLite operations for local storage of emails,
contacts, servers, attachments, and sessions. Designed for easy translation
to C (database.c/database.h) in Phase III.

Author: Claude Opus 4.5 (opus45)
Phase: I
Version: 1.1.0

Changes in v1.1.0:
    - Added path validation security check (from Sonnet review)
    - Added safety comments for dynamic SQL queries (from Sonnet review)
    - Added support for qmail_types.py dataclasses (from Gemini review)
    - Added note about Locker_Keys CASCADE behavior consideration

Functions (from plan 4.8):
    init_database(db_path)               -> db_handle
    close_database(handle)               -> bool
    store_email(handle, email)           -> email_id
    retrieve_email(handle, email_id)     -> Email
    store_contact(handle, contact)       -> contact_id
    get_popular_contacts(handle, limit)  -> User[]
    update_email_flags(handle, id, flags)-> bool
    execute_query(handle, sql, params)   -> ResultSet

C Notes: Use sqlite3 C library directly. This Python implementation
uses Python's built-in sqlite3 module which wraps the same C library.
"""

import sqlite3
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import IntEnum

# Try to import from package, fall back to direct import for standalone testing
try:
    from .logger import log_info, log_error, log_warning, log_debug
except ImportError:
    # Fallback for standalone testing (uses new 3-parameter API with context)
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")

# Module context for logging
DB_CONTEXT = "DatabaseMod"

# Try to import shared types from qmail_types.py
# These dataclasses provide type safety and consistency across modules
try:
    from .qmail_types import Email, User, Attachment
    TYPES_AVAILABLE = True
except ImportError:
    # Fallback for standalone testing - types not available
    TYPES_AVAILABLE = False
    Email = None
    User = None
    Attachment = None


# ============================================================================
# ERROR CODES (C-style error handling)
# ============================================================================

class DatabaseErrorCode(IntEnum):
    """
    Error codes for database operations.
    C: typedef enum { DB_SUCCESS = 0, ... } DatabaseErrorCode;
    """
    SUCCESS = 0
    ERR_OPEN_FAILED = 1
    ERR_CLOSE_FAILED = 2
    ERR_QUERY_FAILED = 3
    ERR_NOT_FOUND = 4
    ERR_INVALID_PARAM = 5
    ERR_CONSTRAINT = 6
    ERR_SCHEMA = 7
    ERR_IO = 8


# ============================================================================
# DATABASE HANDLE (Opaque handle for C conversion)
# ============================================================================

class DatabaseHandle:
    """
    Opaque handle for database connection.
    C: typedef struct DatabaseHandle { sqlite3* conn; char* path; } DatabaseHandle;
    """
    __slots__ = ('connection', 'path', 'logger')

    def __init__(self, connection: sqlite3.Connection, path: str, logger: Any = None):
        self.connection = connection
        self.path = path
        self.logger = logger


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _safe_hex_to_bytes(
    hex_string: str,
    logger_handle: Optional[Any] = None
) -> Tuple[bool, bytes, str]:
    """
    Safely convert a hex string (possibly with dashes) to bytes.

    Args:
        hex_string: Hex string to convert (may contain dashes like UUID format)
        logger_handle: Optional logger handle

    Returns:
        Tuple of (success, bytes_result, error_message)
    """
    if not hex_string:
        return False, b'', "Empty hex string"

    try:
        # Remove dashes and whitespace
        clean_hex = hex_string.replace('-', '').replace(' ', '').strip()
        result = bytes.fromhex(clean_hex)
        return True, result, ""
    except ValueError as e:
        log_error(logger_handle, DB_CONTEXT,
                  f"Invalid hex string: {hex_string[:20]}...", str(e))
        return False, b'', f"Invalid hex characters: {str(e)}"


# ============================================================================
# SCHEMA DEFINITION
# Based on: docs/API endpoint descriptions/api-client-database.md
# ============================================================================

SCHEMA_SQL = """
-- Enable Foreign Keys constraints (SQLite defaults them to off)
PRAGMA foreign_keys = ON;

-- ==========================================
-- 1. QMailServers
-- ==========================================
CREATE TABLE IF NOT EXISTS QMailServers (
    QMailServerID TEXT PRIMARY KEY,
    ServerIndex INTEGER,
    IPAddress TEXT NOT NULL,
    PortNumb INTEGER,
    server_type TEXT CHECK(server_type IN ('RAIDA', 'DRD', 'DKE', 'QMAIL', 'QWEB', 'QVPN')),
    cost_per_mb TEXT,
    Cost_per_week_storage TEXT,
    ping_ms INTEGER,
    percent_uptime REAL,
    performance_benchmark_percentile REAL,
    date_created DATETIME,
    is_available INTEGER DEFAULT 1,
    last_checked DATETIME,
    use_for_parity INTEGER DEFAULT 0,
    synced_at DATETIME
);

-- ==========================================
-- 2. Users (Contacts)
-- ==========================================
CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY,
    FirstName TEXT,
    MiddleName TEXT,
    LastName TEXT,
    Avatar TEXT,
    streak INTEGER DEFAULT 0,
    sending_fee TEXT,
    Description TEXT,
    BeaconID TEXT,
    dreg_score INTEGER DEFAULT 0,
    emails_sent_total INTEGER DEFAULT 0,
    date_created DATETIME,
    auto_address TEXT,
    last_contacted_timestamp DATETIME,
    contact_count INTEGER DEFAULT 0,
    synced_at DATETIME
);

-- ==========================================
-- 3. Emails (Main Storage Table)
-- ==========================================
CREATE TABLE IF NOT EXISTS Emails (
    EmailID BLOB PRIMARY KEY,
    Subject TEXT,
    Body TEXT,
    ReceivedTimestamp DATETIME,
    SentTimestamp DATETIME,
    Meta BLOB,
    Style BLOB,
    is_read INTEGER DEFAULT 0,
    is_starred INTEGER DEFAULT 0,
    is_trashed INTEGER DEFAULT 0,
    folder TEXT DEFAULT 'inbox'
);

-- ==========================================
-- 4. Email FTS Index (Search Engine)
-- ==========================================
CREATE VIRTUAL TABLE IF NOT EXISTS Emails_FTS USING fts5(
    Subject,
    Body,
    content='Emails',
    content_rowid='rowid'
);

-- Triggers to keep Search Index in sync with Main Table
CREATE TRIGGER IF NOT EXISTS emails_ai AFTER INSERT ON Emails BEGIN
    INSERT INTO Emails_FTS(rowid, Subject, Body) VALUES (new.rowid, new.Subject, new.Body);
END;

CREATE TRIGGER IF NOT EXISTS emails_ad AFTER DELETE ON Emails BEGIN
    INSERT INTO Emails_FTS(Emails_FTS, rowid, Subject, Body) VALUES('delete', old.rowid, old.Subject, old.Body);
END;

CREATE TRIGGER IF NOT EXISTS emails_au AFTER UPDATE ON Emails BEGIN
    INSERT INTO Emails_FTS(Emails_FTS, rowid, Subject, Body) VALUES('delete', old.rowid, old.Subject, old.Body);
    INSERT INTO Emails_FTS(rowid, Subject, Body) VALUES (new.rowid, new.Subject, new.Body);
END;

-- ==========================================
-- 5. Junction: Emails <-> Users
-- ==========================================
CREATE TABLE IF NOT EXISTS Junction_Email_Users (
    EmailID BLOB,
    UserID INTEGER,
    user_type TEXT CHECK(user_type IN ('TO', 'CC', 'BC', 'MASS', 'FROM')),
    PRIMARY KEY (EmailID, UserID, user_type),
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE,
    FOREIGN KEY(UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

-- ==========================================
-- 6. Junction: Emails <-> QMailServers
-- ==========================================
CREATE TABLE IF NOT EXISTS Junction_Email_QMailServers (
    EmailID BLOB,
    QMailServerID TEXT,
    stripe_index INTEGER,
    PRIMARY KEY (EmailID, QMailServerID),
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE,
    FOREIGN KEY(QMailServerID) REFERENCES QMailServers(QMailServerID)
);

-- ==========================================
-- 7. Locker_Keys
-- NOTE: Uses ON DELETE CASCADE for EmailID FK. This means deleting an email
-- will also delete associated locker keys. Consider using SET NULL instead
-- if payment keys should survive email deletion (Phase II consideration).
-- ==========================================
CREATE TABLE IF NOT EXISTS Locker_Keys (
    KeyID INTEGER PRIMARY KEY AUTOINCREMENT,
    EmailID BLOB,
    Key BLOB NOT NULL,
    ReceivedFrom INTEGER,
    ReceivedTimestamp DATETIME,
    SentTimestamp DATETIME,
    RedeemedTimestamp DATETIME,
    IsAuthentic INTEGER,
    Amount TEXT,
    SendingServerID INTEGER,
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE
);

-- ==========================================
-- 8. Attachments
-- ==========================================
CREATE TABLE IF NOT EXISTS Attachments (
    Attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    EmailID BLOB,
    name TEXT,
    file_extension TEXT,
    storage_mode TEXT CHECK(storage_mode IN ('INTERNAL', 'EXTERNAL')),
    status TEXT,
    data_blob BLOB,
    file_path TEXT,
    size_bytes INTEGER,
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE
);

-- ==========================================
-- 9. Session
-- ==========================================
CREATE TABLE IF NOT EXISTS Session (
    SessionPk INTEGER PRIMARY KEY AUTOINCREMENT,
    SessionGUID BLOB,
    QMailServerID TEXT,
    SessionEncryptionKey BLOB,
    created_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_timestamp DATETIME,
    FOREIGN KEY(QMailServerID) REFERENCES QMailServers(QMailServerID)
);

-- ==========================================
-- 10. Pending Tells (for retry queue)
-- ==========================================
CREATE TABLE IF NOT EXISTS PendingTells (
    TellID INTEGER PRIMARY KEY AUTOINCREMENT,
    FileGroupGUID BLOB NOT NULL,
    RecipientAddress TEXT NOT NULL,
    RecipientType INTEGER NOT NULL DEFAULT 0,
    BeaconServerID TEXT NOT NULL,
    LockerCode BLOB NOT NULL,
    ServerListJSON TEXT NOT NULL,
    CreatedTimestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    RetryCount INTEGER DEFAULT 0,
    LastAttemptTimestamp DATETIME,
    ErrorMessage TEXT,
    Status TEXT DEFAULT 'pending'
);

-- Table for incoming email metadata (from .tell files)
CREATE TABLE IF NOT EXISTS received_tells (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_guid TEXT UNIQUE,            -- The unique identifier for the mail package
    locker_code BLOB,                 -- Code used to fetch stripes
    tell_type INTEGER,                -- 0 for QMail, 1 for Payment
    download_status INTEGER DEFAULT 0, -- 0=Metadata Only, 1=Downloaded
    read_status INTEGER DEFAULT 0,     -- 0=Unread, 1=Read
    local_path TEXT,                  -- Path to the file on local disk
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for tracking stripe locations
CREATE TABLE IF NOT EXISTS received_stripes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tell_id INTEGER,
    server_ip TEXT,
    stripe_id INTEGER,
    is_parity BOOLEAN,
    port INTEGER,
    stripe_hash TEXT,  -- ADD THIS LINE
    FOREIGN KEY(tell_id) REFERENCES received_tells(id) ON DELETE CASCADE
);

-- ==========================================
-- 11. Index for performance
-- ==========================================
CREATE INDEX IF NOT EXISTS idx_emails_received ON Emails(ReceivedTimestamp);
CREATE INDEX IF NOT EXISTS idx_emails_folder ON Emails(folder);
CREATE INDEX IF NOT EXISTS idx_users_name ON Users(FirstName, LastName);
CREATE INDEX IF NOT EXISTS idx_users_address ON Users(auto_address);
CREATE INDEX IF NOT EXISTS idx_attachments_email ON Attachments(EmailID);
CREATE INDEX IF NOT EXISTS idx_servers_available ON QMailServers(is_available);
CREATE INDEX IF NOT EXISTS idx_servers_parity ON QMailServers(use_for_parity);
CREATE INDEX IF NOT EXISTS idx_pending_tells_status ON PendingTells(Status);
CREATE INDEX IF NOT EXISTS idx_received_tells_download_status ON received_tells(download_status);
CREATE INDEX IF NOT EXISTS idx_received_tells_file_guid ON received_tells(file_guid);
CREATE INDEX IF NOT EXISTS idx_received_stripes_tell_id ON received_stripes(tell_id);
"""


# ============================================================================
# INIT DATABASE
# ============================================================================

def init_database(db_path: str, logger: Any = None, base_dir: str = None) -> Tuple[DatabaseErrorCode, Optional[DatabaseHandle]]:
    """
    Initialize database connection and create schema if needed.

    Args:
        db_path: Path to the SQLite database file
        logger: Optional logger handle for logging operations
        base_dir: Optional base directory for path validation security.
                  If provided, db_path must be within this directory.

    Returns:
        Tuple of (error_code, database_handle)
        Handle is None if initialization failed.

    C signature: DatabaseErrorCode init_database(const char* db_path, const char* base_dir, DatabaseHandle** out_handle);
    """
    if not db_path:
        log_error(logger, DB_CONTEXT, "init_database failed", "db_path is empty")
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Security: Validate path doesn't escape intended directory (prevents path traversal)
    # This check is optional but recommended for production use
    if base_dir is not None:
        abs_db_path = os.path.abspath(db_path)
        abs_base_dir = os.path.abspath(base_dir)
        if not abs_db_path.startswith(abs_base_dir):
            log_error(logger, DB_CONTEXT, "init_database failed", f"db_path '{db_path}' escapes base_dir (path traversal attempt)")
            return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Ensure directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir)
            log_info(logger, DB_CONTEXT, f"Created database directory: {db_dir}")
        except OSError as e:
            log_error(logger, DB_CONTEXT, "Failed to create database directory", str(e))
            return DatabaseErrorCode.ERR_IO, None

    try:
        # Connect to database (creates file if doesn't exist)
        # check_same_thread=False allows connection to be used from multiple threads
        # (required for multi-threaded API server)
        connection = sqlite3.connect(db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row  # Enable dict-like access to rows

        # Enable foreign keys
        connection.execute("PRAGMA foreign_keys = ON")

        # Create schema
        cursor = connection.cursor()
        cursor.executescript(SCHEMA_SQL)
        connection.commit()

        handle = DatabaseHandle(connection=connection, path=db_path, logger=logger)
        log_info(logger, DB_CONTEXT, f"Database initialized successfully: {db_path}")

        return DatabaseErrorCode.SUCCESS, handle

    except sqlite3.Error as e:
        log_error(logger, DB_CONTEXT, "Database initialization failed", str(e))
        return DatabaseErrorCode.ERR_OPEN_FAILED, None


# ============================================================================
# CLOSE DATABASE
# ============================================================================

def close_database(handle: DatabaseHandle) -> bool:
    """
    Close database connection and release resources.

    Args:
        handle: Database handle from init_database()

    Returns:
        True if closed successfully, False otherwise

    C signature: bool close_database(DatabaseHandle* handle);
    """
    if handle is None or handle.connection is None:
        return True  # Already closed

    try:
        handle.connection.close()
        handle.connection = None
        log_info(handle.logger, DB_CONTEXT, f"Database closed: {handle.path}")
        return True
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to close database", str(e))
        return False


# ============================================================================
# STORE EMAIL
# ============================================================================

def store_email(handle: DatabaseHandle, email: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[bytes]]:
    """
    Store an email in the database.

    Args:
        handle: Database handle
        email: Dictionary with email data:
            - email_id: bytes (GUID) - optional, generated if not provided
            - subject: str
            - body: str
            - sender_id: int (UserID)
            - recipient_ids: List[int] (UserIDs)
            - cc_ids: List[int] (UserIDs) - optional
            - received_timestamp: str (ISO format) - optional
            - sent_timestamp: str (ISO format) - optional
            - meta: bytes - optional
            - style: bytes - optional

    Returns:
        Tuple of (error_code, email_id as bytes)

    C signature: DatabaseErrorCode store_email(DatabaseHandle* handle, const Email* email, uint8_t* out_email_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Generate email ID if not provided
    email_id = email.get('email_id')
    if email_id is None:
        email_id = uuid.uuid4().bytes
    elif isinstance(email_id, str):
        # Convert hex string to bytes (with safe conversion)
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, None
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Insert email (with optional folder and is_read for drafts)
        folder = email.get('folder', 'inbox')
        is_read = email.get('is_read', 0)
        cursor.execute("""
            INSERT INTO Emails (EmailID, Subject, Body, ReceivedTimestamp, SentTimestamp, Meta, Style, folder, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email_id,
            email.get('subject', ''),
            email.get('body', ''),
            email.get('received_timestamp'),
            email.get('sent_timestamp'),
            email.get('meta'),
            email.get('style'),
            folder,
            is_read
        ))

        # Link sender (FROM)
        sender_id = email.get('sender_id')
        if sender_id is not None:
            cursor.execute("""
                INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                VALUES (?, ?, 'FROM')
            """, (email_id, sender_id))

        # Link recipients (TO)
        for recipient_id in email.get('recipient_ids', []):
            cursor.execute("""
                INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                VALUES (?, ?, 'TO')
            """, (email_id, recipient_id))

        # Link CC recipients
        for cc_id in email.get('cc_ids', []):
            cursor.execute("""
                INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                VALUES (?, ?, 'CC')
            """, (email_id, cc_id))

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT, f"Stored email: {email_id.hex()}")

        return DatabaseErrorCode.SUCCESS, email_id

    except sqlite3.IntegrityError as e:
        log_error(handle.logger, DB_CONTEXT, "Constraint violation storing email", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_CONSTRAINT, None
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store email", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# UPDATE DRAFT
# ============================================================================

def update_draft(handle: DatabaseHandle, email_id: bytes, draft_data: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Update a draft email's content and recipients.

    Uses JSON Merge Patch semantics:
    - Key present with value: replace field with new value
    - Key present with []: clear the field (e.g., remove all TO recipients)
    - Key absent: leave existing value unchanged

    Args:
        handle: Database handle
        email_id: Email GUID (bytes or hex string)
        draft_data: Dictionary with optional fields:
            - subject: str (replaces if present)
            - body: str (replaces if present)
            - recipient_ids: List[int] (replaces TO recipients if key present)
            - cc_ids: List[int] (replaces CC recipients if key present)

    Returns:
        Tuple of (error_code, updated_draft_dict or None)

    C signature: DatabaseErrorCode update_draft(DatabaseHandle* handle, const uint8_t* email_id, const DraftData* data, Draft* out_draft);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Convert string to bytes if needed
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in update_draft", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, None
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Verify email exists, is a draft, and is not trashed
        cursor.execute("""
            SELECT EmailID FROM Emails
            WHERE EmailID = ? AND folder = 'drafts' AND is_trashed = 0
        """, (email_id,))

        if cursor.fetchone() is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        # Build dynamic UPDATE for subject/body
        set_parts = ["SentTimestamp = datetime('now')"]  # Always update last_modified
        params = []

        if 'subject' in draft_data:
            set_parts.append("Subject = ?")
            params.append(draft_data['subject'])

        if 'body' in draft_data:
            set_parts.append("Body = ?")
            params.append(draft_data['body'])

        params.append(email_id)

        # Update email content
        query = f"UPDATE Emails SET {', '.join(set_parts)} WHERE EmailID = ?"
        cursor.execute(query, params)

        # Update TO recipients if key is present
        if 'recipient_ids' in draft_data:
            # Delete existing TO recipients
            cursor.execute("""
                DELETE FROM Junction_Email_Users
                WHERE EmailID = ? AND user_type = 'TO'
            """, (email_id,))

            # Insert new TO recipients
            for recipient_id in draft_data['recipient_ids']:
                cursor.execute("""
                    INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                    VALUES (?, ?, 'TO')
                """, (email_id, recipient_id))

        # Update CC recipients if key is present
        if 'cc_ids' in draft_data:
            # Delete existing CC recipients
            cursor.execute("""
                DELETE FROM Junction_Email_Users
                WHERE EmailID = ? AND user_type = 'CC'
            """, (email_id,))

            # Insert new CC recipients
            for cc_id in draft_data['cc_ids']:
                cursor.execute("""
                    INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                    VALUES (?, ?, 'CC')
                """, (email_id, cc_id))

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT, f"Updated draft: {email_id.hex()}")

        # Return the updated draft
        return retrieve_email(handle, email_id)

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to update draft", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# RETRIEVE EMAIL
# ============================================================================

def retrieve_email(handle: DatabaseHandle, email_id: bytes) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Retrieve an email by its ID.

    Args:
        handle: Database handle
        email_id: Email GUID as bytes

    Returns:
        Tuple of (error_code, email_dict or None)

    C signature: DatabaseErrorCode retrieve_email(DatabaseHandle* handle, const uint8_t* email_id, Email* out_email);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Convert string to bytes if needed (with safe conversion)
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in retrieve", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, None
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Get email
        cursor.execute("""
            SELECT EmailID, Subject, Body, ReceivedTimestamp, SentTimestamp,
                   Meta, Style, is_read, is_starred, is_trashed, folder
            FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        email = {
            'email_id': row['EmailID'].hex() if row['EmailID'] else None,
            'subject': row['Subject'],
            'body': row['Body'],
            'received_timestamp': row['ReceivedTimestamp'],
            'sent_timestamp': row['SentTimestamp'],
            'meta': row['Meta'],
            'style': row['Style'],
            'is_read': bool(row['is_read']),
            'is_starred': bool(row['is_starred']),
            'is_trashed': bool(row['is_trashed']),
            'folder': row['folder'],
            'recipients': [],
            'cc': [],
            'sender': None,
            'attachments': []
        }

        # Get sender
        cursor.execute("""
            SELECT u.UserID, u.FirstName, u.LastName, u.auto_address
            FROM Junction_Email_Users j
            JOIN Users u ON j.UserID = u.UserID
            WHERE j.EmailID = ? AND j.user_type = 'FROM'
        """, (email_id,))
        sender_row = cursor.fetchone()
        if sender_row:
            email['sender'] = {
                'user_id': sender_row['UserID'],
                'first_name': sender_row['FirstName'],
                'last_name': sender_row['LastName'],
                'auto_address': sender_row['auto_address']
            }

        # Get recipients
        cursor.execute("""
            SELECT u.UserID, u.FirstName, u.LastName, u.auto_address, j.user_type
            FROM Junction_Email_Users j
            JOIN Users u ON j.UserID = u.UserID
            WHERE j.EmailID = ? AND j.user_type IN ('TO', 'CC')
        """, (email_id,))
        for r in cursor.fetchall():
            recipient_info = {
                'user_id': r['UserID'],
                'first_name': r['FirstName'],
                'last_name': r['LastName'],
                'auto_address': r['auto_address']
            }
            if r['user_type'] == 'TO':
                email['recipients'].append(recipient_info)
            else:
                email['cc'].append(recipient_info)

        # Get attachments
        cursor.execute("""
            SELECT Attachment_id, name, file_extension, storage_mode, status, size_bytes
            FROM Attachments WHERE EmailID = ?
        """, (email_id,))
        for a in cursor.fetchall():
            email['attachments'].append({
                'attachment_id': a['Attachment_id'],
                'name': a['name'],
                'file_extension': a['file_extension'],
                'storage_mode': a['storage_mode'],
                'status': a['status'],
                'size_bytes': a['size_bytes']
            })

        return DatabaseErrorCode.SUCCESS, email

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to retrieve email", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# GET EMAIL METADATA (without body for efficiency)
# ============================================================================

def get_email_metadata(
    handle: DatabaseHandle,
    email_id: bytes
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Retrieve email metadata without body for efficiency.

    Args:
        handle: Database handle
        email_id: Email GUID as bytes or hex string

    Returns:
        Tuple of (error_code, email_metadata_dict or None)

    C signature: DatabaseErrorCode get_email_metadata(DatabaseHandle* handle,
                                                       const uint8_t* email_id,
                                                       EmailMetadata* out_metadata);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Convert string to bytes if needed (with safe conversion)
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in get_metadata", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, None
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Get email metadata (excluding Body for efficiency)
        cursor.execute("""
            SELECT EmailID, Subject, ReceivedTimestamp, SentTimestamp,
                   is_read, is_starred, is_trashed, folder
            FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        metadata = {
            'email_id': row['EmailID'].hex() if row['EmailID'] else None,
            'subject': row['Subject'],
            'received_timestamp': row['ReceivedTimestamp'],
            'sent_timestamp': row['SentTimestamp'],
            'is_read': bool(row['is_read']),
            'is_starred': bool(row['is_starred']),
            'is_trashed': bool(row['is_trashed']),
            'folder': row['folder'],
            'sender': None,
            'recipients': [],
            'cc': [],
            'attachments': []
        }

        # Get sender
        cursor.execute("""
            SELECT u.UserID, u.FirstName, u.LastName, u.auto_address
            FROM Junction_Email_Users j
            JOIN Users u ON j.UserID = u.UserID
            WHERE j.EmailID = ? AND j.user_type = 'FROM'
        """, (email_id,))
        sender_row = cursor.fetchone()
        if sender_row:
            metadata['sender'] = {
                'user_id': sender_row['UserID'],
                'first_name': sender_row['FirstName'],
                'last_name': sender_row['LastName'],
                'auto_address': sender_row['auto_address']
            }

        # Get recipients
        cursor.execute("""
            SELECT u.UserID, u.FirstName, u.LastName, u.auto_address, j.user_type
            FROM Junction_Email_Users j
            JOIN Users u ON j.UserID = u.UserID
            WHERE j.EmailID = ? AND j.user_type IN ('TO', 'CC')
        """, (email_id,))
        for r in cursor.fetchall():
            recipient_info = {
                'user_id': r['UserID'],
                'first_name': r['FirstName'],
                'last_name': r['LastName'],
                'auto_address': r['auto_address']
            }
            if r['user_type'] == 'TO':
                metadata['recipients'].append(recipient_info)
            else:
                metadata['cc'].append(recipient_info)

        # Get attachments (metadata only, no data_blob)
        cursor.execute("""
            SELECT Attachment_id, name, file_extension, storage_mode, status, size_bytes
            FROM Attachments WHERE EmailID = ?
        """, (email_id,))
        for a in cursor.fetchall():
            metadata['attachments'].append({
                'attachment_id': a['Attachment_id'],
                'name': a['name'],
                'file_extension': a['file_extension'],
                'storage_mode': a['storage_mode'],
                'status': a['status'],
                'size_bytes': a['size_bytes']
            })

        return DatabaseErrorCode.SUCCESS, metadata

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get email metadata", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# ATTACHMENT RETRIEVAL FUNCTIONS
# ============================================================================

def _get_attachments_base_dir() -> str:
    """
    Get the base directory for external attachments.

    Dynamically computed relative to the application location.
    Structure: {app_dir}/Data/Attachments/XX/ where XX is first byte of GUID (00-FF)

    Returns:
        Absolute path to attachments base directory
    """
    # Get directory containing this module (src/), then go up to project root
    src_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(src_dir)
    return os.path.join(project_root, 'Data', 'Attachments')


def _validate_attachment_filename(filename: str) -> Tuple[bool, str]:
    """
    Validate and sanitize attachment filename for subfolder computation.

    Args:
        filename: The attachment filename

    Returns:
        Tuple of (is_valid, sanitized_subfolder)
        - If valid GUID-style name: (True, first 2 chars uppercase)
        - If invalid/empty: (True, '00') as fallback
    """
    if not filename or len(filename) < 2:
        return True, '00'

    # Skip leading dots (hidden files)
    clean_name = filename.lstrip('.')
    if len(clean_name) < 2:
        return True, '00'

    # Get first two chars and validate they're hex
    prefix = clean_name[:2].upper()
    try:
        # Verify it's valid hex
        int(prefix, 16)
        return True, prefix
    except ValueError:
        # Not valid hex, use fallback
        return True, '00'


def get_attachments_for_email(
    handle: DatabaseHandle,
    email_id: bytes
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get all attachments for an email (metadata only, no data_blob).

    Args:
        handle: Database handle
        email_id: Email GUID as bytes or hex string

    Returns:
        Tuple of (error_code, list of attachment dicts)
        Returns empty list if email exists but has no attachments.
        Returns ERR_NOT_FOUND if email doesn't exist.

    C signature: DatabaseErrorCode get_attachments_for_email(DatabaseHandle* handle,
                                                              const uint8_t* email_id,
                                                              AttachmentList* out_list);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    # Convert string to bytes if needed
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, []
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # First verify email exists
        cursor.execute("SELECT 1 FROM Emails WHERE EmailID = ?", (email_id,))
        if cursor.fetchone() is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, []

        # Get attachments (metadata only, no data_blob)
        cursor.execute("""
            SELECT Attachment_id, name, file_extension, storage_mode, status, size_bytes
            FROM Attachments
            WHERE EmailID = ?
            ORDER BY Attachment_id
        """, (email_id,))

        attachments = []
        for row in cursor.fetchall():
            attachments.append({
                'attachment_id': row['Attachment_id'],
                'name': row['name'],
                'file_extension': row['file_extension'],
                'storage_mode': row['storage_mode'],
                'status': row['status'],
                'size_bytes': row['size_bytes']
            })

        return DatabaseErrorCode.SUCCESS, attachments

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get attachments", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_attachment_data(
    handle: DatabaseHandle,
    attachment_id: int
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get a single attachment with its data.

    For INTERNAL storage: returns data_blob directly.
    For EXTERNAL storage: reads file from Data/Attachments/XX/ directory.

    Args:
        handle: Database handle
        attachment_id: Attachment ID (integer primary key)

    Returns:
        Tuple of (error_code, attachment_dict or None)
        attachment_dict contains:
        - attachment_id: int
        - email_id: str (hex)
        - name: str
        - file_extension: str
        - storage_mode: str
        - status: str
        - size_bytes: int
        - data: bytes (actual file content)

    C signature: DatabaseErrorCode get_attachment_data(DatabaseHandle* handle,
                                                        int attachment_id,
                                                        AttachmentData* out_data);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if attachment_id is None or not isinstance(attachment_id, int) or attachment_id < 1:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        # Get attachment record
        cursor.execute("""
            SELECT Attachment_id, EmailID, name, file_extension,
                   storage_mode, status, data_blob, file_path, size_bytes
            FROM Attachments
            WHERE Attachment_id = ?
        """, (attachment_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        # Build base attachment dict
        attachment = {
            'attachment_id': row['Attachment_id'],
            'email_id': row['EmailID'].hex() if row['EmailID'] else None,
            'name': row['name'],
            'file_extension': row['file_extension'],
            'storage_mode': row['storage_mode'],
            'status': row['status'],
            'size_bytes': row['size_bytes'],
            'data': None
        }

        storage_mode = row['storage_mode']

        if storage_mode == 'INTERNAL':
            # Data is in the database
            attachment['data'] = row['data_blob']
        elif storage_mode == 'EXTERNAL':
            # Data is on filesystem - file_path stores only the filename
            # Full path is constructed at runtime: Data/Attachments/XX/filename
            filename = row['file_path']
            if not filename:
                log_error(handle.logger, DB_CONTEXT,
                          f"External attachment {attachment_id} has no file_path")
                return DatabaseErrorCode.ERR_IO, None

            try:
                # Get base directory (dynamically computed, portable)
                base_dir = os.path.realpath(_get_attachments_base_dir())

                # Validate filename and get subfolder
                _, subfolder = _validate_attachment_filename(filename)

                # Construct full path at runtime
                # file_path in DB is just the filename (e.g., "AABBCCDD...docx")
                full_path = os.path.join(base_dir, subfolder, os.path.basename(filename))
                full_path = os.path.realpath(full_path)

                # Security: Verify constructed path is within base directory
                if not full_path.startswith(base_dir + os.sep):
                    log_error(handle.logger, DB_CONTEXT,
                              f"Attachment path outside allowed directory: {filename}")
                    return DatabaseErrorCode.ERR_INVALID_PARAM, None

                # Read the file
                if not os.path.exists(full_path):
                    log_error(handle.logger, DB_CONTEXT,
                              f"External attachment file not found: {full_path}")
                    return DatabaseErrorCode.ERR_IO, None

                with open(full_path, 'rb') as f:
                    attachment['data'] = f.read()

            except IOError as e:
                log_error(handle.logger, DB_CONTEXT,
                          f"Failed to read external attachment: {e}")
                return DatabaseErrorCode.ERR_IO, None
        else:
            log_error(handle.logger, DB_CONTEXT,
                      f"Unknown storage mode: {storage_mode}")
            return DatabaseErrorCode.ERR_INVALID_PARAM, None

        return DatabaseErrorCode.SUCCESS, attachment

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get attachment data", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def get_attachment_path(attachment_name: str) -> str:
    """
    Get the full path for an external attachment.

    Uses hierarchical folder structure: Data/Attachments/XX/filename
    where XX is the first byte (2 hex chars) of the attachment name.
    Path is computed dynamically relative to the application location.

    Args:
        attachment_name: Attachment filename (typically GUID + extension)

    Returns:
        Full path to the attachment file

    C signature: void get_attachment_path(const char* name, char* out_path, size_t max_len);
    """
    base_dir = _get_attachments_base_dir()
    _, subfolder = _validate_attachment_filename(attachment_name)
    # Use basename to ensure only the filename is used (security)
    safe_name = os.path.basename(attachment_name) if attachment_name else attachment_name
    return os.path.join(base_dir, subfolder, safe_name)


def ensure_attachment_directory(attachment_name: str) -> bool:
    """
    Ensure the attachment subdirectory exists, creating it if needed.

    Args:
        attachment_name: Attachment filename (typically GUID + extension)

    Returns:
        True if directory exists or was created, False on error

    C signature: bool ensure_attachment_directory(const char* name);
    """
    base_dir = _get_attachments_base_dir()
    _, subfolder = _validate_attachment_filename(attachment_name)
    dir_path = os.path.join(base_dir, subfolder)

    try:
        os.makedirs(dir_path, exist_ok=True)
        return True
    except OSError:
        return False


# ============================================================================
# STORE CONTACT
# ============================================================================

def store_contact(handle: DatabaseHandle, contact: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[int]]:
    """
    Store or update a contact (user) in the database.

    Args:
        handle: Database handle
        contact: Dictionary with contact data:
            - user_id: int - optional, auto-generated if not provided
            - first_name: str
            - last_name: str
            - middle_name: str - optional
            - auto_address: str - optional
            - description: str - optional
            - avatar: bytes - optional
            - sending_fee: str - optional

    Returns:
        Tuple of (error_code, user_id)

    C signature: DatabaseErrorCode store_contact(DatabaseHandle* handle, const Contact* contact, int64_t* out_user_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        user_id = contact.get('user_id')

        if user_id is not None:
            # Update existing contact
            cursor.execute("""
                INSERT OR REPLACE INTO Users
                (UserID, FirstName, MiddleName, LastName, auto_address, Description, Avatar, sending_fee, BeaconID)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                contact.get('first_name', ''),
                contact.get('middle_name'),
                contact.get('last_name', ''),
                contact.get('auto_address'),
                contact.get('description'),
                contact.get('avatar'),
                contact.get('sending_fee'),
                contact.get('beacon_id')
            ))
        else:
            # Insert new contact
            cursor.execute("""
                INSERT INTO Users (FirstName, MiddleName, LastName, auto_address, Description, Avatar, sending_fee, BeaconID)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                contact.get('first_name', ''),
                contact.get('middle_name'),
                contact.get('last_name', ''),
                contact.get('auto_address'),
                contact.get('description'),
                contact.get('avatar'),
                contact.get('sending_fee'),
                contact.get('beacon_id')
            ))
            user_id = cursor.lastrowid

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT, f"Stored contact: {user_id}")

        return DatabaseErrorCode.SUCCESS, user_id

    except sqlite3.IntegrityError as e:
        log_error(handle.logger, DB_CONTEXT, "Constraint violation storing contact", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_CONSTRAINT, None
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store contact", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# GET POPULAR CONTACTS
# ============================================================================

def get_popular_contacts(
    handle: DatabaseHandle,
    limit: int = 10,
    first_name_like: str = None,
    last_name_like: str = None,
    auto_address_like: str = None
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get most popular contacts based on contact frequency and recency.

    Popularity is calculated using a decaying algorithm:
    popularity = contact_count * decay_factor
    where decay_factor decreases based on days since last contact.

    Args:
        handle: Database handle
        limit: Maximum number of contacts to return
        first_name_like: Filter by first name (partial match)
        last_name_like: Filter by last name (partial match)
        auto_address_like: Filter by auto address (partial match)

    Returns:
        Tuple of (error_code, list of contact dicts)

    C signature: DatabaseErrorCode get_popular_contacts(DatabaseHandle* handle, int limit,
                                                         const char* first_name_like, const char* last_name_like,
                                                         const char* auto_address_like, Contact** out_contacts, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if limit <= 0:
        limit = 10

    try:
        cursor = handle.connection.cursor()

        # Build query with optional filters
        # Popularity formula: contact_count / (1 + days_since_last_contact * 0.1)
        query = """
            SELECT
                UserID,
                FirstName,
                MiddleName,
                LastName,
                auto_address,
                Description,
                contact_count,
                last_contacted_timestamp,
                CASE
                    WHEN last_contacted_timestamp IS NULL THEN 0
                    ELSE contact_count / (1.0 + (julianday('now') - julianday(last_contacted_timestamp)) * 0.1)
                END AS popularity,
                CASE
                    WHEN last_contacted_timestamp IS NULL THEN 9999
                    ELSE CAST(julianday('now') - julianday(last_contacted_timestamp) AS INTEGER)
                END AS days_since_last_contact
            FROM Users
            WHERE 1=1
        """
        params = []

        if first_name_like:
            query += " AND FirstName LIKE ?"
            params.append(f"%{first_name_like}%")

        if last_name_like:
            query += " AND LastName LIKE ?"
            params.append(f"%{last_name_like}%")

        if auto_address_like:
            query += " AND auto_address LIKE ?"
            params.append(f"%{auto_address_like}%")

        query += " ORDER BY popularity DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        contacts = []
        for row in cursor.fetchall():
            contacts.append({
                'user_id': row['UserID'],
                'first_name': row['FirstName'],
                'middle_name': row['MiddleName'],
                'last_name': row['LastName'],
                'auto_address': row['auto_address'],
                'description': row['Description'],
                'contact_count': row['contact_count'],
                'popularity': row['popularity'] or 0,
                'days_since_last_contact': row['days_since_last_contact']
            })

        return DatabaseErrorCode.SUCCESS, contacts

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get popular contacts", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


# ============================================================================
# CONTACT MANAGEMENT FUNCTIONS
# ============================================================================

def get_all_contacts(
    handle: DatabaseHandle,
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]], int]:
    """
    Get paginated list of all contacts with optional search.
    Excludes Avatar field for lightweight response.

    Args:
        handle: Database handle
        page: Page number (1-indexed, default 1)
        limit: Results per page (default 50, max 200)
        search: Optional search term for name/email (case-insensitive)

    Returns:
        Tuple of (error_code, contacts_list, total_count)

    C signature: DatabaseErrorCode get_all_contacts(DatabaseHandle* handle, int page, int limit,
                                                     const char* search, Contact** out_contacts,
                                                     int* out_count, int* out_total);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, [], 0

    # Clamp pagination values
    if page < 1:
        page = 1
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200

    offset = (page - 1) * limit

    try:
        cursor = handle.connection.cursor()

        # Build WHERE clause for search
        where_clause = ""
        params = []
        if search and search.strip():
            search_pattern = f"%{search.strip()}%"
            where_clause = """
                WHERE LOWER(FirstName) LIKE LOWER(?)
                   OR LOWER(LastName) LIKE LOWER(?)
                   OR LOWER(auto_address) LIKE LOWER(?)
            """
            params = [search_pattern, search_pattern, search_pattern]

        # Count query (respects search filter)
        count_query = f"SELECT COUNT(*) FROM Users {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Data query (Avatar EXCLUDED for lightweight response)
        data_query = f"""
            SELECT UserID, FirstName, MiddleName, LastName, auto_address,
                   Description, date_created, last_contacted_timestamp,
                   contact_count, emails_sent_total
            FROM Users
            {where_clause}
            ORDER BY FirstName, LastName
            LIMIT ? OFFSET ?
        """
        cursor.execute(data_query, params + [limit, offset])

        contacts = []
        for row in cursor.fetchall():
            contacts.append({
                'user_id': row['UserID'],
                'first_name': row['FirstName'],
                'middle_name': row['MiddleName'],
                'last_name': row['LastName'],
                'auto_address': row['auto_address'],
                'description': row['Description'],
                'date_created': row['date_created'],
                'last_contacted': row['last_contacted_timestamp'],
                'contact_count': row['contact_count'],
                'emails_sent_total': row['emails_sent_total']
            })

        log_debug(handle.logger, DB_CONTEXT, f"get_all_contacts: found {len(contacts)} of {total_count} total")
        return DatabaseErrorCode.SUCCESS, contacts, total_count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get all contacts", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, [], 0


def get_contact_by_id(
    handle: DatabaseHandle,
    user_id: int
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get a single contact by ID. Excludes Avatar for consistency.

    Args:
        handle: Database handle
        user_id: User ID (integer primary key)

    Returns:
        Tuple of (error_code, contact_dict or None)

    C signature: DatabaseErrorCode get_contact_by_id(DatabaseHandle* handle, int user_id,
                                                      Contact* out_contact);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if user_id is None or not isinstance(user_id, int) or user_id < 1:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT UserID, FirstName, MiddleName, LastName, auto_address,
                   Description, BeaconID, sending_fee, date_created,
                   last_contacted_timestamp, contact_count, emails_sent_total
            FROM Users
            WHERE UserID = ?
        """, (user_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        contact = {
            'user_id': row['UserID'],
            'first_name': row['FirstName'],
            'middle_name': row['MiddleName'],
            'last_name': row['LastName'],
            'auto_address': row['auto_address'],
            'description': row['Description'],
            'beacon_id': row['BeaconID'],
            'sending_fee': row['sending_fee'],
            'date_created': row['date_created'],
            'last_contacted': row['last_contacted_timestamp'],
            'contact_count': row['contact_count'],
            'emails_sent_total': row['emails_sent_total']
        }

        return DatabaseErrorCode.SUCCESS, contact

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to get contact {user_id}", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def delete_contact(
    handle: DatabaseHandle,
    user_id: int
) -> DatabaseErrorCode:
    """
    Hard delete a contact by ID.

    Args:
        handle: Database handle
        user_id: User ID to delete

    Returns:
        SUCCESS if deleted, ERR_NOT_FOUND if contact doesn't exist

    C signature: DatabaseErrorCode delete_contact(DatabaseHandle* handle, int user_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if user_id is None or not isinstance(user_id, int) or user_id < 1:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        cursor.execute("DELETE FROM Users WHERE UserID = ?", (user_id,))
        handle.connection.commit()

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        log_debug(handle.logger, DB_CONTEXT, f"Deleted contact: {user_id}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to delete contact {user_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def check_email_exists(
    handle: DatabaseHandle,
    auto_address: str,
    exclude_user_id: Optional[int] = None
) -> Tuple[DatabaseErrorCode, bool]:
    """
    Check if an email address already exists (case-insensitive).

    Args:
        handle: Database handle
        auto_address: Email to check
        exclude_user_id: Optional user ID to exclude (for updates)

    Returns:
        Tuple of (error_code, exists_bool)

    C signature: DatabaseErrorCode check_email_exists(DatabaseHandle* handle, const char* email,
                                                       int exclude_user_id, bool* out_exists);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, False

    if not auto_address or not auto_address.strip():
        return DatabaseErrorCode.ERR_INVALID_PARAM, False

    try:
        cursor = handle.connection.cursor()

        # Normalize to lowercase for comparison
        normalized_email = auto_address.strip().lower()

        if exclude_user_id is not None:
            cursor.execute("""
                SELECT 1 FROM Users
                WHERE LOWER(auto_address) = ?
                AND UserID != ?
                LIMIT 1
            """, (normalized_email, exclude_user_id))
        else:
            cursor.execute("""
                SELECT 1 FROM Users
                WHERE LOWER(auto_address) = ?
                LIMIT 1
            """, (normalized_email,))

        exists = cursor.fetchone() is not None
        return DatabaseErrorCode.SUCCESS, exists

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to check email exists: {auto_address}", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, False


# ============================================================================
# UPDATE EMAIL FLAGS
# ============================================================================

def update_email_flags(handle: DatabaseHandle, email_id: bytes, flags: Dict[str, Any]) -> bool:
    """
    Update email flags (read, starred, trashed, folder).

    Args:
        handle: Database handle
        email_id: Email GUID as bytes
        flags: Dictionary of flags to update:
            - is_read: bool
            - is_starred: bool
            - is_trashed: bool
            - folder: str

    Returns:
        True if update successful, False otherwise

    C signature: bool update_email_flags(DatabaseHandle* handle, const uint8_t* email_id, const EmailFlags* flags);
    """
    if handle is None or handle.connection is None:
        return False

    if email_id is None:
        return False

    # Convert string to bytes if needed (with safe conversion)
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in update_flags", err_msg)
            return False
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Build SET clause dynamically based on provided flags
        set_parts = []
        params = []

        if 'is_read' in flags:
            set_parts.append("is_read = ?")
            params.append(1 if flags['is_read'] else 0)

        if 'is_starred' in flags:
            set_parts.append("is_starred = ?")
            params.append(1 if flags['is_starred'] else 0)

        if 'is_trashed' in flags:
            set_parts.append("is_trashed = ?")
            params.append(1 if flags['is_trashed'] else 0)

        if 'folder' in flags:
            set_parts.append("folder = ?")
            params.append(flags['folder'])

        if not set_parts:
            return True  # Nothing to update

        params.append(email_id)

        # SAFETY NOTE: This f-string is SAFE because set_parts only contains
        # hardcoded column names from the if-blocks above (lines 780-794).
        # No user input is interpolated into the SQL - user values go into params.
        query = f"UPDATE Emails SET {', '.join(set_parts)} WHERE EmailID = ?"
        cursor.execute(query, params)

        handle.connection.commit()

        updated = cursor.rowcount > 0
        if updated:
            log_debug(handle.logger, DB_CONTEXT, f"Updated flags for email: {email_id.hex()}")

        return updated

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to update email flags", str(e))
        handle.connection.rollback()
        return False


def delete_email(
    handle: DatabaseHandle,
    email_id: bytes
) -> Tuple[DatabaseErrorCode, bool]:
    """
    Soft delete an email by setting is_trashed=1.

    This moves the email to trash rather than permanently deleting it.
    If already trashed, returns success with was_modified=False.

    Args:
        handle: Database handle
        email_id: Email GUID as bytes or hex string

    Returns:
        Tuple of (error_code, was_modified)
        - SUCCESS, True: Email was moved to trash
        - SUCCESS, False: Email was already in trash
        - ERR_NOT_FOUND, False: Email does not exist

    C signature: DatabaseErrorCode delete_email(DatabaseHandle* handle,
                                                 const uint8_t* email_id,
                                                 bool* out_was_modified);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, False

    if email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, False

    # Convert string to bytes if needed (with safe conversion)
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in delete_email", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, False
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        # Check if email exists and get current trashed status
        cursor.execute("""
            SELECT is_trashed FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, False

        # If already trashed, return success but not modified
        if row['is_trashed']:
            return DatabaseErrorCode.SUCCESS, False

        # Set is_trashed = 1 (soft delete)
        cursor.execute("""
            UPDATE Emails SET is_trashed = 1 WHERE EmailID = ?
        """, (email_id,))

        handle.connection.commit()

        log_debug(handle.logger, DB_CONTEXT, f"Soft deleted email: {email_id.hex()}")
        return DatabaseErrorCode.SUCCESS, True

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to delete email", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, False


# ============================================================================
# EXECUTE QUERY (Generic query execution)
# ============================================================================

def execute_query(
    handle: DatabaseHandle,
    sql: str,
    params: Tuple = ()
) -> Tuple[DatabaseErrorCode, Optional[List[Dict[str, Any]]]]:
    """
    Execute a SQL query with parameters and return results.

    Args:
        handle: Database handle
        sql: SQL query string with ? placeholders
        params: Tuple of parameter values

    Returns:
        Tuple of (error_code, list of row dicts for SELECT, or empty list for other queries)

    C signature: DatabaseErrorCode execute_query(DatabaseHandle* handle, const char* sql,
                                                  const char** params, int param_count,
                                                  ResultSet* out_results);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if not sql:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()
        cursor.execute(sql, params)

        # Check if this is a SELECT query
        if sql.strip().upper().startswith("SELECT"):
            rows = cursor.fetchall()
            results = []
            for row in rows:
                # Convert Row object to dict
                results.append({key: row[key] for key in row.keys()})
            return DatabaseErrorCode.SUCCESS, results
        else:
            handle.connection.commit()
            return DatabaseErrorCode.SUCCESS, []

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Query execution failed", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# ADDITIONAL HELPER FUNCTIONS
# ============================================================================

def store_server(handle: DatabaseHandle, server: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[int]]:
    """
    Store or update a QMail server record.

    Args:
        handle: Database handle
        server: Dictionary with server data

    Returns:
        Tuple of (error_code, server_id)

    C signature: DatabaseErrorCode store_server(DatabaseHandle* handle, const ServerInfo* server, int64_t* out_server_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        server_id = server.get('server_id')

        cursor.execute("""
            INSERT OR REPLACE INTO QMailServers
            (QMailServerID, IPAddress, PortNumb, server_type, ping_ms)
            VALUES (?, ?, ?, ?, ?)
        """, (
            server_id,
            server.get('ip_address', ''),
            server.get('port'),
            server.get('server_type'),
            server.get('ping_ms')
        ))

        if server_id is None:
            server_id = cursor.lastrowid

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS, server_id

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store server", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def store_attachment(
    handle: DatabaseHandle,
    email_id: bytes,
    attachment: Dict[str, Any]
) -> Tuple[DatabaseErrorCode, Optional[int]]:
    """
    Store an attachment for an email.

    Args:
        handle: Database handle
        email_id: Parent email GUID
        attachment: Dictionary with attachment data:
            - name: str - Display filename
            - file_extension: str - e.g., 'pdf', 'docx'
            - storage_mode: str - 'INTERNAL' or 'EXTERNAL' (default: 'INTERNAL')
            - status: str - Optional status flag
            - data_blob: bytes - File data (for INTERNAL mode)
            - file_path: str - Filename only, NOT full path (for EXTERNAL mode)
                         The full path is constructed at runtime using:
                         Data/Attachments/XX/filename where XX is derived from filename.
                         This ensures portability across installations.
            - size_bytes: int - File size in bytes

    Returns:
        Tuple of (error_code, attachment_id)

    C signature: DatabaseErrorCode store_attachment(DatabaseHandle* handle, const uint8_t* email_id,
                                                     const Attachment* attachment, int64_t* out_attachment_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Convert string to bytes if needed (with safe conversion)
    if isinstance(email_id, str):
        success, email_id_bytes, err_msg = _safe_hex_to_bytes(email_id, handle.logger)
        if not success:
            log_error(handle.logger, DB_CONTEXT, "Invalid email_id format in store_attachment", err_msg)
            return DatabaseErrorCode.ERR_INVALID_PARAM, None
        email_id = email_id_bytes

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            INSERT INTO Attachments
            (EmailID, name, file_extension, storage_mode, status, data_blob, file_path, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email_id,
            attachment.get('name'),
            attachment.get('file_extension'),
            attachment.get('storage_mode', 'INTERNAL'),
            attachment.get('status'),
            attachment.get('data_blob'),
            attachment.get('file_path'),
            attachment.get('size_bytes')
        ))

        attachment_id = cursor.lastrowid
        handle.connection.commit()

        return DatabaseErrorCode.SUCCESS, attachment_id

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store attachment", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def update_contact_stats(handle: DatabaseHandle, user_id: int) -> bool:
    """
    Update contact statistics after sending/receiving an email.
    Increments contact_count and updates last_contacted_timestamp.

    Args:
        handle: Database handle
        user_id: User/contact ID

    Returns:
        True if update successful

    C signature: bool update_contact_stats(DatabaseHandle* handle, int64_t user_id);
    """
    if handle is None or handle.connection is None:
        return False

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            UPDATE Users
            SET contact_count = contact_count + 1,
                last_contacted_timestamp = datetime('now')
            WHERE UserID = ?
        """, (user_id,))

        handle.connection.commit()
        return cursor.rowcount > 0

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to update contact stats", str(e))
        handle.connection.rollback()
        return False


def get_database_stats(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, Dict[str, int]]:
    """
    Get database statistics (row counts for each table).

    Args:
        handle: Database handle

    Returns:
        Tuple of (error_code, dict of table->count)

    C signature: DatabaseErrorCode get_database_stats(DatabaseHandle* handle, DatabaseStats* out_stats);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, {}

    try:
        cursor = handle.connection.cursor()
        stats = {}

        # SAFETY NOTE: This list is hardcoded - no user input can affect table names.
        # The f-string below is SAFE because 'table' comes only from this constant list.
        tables = ['Emails', 'Users', 'Attachments', 'QMailServers', 'Session', 'Locker_Keys']

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]

        return DatabaseErrorCode.SUCCESS, stats

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get database stats", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, {}


# ============================================================================
# LIST AND SEARCH FUNCTIONS (Added for API integration)
# ============================================================================

def list_emails(
    handle: DatabaseHandle,
    folder: str = 'inbox',
    limit: int = 50,
    offset: int = 0,
    include_trashed: bool = False
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    List emails with pagination and folder filtering.

    Returns list of email summaries (not full body for performance).

    Args:
        handle: Database handle
        folder: Folder to list from (inbox, sent, drafts, trash)
        limit: Maximum number of results
        offset: Pagination offset
        include_trashed: Whether to include trashed emails

    Returns:
        Tuple of (error_code, list of email dicts)

    C signature: DatabaseErrorCode list_emails(DatabaseHandle* handle, const char* folder,
                                                int limit, int offset, bool include_trashed,
                                                EmailSummary** out_emails, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        query = """
            SELECT EmailID, Subject, ReceivedTimestamp, SentTimestamp,
                   is_read, is_starred, is_trashed, folder
            FROM Emails
            WHERE folder = ? AND (is_trashed = 0 OR is_trashed = ?)
            ORDER BY ReceivedTimestamp DESC
            LIMIT ? OFFSET ?
        """

        cursor.execute(query, (folder, int(include_trashed), limit, offset))
        rows = cursor.fetchall()

        # Convert to list of dicts
        columns = ['EmailID', 'Subject', 'ReceivedTimestamp', 'SentTimestamp',
                   'is_read', 'is_starred', 'is_trashed', 'folder']
        emails = []
        for row in rows:
            email = dict(zip(columns, row))
            # Convert boolean flags
            email['is_read'] = bool(email['is_read'])
            email['is_starred'] = bool(email['is_starred'])
            email['is_trashed'] = bool(email['is_trashed'])
            emails.append(email)

        log_debug(handle.logger, DB_CONTEXT, f"Listed {len(emails)} emails from folder '{folder}'")
        return DatabaseErrorCode.SUCCESS, emails

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to list emails", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def list_drafts(
    handle: DatabaseHandle,
    page: int = 1,
    limit: int = 50
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]], int]:
    """
    List drafts with pagination and recipient preview.

    Returns draft summaries ordered by last modified (SentTimestamp) descending.
    Includes recipient count and first recipient name for UI preview.

    Args:
        handle: Database handle
        page: Page number (1-based, default 1)
        limit: Maximum number of results per page (default 50, max 200)

    Returns:
        Tuple of (error_code, drafts_list, total_count)

    C signature: DatabaseErrorCode list_drafts(DatabaseHandle* handle, int page, int limit,
                                                DraftSummary** out_drafts, int* out_count, int* out_total);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, [], 0

    # Clamp pagination values
    if page < 1:
        page = 1
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200

    offset = (page - 1) * limit

    try:
        cursor = handle.connection.cursor()

        # Get total count first
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM Emails
            WHERE folder = 'drafts' AND is_trashed = 0
        """)
        total_count = cursor.fetchone()['total']

        # Get drafts with recipient preview
        cursor.execute("""
            SELECT
                e.EmailID, e.Subject, e.ReceivedTimestamp, e.SentTimestamp,
                e.Body, e.is_starred, e.is_read,
                (SELECT COUNT(*) FROM Junction_Email_Users j
                 WHERE j.EmailID = e.EmailID AND j.user_type = 'TO') as recipient_count,
                (SELECT u.FirstName || ' ' || COALESCE(u.LastName, '')
                 FROM Junction_Email_Users j
                 JOIN Users u ON j.UserID = u.UserID
                 WHERE j.EmailID = e.EmailID AND j.user_type = 'TO'
                 LIMIT 1) as first_recipient
            FROM Emails e
            WHERE e.folder = 'drafts' AND e.is_trashed = 0
            ORDER BY e.SentTimestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        drafts = []
        for row in cursor.fetchall():
            draft = {
                'email_id': row['EmailID'].hex() if row['EmailID'] else None,
                'subject': row['Subject'],
                'date_created': row['ReceivedTimestamp'],
                'last_modified': row['SentTimestamp'],
                'has_body': bool(row['Body']),
                'is_starred': bool(row['is_starred']),
                'is_read': bool(row['is_read']),
                'recipient_count': row['recipient_count'] or 0,
                'first_recipient': row['first_recipient']
            }
            drafts.append(draft)

        log_debug(handle.logger, DB_CONTEXT, f"Listed {len(drafts)} drafts (page {page})")
        return DatabaseErrorCode.SUCCESS, drafts, total_count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to list drafts", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, [], 0


def search_emails(
    handle: DatabaseHandle,
    search_term: str,
    limit: int = 50,
    offset: int = 0
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Full-text search using FTS5 index.

    Uses the Emails_FTS virtual table for fast text search on Subject and Body.

    Args:
        handle: Database handle
        search_term: Search query string
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        Tuple of (error_code, list of search result dicts with snippets)

    C signature: DatabaseErrorCode search_emails(DatabaseHandle* handle, const char* search_term,
                                                  int limit, int offset,
                                                  SearchResult** out_results, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if not search_term or not search_term.strip():
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        # Sanitize search term to prevent FTS injection
        # Double quotes are the escape character in FTS5
        safe_term = search_term.replace('"', '""').strip()

        # Use FTS5 MATCH query with snippet for context
        query = """
            SELECT e.EmailID, e.Subject, e.ReceivedTimestamp, e.is_read, e.folder,
                   snippet(Emails_FTS, 1, '<mark>', '</mark>', '...', 32) as snippet
            FROM Emails_FTS
            JOIN Emails e ON Emails_FTS.rowid = e.rowid
            WHERE Emails_FTS MATCH ?
            ORDER BY rank
            LIMIT ? OFFSET ?
        """

        # FTS5 phrase query with quotes
        cursor.execute(query, (f'"{safe_term}"', limit, offset))
        rows = cursor.fetchall()

        # Convert to list of dicts
        columns = ['EmailID', 'Subject', 'ReceivedTimestamp', 'is_read', 'folder', 'snippet']
        results = []
        for row in rows:
            result = dict(zip(columns, row))
            result['is_read'] = bool(result['is_read'])
            results.append(result)

        log_debug(handle.logger, DB_CONTEXT, f"Search '{search_term}' found {len(results)} results")
        return DatabaseErrorCode.SUCCESS, results

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Search failed for '{search_term}'", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_email_count(
    handle: DatabaseHandle,
    folder: str = 'inbox',
    include_trashed: bool = False
) -> Tuple[DatabaseErrorCode, int]:
    """
    Get total count of emails in a folder for pagination.

    Args:
        handle: Database handle
        folder: Folder to count (inbox, sent, drafts, trash)
        include_trashed: Whether to include trashed emails in count

    Returns:
        Tuple of (error_code, count)

    C signature: DatabaseErrorCode get_email_count(DatabaseHandle* handle, const char* folder,
                                                    bool include_trashed, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()

        query = """
            SELECT COUNT(*) FROM Emails
            WHERE folder = ? AND (is_trashed = 0 OR is_trashed = ?)
        """

        cursor.execute(query, (folder, int(include_trashed)))
        count = cursor.fetchone()[0]

        return DatabaseErrorCode.SUCCESS, count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get email count", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0


def get_folder_counts(
    handle: DatabaseHandle
) -> Tuple[DatabaseErrorCode, Dict[str, Dict[str, int]]]:
    """
    Get total and unread email counts for all folders.

    Returns counts for inbox, sent, drafts, and trash folders.
    Uses separate queries to correctly count trash (Gemini review fix).

    Args:
        handle: Database handle

    Returns:
        Tuple of (error_code, counts_dict)
        counts_dict format: {'inbox': {'total': 50, 'unread': 5}, ...}

    C signature: DatabaseErrorCode get_folder_counts(DatabaseHandle* handle,
                                                      FolderCounts* out_counts);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, {}

    try:
        cursor = handle.connection.cursor()

        # Initialize counts for all folders
        counts = {
            'inbox': {'total': 0, 'unread': 0},
            'sent': {'total': 0, 'unread': 0},
            'drafts': {'total': 0, 'unread': 0},
            'trash': {'total': 0, 'unread': 0}
        }

        # Query 1: Standard folders (inbox, sent, drafts) - exclude trashed
        cursor.execute("""
            SELECT folder,
                   COUNT(*) as total,
                   SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread
            FROM Emails
            WHERE folder IN ('inbox', 'sent', 'drafts') AND is_trashed = 0
            GROUP BY folder
        """)

        for row in cursor.fetchall():
            folder = row['folder']
            if folder in counts:
                counts[folder]['total'] = row['total']
                counts[folder]['unread'] = row['unread'] or 0

        # Query 2: Trash folder - count all trashed emails regardless of original folder
        cursor.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread
            FROM Emails
            WHERE is_trashed = 1
        """)

        trash_row = cursor.fetchone()
        if trash_row:
            counts['trash']['total'] = trash_row['total'] or 0
            counts['trash']['unread'] = trash_row['unread'] or 0

        return DatabaseErrorCode.SUCCESS, counts

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get folder counts", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, {}


# ============================================================================
# USER AND SERVER SYNC FUNCTIONS (For data_sync.py integration)
# ============================================================================

def upsert_user(handle: DatabaseHandle, user: Dict[str, Any]) -> DatabaseErrorCode:
    """
    Insert or update a user from remote sync data.

    Uses INSERT OR REPLACE for atomic upsert.
    Automatically generates auto_address from user_id.

    Args:
        handle: Database handle
        user: Dictionary with user data from JSON sync:
            - user_id: int (required)
            - first_name: str
            - middle_name: str
            - last_name: str
            - avatar: str (hex string)
            - streak: int
            - sending_fee: str
            - description: str
            - beacon_id: str
            - dreg_score: int
            - emails_sent_total: int
            - date_created: str (ISO datetime)

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode upsert_user(DatabaseHandle* handle, const SyncUser* user);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    user_id = user.get('user_id')
    if user_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        # Generate auto_address from user_id
        auto_address = f"0006.1.{user_id}"

        cursor.execute("""
            INSERT OR REPLACE INTO Users
            (UserID, FirstName, MiddleName, LastName, Avatar, streak, sending_fee,
             Description, BeaconID, dreg_score, emails_sent_total, date_created,
             auto_address, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            user_id,
            user.get('first_name', ''),
            user.get('middle_name', ''),
            user.get('last_name', ''),
            user.get('avatar'),
            user.get('streak', 0),
            user.get('sending_fee'),
            user.get('description'),
            user.get('beacon_id'),
            user.get('dreg_score', 0),
            user.get('emails_sent_total', 0),
            user.get('date_created'),
            auto_address
        ))

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to upsert user {user_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def upsert_server(handle: DatabaseHandle, server: Dict[str, Any]) -> DatabaseErrorCode:
    """
    Insert or update a QMail server from remote sync data.

    Args:
        handle: Database handle
        server: Dictionary with server data from JSON sync:
            - server_id: str (required, e.g., "RAIDA1")
            - server_index: int
            - ip_address: str
            - port: int
            - server_type: str
            - cost_per_mb: float
            - cost_per_week: float
            - percent_uptime: float
            - performance_benchmark_percentile: float
            - date_created: str (ISO datetime)

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode upsert_server(DatabaseHandle* handle, const SyncServer* server);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    server_id = server.get('server_id')
    if server_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO QMailServers
            (QMailServerID, ServerIndex, IPAddress, PortNumb, server_type,
             cost_per_mb, Cost_per_week_storage, percent_uptime,
             performance_benchmark_percentile, date_created, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            server_id,
            server.get('server_index'),
            server.get('ip_address', ''),
            server.get('port'),
            server.get('server_type', 'QMAIL'),
            str(server.get('cost_per_mb', '')) if server.get('cost_per_mb') else None,
            str(server.get('cost_per_week', '')) if server.get('cost_per_week') else None,
            server.get('percent_uptime'),
            server.get('performance_benchmark_percentile'),
            server.get('date_created')
        ))

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to upsert server {server_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def search_users(
    handle: DatabaseHandle,
    query: str,
    limit: int = 20
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Search users by name or description for autocomplete.

    Args:
        handle: Database handle
        query: Search query string
        limit: Maximum number of results (default 20)

    Returns:
        Tuple of (error_code, list of user dicts)

    C signature: DatabaseErrorCode search_users(DatabaseHandle* handle, const char* query,
                                                 int limit, User** out_users, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if not query or not query.strip():
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        # Search in FirstName, LastName, and Description
        search_pattern = f"%{query.strip()}%"

        cursor.execute("""
            SELECT UserID, FirstName, MiddleName, LastName, Avatar,
                   auto_address, Description, BeaconID, dreg_score, emails_sent_total
            FROM Users
            WHERE FirstName LIKE ? OR LastName LIKE ? OR Description LIKE ?
            ORDER BY
                CASE
                    WHEN FirstName LIKE ? THEN 1
                    WHEN LastName LIKE ? THEN 2
                    ELSE 3
                END,
                FirstName, LastName
            LIMIT ?
        """, (search_pattern, search_pattern, search_pattern,
              f"{query.strip()}%", f"{query.strip()}%", limit))

        users = []
        for row in cursor.fetchall():
            users.append({
                'user_id': row['UserID'],
                'first_name': row['FirstName'],
                'middle_name': row['MiddleName'],
                'last_name': row['LastName'],
                'avatar': row['Avatar'],
                'auto_address': row['auto_address'],
                'description': row['Description'],
                'beacon_id': row['BeaconID'],
                'dreg_score': row['dreg_score'],
                'emails_sent_total': row['emails_sent_total']
            })

        log_debug(handle.logger, DB_CONTEXT, f"User search '{query}' found {len(users)} results")
        return DatabaseErrorCode.SUCCESS, users

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"User search failed for '{query}'", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_all_servers(
    handle: DatabaseHandle,
    available_only: bool = True
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get all QMail servers from database.

    Args:
        handle: Database handle
        available_only: If True, only return servers marked as available

    Returns:
        Tuple of (error_code, list of server dicts)

    C signature: DatabaseErrorCode get_all_servers(DatabaseHandle* handle, bool available_only,
                                                    Server** out_servers, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        if available_only:
            cursor.execute("""
                SELECT QMailServerID, ServerIndex, IPAddress, PortNumb, server_type,
                       cost_per_mb, Cost_per_week_storage, ping_ms,
                       percent_uptime, performance_benchmark_percentile,
                       is_available, use_for_parity, last_checked
                FROM QMailServers
                WHERE is_available = 1
                ORDER BY ServerIndex
            """)
        else:
            cursor.execute("""
                SELECT QMailServerID, ServerIndex, IPAddress, PortNumb, server_type,
                       cost_per_mb, Cost_per_week_storage, ping_ms,
                       percent_uptime, performance_benchmark_percentile,
                       is_available, use_for_parity, last_checked
                FROM QMailServers
                ORDER BY ServerIndex
            """)

        servers = []
        for row in cursor.fetchall():
            servers.append({
                'server_id': row['QMailServerID'],
                'server_index': row['ServerIndex'],
                'ip_address': row['IPAddress'],
                'port': row['PortNumb'],
                'server_type': row['server_type'],
                'cost_per_mb': row['cost_per_mb'],
                'cost_per_week': row['Cost_per_week_storage'],
                'ping_ms': row['ping_ms'],
                'percent_uptime': row['percent_uptime'],
                'performance_benchmark_percentile': row['performance_benchmark_percentile'],
                'is_available': bool(row['is_available']),
                'is_parity': bool(row['use_for_parity']),
                'last_checked': row['last_checked']
            })

        return DatabaseErrorCode.SUCCESS, servers

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get servers", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_stripe_servers(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get servers to use for data stripes (excludes parity server).

    Returns:
        Tuple of (error_code, list of server dicts)

    C signature: DatabaseErrorCode get_stripe_servers(DatabaseHandle* handle,
                                                       Server** out_servers, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT QMailServerID, ServerIndex, IPAddress, PortNumb, server_type,
                   ping_ms, is_available
            FROM QMailServers
            WHERE is_available = 1 AND use_for_parity = 0
            ORDER BY ServerIndex
        """)

        servers = []
        for row in cursor.fetchall():
            servers.append({
                'server_id': row['QMailServerID'],
                'server_index': row['ServerIndex'],
                'ip_address': row['IPAddress'],
                'port': row['PortNumb'],
                'server_type': row['server_type'],
                'ping_ms': row['ping_ms'],
                'is_available': bool(row['is_available'])
            })

        return DatabaseErrorCode.SUCCESS, servers

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get stripe servers", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_parity_server(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get the designated parity server.

    Returns:
        Tuple of (error_code, server dict or None)

    C signature: DatabaseErrorCode get_parity_server(DatabaseHandle* handle, Server* out_server);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT QMailServerID, ServerIndex, IPAddress, PortNumb, server_type,
                   ping_ms, is_available
            FROM QMailServers
            WHERE use_for_parity = 1
            LIMIT 1
        """)

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.SUCCESS, None

        server = {
            'server_id': row['QMailServerID'],
            'server_index': row['ServerIndex'],
            'ip_address': row['IPAddress'],
            'port': row['PortNumb'],
            'server_type': row['server_type'],
            'ping_ms': row['ping_ms'],
            'is_available': bool(row['is_available'])
        }

        return DatabaseErrorCode.SUCCESS, server

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get parity server", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def set_parity_server(handle: DatabaseHandle, server_id: str) -> DatabaseErrorCode:
    """
    Designate a server as the parity server.

    Clears parity flag from all other servers first.

    Args:
        handle: Database handle
        server_id: QMailServerID to use for parity (e.g., "RAIDA14")

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode set_parity_server(DatabaseHandle* handle, const char* server_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if not server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        # Clear all parity flags
        cursor.execute("UPDATE QMailServers SET use_for_parity = 0")

        # Set the new parity server
        cursor.execute("""
            UPDATE QMailServers SET use_for_parity = 1 WHERE QMailServerID = ?
        """, (server_id,))

        if cursor.rowcount == 0:
            handle.connection.rollback()
            return DatabaseErrorCode.ERR_NOT_FOUND

        handle.connection.commit()
        log_info(handle.logger, DB_CONTEXT, f"Set parity server to: {server_id}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to set parity server to {server_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def update_server_status(
    handle: DatabaseHandle,
    server_id: str,
    is_available: bool,
    ping_ms: int = None
) -> DatabaseErrorCode:
    """
    Update server availability status.

    Called after ping tests or connection failures.

    Args:
        handle: Database handle
        server_id: QMailServerID
        is_available: Whether server is available
        ping_ms: Optional ping time in milliseconds

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode update_server_status(DatabaseHandle* handle, const char* server_id,
                                                         bool is_available, int ping_ms);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if not server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        if ping_ms is not None:
            cursor.execute("""
                UPDATE QMailServers
                SET is_available = ?, ping_ms = ?, last_checked = datetime('now')
                WHERE QMailServerID = ?
            """, (1 if is_available else 0, ping_ms, server_id))
        else:
            cursor.execute("""
                UPDATE QMailServers
                SET is_available = ?, last_checked = datetime('now')
                WHERE QMailServerID = ?
            """, (1 if is_available else 0, server_id))

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to update server status for {server_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def get_user_count(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, int]:
    """
    Get total count of users in database.

    Returns:
        Tuple of (error_code, count)

    C signature: DatabaseErrorCode get_user_count(DatabaseHandle* handle, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM Users")
        count = cursor.fetchone()[0]
        return DatabaseErrorCode.SUCCESS, count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get user count", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0


def get_server_count(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, int]:
    """
    Get total count of servers in database.

    Returns:
        Tuple of (error_code, count)

    C signature: DatabaseErrorCode get_server_count(DatabaseHandle* handle, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM QMailServers")
        count = cursor.fetchone()[0]
        return DatabaseErrorCode.SUCCESS, count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get server count", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0


# ============================================================================
# INCOMING EMAIL/DOWNLOAD FUNCTIONS
# ============================================================================

def get_received_tell_by_guid(handle: DatabaseHandle, file_guid: str) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Retrieve a received tell by its file GUID.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None
    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT * FROM received_tells WHERE file_guid = ?", (file_guid,))
        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None
        
        return DatabaseErrorCode.SUCCESS, dict(row)
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get received tell", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None

def get_stripes_for_tell(handle: DatabaseHandle, tell_id: int) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Retrieve all stripe information for a given tell ID.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []
    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT * FROM received_stripes WHERE tell_id = ?", (tell_id,))
        rows = cursor.fetchall()
        return DatabaseErrorCode.SUCCESS, [dict(row) for row in rows]
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get stripes for tell", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def store_received_tell(
    handle: DatabaseHandle,
    file_guid: str,
    locker_code: bytes,
    tell_type: int = 0,
    version: int = 1,
    file_size: int = 0,
    status: str = 'pending'
) -> Tuple[DatabaseErrorCode, int]:
    """
    Store a received tell notification in the database.

    Args:
        handle: Database handle
        file_guid: File group GUID (string, hex format)
        locker_code: 8-byte locker code
        file_type: Type of file (0=email, 10+=attachments)
        version: Protocol version
        file_size: Expected file size (if known)
        status: Status string ('pending', 'downloading', 'complete', 'failed')

    Returns:
        Tuple of (error_code, tell_id)
        tell_id is -1 on failure

    C signature: DatabaseErrorCode store_received_tell(DatabaseHandle* handle,
                                                         const char* file_guid,
                                                         const uint8_t* locker_code,
                                                         int file_type, int* out_tell_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    if not file_guid or locker_code is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    # Convert locker_code to hex string for storage
    locker_code_hex = locker_code.hex() if isinstance(locker_code, bytes) else str(locker_code)

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO received_tells
        (file_guid, locker_code, tell_type)
         VALUES (?, ?, ?)
        """, (file_guid, locker_code_hex, tell_type))
        handle.connection.commit()
        tell_id = cursor.lastrowid

        log_info(handle.logger, DB_CONTEXT, f"Stored received tell: {file_guid}, id={tell_id}")
        return DatabaseErrorCode.SUCCESS, tell_id

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store received tell", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, -1


def store_received_stripe(
    handle: DatabaseHandle,
    tell_id: int,
    server_ip: str,
    stripe_id: int,
    is_parity: bool,
    stripe_hash: str = None
) -> DatabaseErrorCode:
    """
    Store stripe location information for a received tell.

    Args:
        handle: Database handle
        tell_id: ID of the parent tell
        server_ip: Server IP address or hostname
        stripe_id: Stripe index (0-based)
        is_parity: True if this is a parity stripe
        stripe_hash: Optional hash of stripe data for verification

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode store_received_stripe(DatabaseHandle* handle,
                                                           int tell_id, const char* server_ip,
                                                           int stripe_id, bool is_parity);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if tell_id < 0 or not server_ip:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            INSERT INTO received_stripes
            (tell_id, server_ip, stripe_id, is_parity, stripe_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (tell_id, server_ip, stripe_id, is_parity, stripe_hash))

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT,
                  f"Stored stripe: tell_id={tell_id}, server={server_ip}, stripe={stripe_id}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store received stripe", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def update_received_tell_status(
    handle: DatabaseHandle,
    file_guid: str,
    status: str,
    file_size: int = None
) -> DatabaseErrorCode:
    """
    Update the status of a received tell.

    Args:
        handle: Database handle
        file_guid: File group GUID to update
        status: New status ('pending', 'downloading', 'complete', 'failed')
        file_size: Optional file size to update (if now known)

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode update_received_tell_status(DatabaseHandle* handle,
                                                                 const char* file_guid,
                                                                 const char* status);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if not file_guid or not status:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        if file_size is not None:
            cursor.execute("""
                UPDATE received_tells
                SET status = ?, file_size = ?
                WHERE file_guid = ?
            """, (status, file_size, file_guid))
        else:
            cursor.execute("""
                UPDATE received_tells
                SET status = ?
                WHERE file_guid = ?
            """, (status, file_guid))

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT,
                  f"Updated tell status: {file_guid} -> {status}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to update tell status", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def get_received_tells_by_status(
    handle: DatabaseHandle,
    status: str,
    limit: int = 100
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get all received tells with a given status.

    Args:
        handle: Database handle
        status: Status to filter by ('pending', 'downloading', 'complete', 'failed')
        limit: Maximum number of results

    Returns:
        Tuple of (error_code, list of tell dicts)

    C signature: DatabaseErrorCode get_received_tells_by_status(DatabaseHandle* handle,
                                                                  const char* status,
                                                                  ReceivedTell** out_tells,
                                                                  int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if not status:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            SELECT * FROM received_tells
            WHERE status = ?
            ORDER BY created_at ASC
            LIMIT ?
        """, (status, limit))

        rows = cursor.fetchall()
        return DatabaseErrorCode.SUCCESS, [dict(row) for row in rows]

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get tells by status", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def delete_received_tell(
    handle: DatabaseHandle,
    file_guid: str
) -> DatabaseErrorCode:
    """
    Delete a received tell and its associated stripes.

    Args:
        handle: Database handle
        file_guid: File group GUID to delete

    Returns:
        DatabaseErrorCode

    Note: Stripes are deleted automatically via ON DELETE CASCADE.

    C signature: DatabaseErrorCode delete_received_tell(DatabaseHandle* handle,
                                                          const char* file_guid);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if not file_guid:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        cursor.execute("DELETE FROM received_tells WHERE file_guid = ?", (file_guid,))

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        handle.connection.commit()
        log_info(handle.logger, DB_CONTEXT, f"Deleted received tell: {file_guid}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to delete received tell", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def get_pending_download_count(handle: DatabaseHandle) -> Tuple[DatabaseErrorCode, int]:
    """
    Get the count of pending downloads.

    Args:
        handle: Database handle

    Returns:
        Tuple of (error_code, count)

    C signature: DatabaseErrorCode get_pending_download_count(DatabaseHandle* handle, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM received_tells WHERE download_status = 0")
        count = cursor.fetchone()[0]
        return DatabaseErrorCode.SUCCESS, count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get pending download count", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0


# ============================================================================
# SENT EMAIL FUNCTIONS (for email_sender module)
# ============================================================================

def store_sent_email(
    handle: DatabaseHandle,
    file_group_guid: bytes,
    subject: str,
    body: str,
    raw_content: bytes,
    searchable_text: str,
    sender_id: int = None,
    recipient_ids: List[Tuple[int, str]] = None,
    storage_duration: int = 2
) -> DatabaseErrorCode:
    """
    Store a sent email in the database.

    Args:
        handle: Database handle
        file_group_guid: 16-byte file group GUID (used as EmailID)
        subject: Email subject
        body: Email body text
        raw_content: Raw CBDF content
        searchable_text: Plain text for FTS indexing
        sender_id: Sender's user ID (optional)
        recipient_ids: List of (user_id, type) tuples where type is 'TO', 'CC', or 'BC'
        storage_duration: Storage duration code (0-5 or 255)

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode store_sent_email(DatabaseHandle* handle, const uint8_t* guid,
                                                      const char* subject, const char* body, ...);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if file_group_guid is None or len(file_group_guid) != 16:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        now = datetime.now().isoformat()

        # Insert into Emails table
        cursor.execute("""
            INSERT OR REPLACE INTO Emails
            (EmailID, Subject, Body, SentTimestamp, folder, is_read, is_starred, is_trashed)
            VALUES (?, ?, ?, ?, 'sent', 1, 0, 0)
        """, (file_group_guid, subject, body, now))

        # Update FTS index
        cursor.execute("""
            INSERT OR REPLACE INTO Emails_FTS(rowid, Subject, Body)
            SELECT rowid, Subject, Body FROM Emails WHERE EmailID = ?
        """, (file_group_guid,))

        # Link sender
        if sender_id:
            cursor.execute("""
                INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                VALUES (?, ?, 'FROM')
            """, (file_group_guid, sender_id))

        # Link recipients
        for user_id, user_type in (recipient_ids or []):
            cursor.execute("""
                INSERT OR IGNORE INTO Junction_Email_Users (EmailID, UserID, user_type)
                VALUES (?, ?, ?)
            """, (file_group_guid, user_id, user_type))

        handle.connection.commit()
        log_info(handle.logger, DB_CONTEXT, f"Stored sent email: {file_group_guid.hex()}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store sent email", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def store_stripe_locations(
    handle: DatabaseHandle,
    file_group_guid: bytes,
    stripe_locations: List[Tuple[str, int]]
) -> DatabaseErrorCode:
    """
    Store stripe locations for a sent email.

    Args:
        handle: Database handle
        file_group_guid: 16-byte file group GUID (EmailID)
        stripe_locations: List of (server_id, stripe_index) tuples

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode store_stripe_locations(DatabaseHandle* handle, const uint8_t* guid,
                                                           StripeLocation* locations, int count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if not file_group_guid or not stripe_locations:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        for server_id, stripe_index in stripe_locations:
            cursor.execute("""
                INSERT OR REPLACE INTO Junction_Email_QMailServers
                (EmailID, QMailServerID, stripe_index)
                VALUES (?, ?, ?)
            """, (file_group_guid, server_id, stripe_index))

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT,
                  f"Stored {len(stripe_locations)} stripe locations for {file_group_guid.hex()}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store stripe locations", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def get_sent_emails(
    handle: DatabaseHandle,
    limit: int = 50,
    offset: int = 0
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get list of sent emails.

    Args:
        handle: Database handle
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        Tuple of (error_code, list of email dicts)

    C signature: DatabaseErrorCode get_sent_emails(DatabaseHandle* handle, int limit, int offset,
                                                    EmailSummary** out_emails, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT EmailID, Subject, SentTimestamp, is_starred
            FROM Emails
            WHERE folder = 'sent' AND is_trashed = 0
            ORDER BY SentTimestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        emails = []
        for row in cursor.fetchall():
            emails.append({
                'email_id': row['EmailID'].hex() if isinstance(row['EmailID'], bytes) else row['EmailID'],
                'subject': row['Subject'],
                'sent_timestamp': row['SentTimestamp'],
                'is_starred': bool(row['is_starred'])
            })

        log_debug(handle.logger, DB_CONTEXT, f"Retrieved {len(emails)} sent emails")
        return DatabaseErrorCode.SUCCESS, emails

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get sent emails", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_stripe_locations(
    handle: DatabaseHandle,
    file_group_guid: bytes
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get stripe locations for an email.

    Args:
        handle: Database handle
        file_group_guid: 16-byte file group GUID (EmailID)

    Returns:
        Tuple of (error_code, list of location dicts)

    C signature: DatabaseErrorCode get_stripe_locations(DatabaseHandle* handle, const uint8_t* guid,
                                                         StripeLocation** out_locations, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    if not file_group_guid:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT jes.QMailServerID, jes.stripe_index,
                   qs.IPAddress, qs.PortNumb, qs.is_available
            FROM Junction_Email_QMailServers jes
            LEFT JOIN QMailServers qs ON jes.QMailServerID = qs.QMailServerID
            WHERE jes.EmailID = ?
            ORDER BY jes.stripe_index
        """, (file_group_guid,))

        locations = []
        for row in cursor.fetchall():
            locations.append({
                'server_id': row['QMailServerID'],
                'stripe_index': row['stripe_index'],
                'ip_address': row['IPAddress'],
                'port': row['PortNumb'],
                'is_available': bool(row['is_available']) if row['is_available'] is not None else True
            })

        log_debug(handle.logger, DB_CONTEXT,
                  f"Retrieved {len(locations)} stripe locations for {file_group_guid.hex()}")
        return DatabaseErrorCode.SUCCESS, locations

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get stripe locations", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


# ============================================================================
# PENDING TELLS FUNCTIONS (for retry queue)
# ============================================================================

def insert_pending_tell(
    handle: DatabaseHandle,
    file_group_guid: bytes,
    recipient_address: str,
    recipient_type: int,
    beacon_server_id: str,
    locker_code: bytes,
    server_list_json: str
) -> Tuple[DatabaseErrorCode, int]:
    """
    Insert a pending Tell notification for retry.

    Called when a Tell to a beacon server fails. Stores the notification
    data for later retry attempts.

    Args:
        handle: Database handle
        file_group_guid: 16-byte file group GUID
        recipient_address: Recipient's qmail address (e.g., "0006.1.12345678")
        recipient_type: 0=To, 1=CC, 2=BCC
        beacon_server_id: Beacon server ID (e.g., "raida11")
        locker_code: 8-byte locker code for re-encryption on retry
        server_list_json: JSON serialized server list

    Returns:
        Tuple of (DatabaseErrorCode, tell_id)

    C signature: DatabaseErrorCode insert_pending_tell(DatabaseHandle* handle, ...);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    if not file_group_guid or not recipient_address or not beacon_server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            INSERT INTO PendingTells
            (FileGroupGUID, RecipientAddress, RecipientType, BeaconServerID,
             LockerCode, ServerListJSON, Status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """, (file_group_guid, recipient_address, recipient_type, beacon_server_id,
              locker_code, server_list_json))

        tell_id = cursor.lastrowid
        handle.connection.commit()

        log_info(handle.logger, DB_CONTEXT,
                 f"Inserted pending tell {tell_id} for {recipient_address}")
        return DatabaseErrorCode.SUCCESS, tell_id

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to insert pending tell", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0


def get_pending_tells(
    handle: DatabaseHandle,
    status: str = 'pending',
    limit: int = 50
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get pending Tell notifications for retry.

    Args:
        handle: Database handle
        status: Filter by status ('pending', 'sent', 'failed')
        limit: Maximum number of results

    Returns:
        Tuple of (DatabaseErrorCode, list of pending tell dicts)

    C signature: DatabaseErrorCode get_pending_tells(DatabaseHandle* handle, const char* status,
                                                      int limit, PendingTell** out, int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT TellID, FileGroupGUID, RecipientAddress, RecipientType,
                   BeaconServerID, LockerCode, ServerListJSON,
                   CreatedTimestamp, RetryCount, LastAttemptTimestamp,
                   ErrorMessage, Status
            FROM PendingTells
            WHERE Status = ?
            ORDER BY CreatedTimestamp ASC
            LIMIT ?
        """, (status, limit))

        tells = []
        for row in cursor.fetchall():
            tells.append({
                'tell_id': row['TellID'],
                'file_group_guid': row['FileGroupGUID'],
                'recipient_address': row['RecipientAddress'],
                'recipient_type': row['RecipientType'],
                'beacon_server_id': row['BeaconServerID'],
                'locker_code': row['LockerCode'],
                'server_list_json': row['ServerListJSON'],
                'created_timestamp': row['CreatedTimestamp'],
                'retry_count': row['RetryCount'],
                'last_attempt_timestamp': row['LastAttemptTimestamp'],
                'error_message': row['ErrorMessage'],
                'status': row['Status']
            })

        log_debug(handle.logger, DB_CONTEXT,
                  f"Retrieved {len(tells)} pending tells with status '{status}'")
        return DatabaseErrorCode.SUCCESS, tells

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get pending tells", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def update_pending_tell_status(
    handle: DatabaseHandle,
    tell_id: int,
    status: str,
    error_message: str = None,
    increment_retry: bool = False
) -> DatabaseErrorCode:
    """
    Update a pending Tell's status.

    Args:
        handle: Database handle
        tell_id: The TellID to update
        status: New status ('pending', 'sent', 'failed')
        error_message: Optional error message on failure
        increment_retry: Whether to increment retry count

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode update_pending_tell_status(DatabaseHandle* handle, int tell_id,
                                                               const char* status, const char* error_msg);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        if increment_retry:
            cursor.execute("""
                UPDATE PendingTells
                SET Status = ?, ErrorMessage = ?,
                    LastAttemptTimestamp = datetime('now'),
                    RetryCount = RetryCount + 1
                WHERE TellID = ?
            """, (status, error_message, tell_id))
        else:
            cursor.execute("""
                UPDATE PendingTells
                SET Status = ?, ErrorMessage = ?,
                    LastAttemptTimestamp = datetime('now')
                WHERE TellID = ?
            """, (status, error_message, tell_id))

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT,
                  f"Updated pending tell {tell_id} to status '{status}'")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT,
                  f"Failed to update pending tell {tell_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def delete_pending_tell(
    handle: DatabaseHandle,
    tell_id: int
) -> DatabaseErrorCode:
    """
    Delete a pending Tell (after successful send).

    Args:
        handle: Database handle
        tell_id: The TellID to delete

    Returns:
        DatabaseErrorCode

    C signature: DatabaseErrorCode delete_pending_tell(DatabaseHandle* handle, int tell_id);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        cursor.execute("DELETE FROM PendingTells WHERE TellID = ?", (tell_id,))

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        handle.connection.commit()
        log_debug(handle.logger, DB_CONTEXT, f"Deleted pending tell {tell_id}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT,
                  f"Failed to delete pending tell {tell_id}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def get_user_by_address(
    handle: DatabaseHandle,
    qmail_address: str
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get user info by their qmail address.

    Used to look up recipient's beacon server.

    Args:
        handle: Database handle
        qmail_address: QMail address (e.g., "0006.1.12345678")

    Returns:
        Tuple of (DatabaseErrorCode, user dict or None)

    C signature: DatabaseErrorCode get_user_by_address(DatabaseHandle* handle, const char* address,
                                                         User* out_user);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if not qmail_address:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT UserID, FirstName, LastName, auto_address, BeaconID,
                   sending_fee, dreg_score
            FROM Users
            WHERE auto_address = ?
        """, (qmail_address,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        user = {
            'user_id': row['UserID'],
            'first_name': row['FirstName'],
            'last_name': row['LastName'],
            'auto_address': row['auto_address'],
            'beacon_id': row['BeaconID'],
            'sending_fee': row['sending_fee'],
            'dreg_score': row['dreg_score']
        }

        return DatabaseErrorCode.SUCCESS, user

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT,
                  f"Failed to get user by address {qmail_address}", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


def fix_null_beacon_ids(
    handle: DatabaseHandle,
    default_beacon: str = 'raida11'
) -> Tuple[DatabaseErrorCode, int]:
    """
    Fix any users with null/empty BeaconID by setting to default.

    One-time migration function.

    Args:
        handle: Database handle
        default_beacon: Default beacon server ID

    Returns:
        Tuple of (DatabaseErrorCode, number of rows updated)

    C signature: DatabaseErrorCode fix_null_beacon_ids(DatabaseHandle* handle, const char* default_beacon,
                                                         int* out_count);
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            UPDATE Users
            SET BeaconID = ?
            WHERE BeaconID IS NULL OR BeaconID = ''
        """, (default_beacon,))

        count = cursor.rowcount
        handle.connection.commit()

        if count > 0:
            log_info(handle.logger, DB_CONTEXT,
                     f"Fixed {count} users with null BeaconID (set to '{default_beacon}')")

        return DatabaseErrorCode.SUCCESS, count

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to fix null beacon IDs", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, 0
    


def is_guid_in_database(handle, file_guid):
    """Checks if a GUID has already been cached."""
    cursor = handle.connection.cursor()
    cursor.execute("SELECT 1 FROM received_tells WHERE file_guid = ?", (file_guid,))
    return cursor.fetchone() is not None

def store_received_tell(
    handle: DatabaseHandle,
    file_guid: str,
    locker_code: bytes,
    tell_type: int = 0,  # Changed from file_type
    version: int = 1,    # Keep for backward compatibility but don't use
    file_size: int = 0,  # Keep for backward compatibility but don't use
    status: str = 'pending'  # Keep for backward compatibility but don't use
) -> Tuple[DatabaseErrorCode, int]:
    """Store a received tell notification in the database."""
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    if not file_guid or locker_code is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    # Convert locker_code to hex string for storage
    locker_code_hex = locker_code.hex() if isinstance(locker_code, bytes) else str(locker_code)

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO received_tells
            (file_guid, locker_code, tell_type)
            VALUES (?, ?, ?)
        """, (file_guid, locker_code_hex, tell_type))

        handle.connection.commit()
        tell_id = cursor.lastrowid

        log_info(handle.logger, DB_CONTEXT, f"Stored received tell: {file_guid}, id={tell_id}")
        return DatabaseErrorCode.SUCCESS, tell_id

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store received tell", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, -1

def store_received_stripe(
    handle: DatabaseHandle,
    tell_id: int,
    server_ip: str,
    stripe_id: int,
    is_parity: bool,
    port: int,
    stripe_hash: str = None
) -> DatabaseErrorCode:
    """
    Store stripe location information for a received tell.

    Args:
        handle: Database handle
        tell_id: ID of the parent tell
        server_ip: Server IP address or hostname
        stripe_id: Stripe index (0-based)
        is_parity: True if this is a parity stripe
        port: Server port number
        stripe_hash: Optional hash of stripe data for verification

    Returns:
        DatabaseErrorCode
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if tell_id < 0 or not server_ip:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            INSERT INTO received_stripes
            (tell_id, server_ip, stripe_id, is_parity, port, stripe_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tell_id, server_ip, stripe_id, is_parity, port, stripe_hash))

        handle.connection.commit()
        log_info(handle.logger, DB_CONTEXT, f"Stored stripe {stripe_id} for tell {tell_id}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to store stripe", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED

def delete_email_locally(handle, file_guid):
    """PHASE I DELETE: Local only. No network commands."""
    cursor = handle.connection.cursor()
    cursor.execute("SELECT local_path FROM received_tells WHERE file_guid = ?", (file_guid,))
    row = cursor.fetchone()
    if row and row['local_path'] and os.path.exists(row['local_path']):
        os.remove(row['local_path'])
    cursor.execute("DELETE FROM received_tells WHERE file_guid = ?", (file_guid,))
    handle.connection.commit()
    return DatabaseErrorCode.SUCCESS


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import tempfile
    import os

    print("=" * 60)
    print("opus45_database.py - Test Suite")
    print("=" * 60)

    # Create temporary database
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_qmail.db")

        # Test init
        print("\n1. Testing init_database()...")
        err, handle = init_database(db_path)
        assert err == DatabaseErrorCode.SUCCESS, f"Init failed: {err}"
        assert handle is not None
        print(f"   SUCCESS: Database created at {db_path}")

        # Test store_contact
        print("\n2. Testing store_contact()...")
        contact = {
            'first_name': 'John',
            'last_name': 'Doe',
            'auto_address': 'john.doe@qmail.net',
            'description': 'Test contact'
        }
        err, user_id = store_contact(handle, contact)
        assert err == DatabaseErrorCode.SUCCESS
        assert user_id is not None
        print(f"   SUCCESS: Stored contact with ID {user_id}")

        # Store another contact
        contact2 = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'auto_address': 'jane.smith@qmail.net'
        }
        err, user_id2 = store_contact(handle, contact2)
        assert err == DatabaseErrorCode.SUCCESS

        # Test store_email
        print("\n3. Testing store_email()...")
        email = {
            'subject': 'Test Email',
            'body': 'This is a test email body.',
            'sender_id': user_id,
            'recipient_ids': [user_id2],
            'sent_timestamp': '2025-12-11T10:00:00'
        }
        err, email_id = store_email(handle, email)
        assert err == DatabaseErrorCode.SUCCESS
        assert email_id is not None
        print(f"   SUCCESS: Stored email with ID {email_id.hex()}")

        # Test retrieve_email
        print("\n4. Testing retrieve_email()...")
        err, retrieved = retrieve_email(handle, email_id)
        assert err == DatabaseErrorCode.SUCCESS
        assert retrieved is not None
        assert retrieved['subject'] == 'Test Email'
        print(f"   SUCCESS: Retrieved email - Subject: '{retrieved['subject']}'")

        # Test update_email_flags
        print("\n5. Testing update_email_flags()...")
        success = update_email_flags(handle, email_id, {'is_read': True, 'is_starred': True})
        assert success
        err, retrieved = retrieve_email(handle, email_id)
        assert retrieved['is_read'] == True
        assert retrieved['is_starred'] == True
        print(f"   SUCCESS: Flags updated - is_read={retrieved['is_read']}, is_starred={retrieved['is_starred']}")

        # Test get_popular_contacts
        print("\n6. Testing get_popular_contacts()...")
        # Update contact stats to give John higher popularity
        update_contact_stats(handle, user_id)
        update_contact_stats(handle, user_id)
        update_contact_stats(handle, user_id2)

        err, contacts = get_popular_contacts(handle, limit=10)
        assert err == DatabaseErrorCode.SUCCESS
        assert len(contacts) == 2
        print(f"   SUCCESS: Found {len(contacts)} contacts")
        for c in contacts:
            print(f"     - {c['first_name']} {c['last_name']} (popularity: {c['popularity']:.2f})")

        # Test execute_query
        print("\n7. Testing execute_query()...")
        err, results = execute_query(handle, "SELECT COUNT(*) as cnt FROM Emails", ())
        assert err == DatabaseErrorCode.SUCCESS
        print(f"   SUCCESS: Query returned {results[0]['cnt']} email(s)")

        # Test store_attachment
        print("\n8. Testing store_attachment()...")
        attachment = {
            'name': 'document.pdf',
            'file_extension': 'pdf',
            'storage_mode': 'INTERNAL',
            'data_blob': b'PDF content here',
            'size_bytes': 16
        }
        err, att_id = store_attachment(handle, email_id, attachment)
        assert err == DatabaseErrorCode.SUCCESS
        print(f"   SUCCESS: Stored attachment with ID {att_id}")

        # Verify attachment is retrieved with email
        err, retrieved = retrieve_email(handle, email_id)
        assert len(retrieved['attachments']) == 1
        print(f"   SUCCESS: Email now has {len(retrieved['attachments'])} attachment(s)")

        # Test database stats
        print("\n9. Testing get_database_stats()...")
        err, stats = get_database_stats(handle)
        assert err == DatabaseErrorCode.SUCCESS
        print(f"   SUCCESS: Database stats:")
        for table, count in stats.items():
            print(f"     - {table}: {count} rows")

        # Test close
        print("\n10. Testing close_database()...")
        success = close_database(handle)
        assert success
        print("   SUCCESS: Database closed")

        print("\n" + "=" * 60)
        print("All tests passed!")
        print("=" * 60)
