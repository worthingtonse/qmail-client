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
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import IntEnum

# Try to import from package, fall back to direct import for standalone testing
try:
    from logger import log_info, log_error, log_warning, log_debug
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
    from qmail_types import Email, User, Attachment
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
CREATE TABLE IF NOT EXISTS Servers (
        ServerID TEXT PRIMARY KEY,
        ServerIndex INTEGER,
        IPAddress TEXT,
        Port INTEGER,
        ServerType TEXT,
        CostPerMB REAL DEFAULT 1.0,
        CostPer8Weeks REAL DEFAULT 1.0,
        PercentUptime INTEGER DEFAULT 100,
        PerformancePercentile INTEGER DEFAULT 0,
        Region TEXT,
        Description TEXT,
        IsAvailable INTEGER DEFAULT 1,
        LastSeen INTEGER,
        UseForParity INTEGER DEFAULT 0,  -- <--- ADDED
        PingMS INTEGER DEFAULT 0         -- <--- ADDED
    );

-- ==========================================
-- 2. Users (Contacts)
-- ==========================================
CREATE TABLE IF NOT EXISTS Users (
    SerialNumber INTEGER PRIMARY KEY,    -- Decoded integer (e.g., 2841)
    Denomination INTEGER DEFAULT 0,
    CustomSerialNumber TEXT UNIQUE,      -- Original Base32 string (e.g., 'C23')
    FirstName TEXT,
    LastName TEXT,
    auto_address TEXT UNIQUE,            -- <--- YE COLUMN MISSING THA
    Description TEXT,
    InboxFee REAL DEFAULT 0.0,           -- The flat fee per message
    Class TEXT,                          -- e.g., 'giga'
    Beacon TEXT,                         -- e.g., 'RAIDA11'
    contact_count INTEGER DEFAULT 0,
    last_contacted_timestamp INTEGER
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
    SerialNumber INTEGER, -- FIXED: Changed from UserID
    user_type TEXT CHECK(user_type IN ('TO', 'CC', 'BC', 'MASS', 'FROM')),
    PRIMARY KEY (EmailID, SerialNumber, user_type),
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE,
    FOREIGN KEY(SerialNumber) REFERENCES Users(SerialNumber) ON DELETE CASCADE -- FIXED
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
    BeaconLockerHex TEXT,
    InboxLockerHex TEXT,
    ServerListJSON TEXT NOT NULL,
    CreatedTimestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    RetryCount INTEGER DEFAULT 0,
    LastAttemptTimestamp DATETIME,
    ErrorMessage TEXT,
    Status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS sent_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_guid TEXT UNIQUE,
    subject TEXT,
    recipients TEXT,
    body_preview TEXT,
    timestamp INTEGER,
    stripe_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sent_timestamp ON sent_emails(timestamp);

-- Table for incoming email metadata (from .tell files)
CREATE TABLE IF NOT EXISTS received_tells (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_guid TEXT UNIQUE,
    locker_code BLOB,
    tell_type INTEGER,
    sender_sn INTEGER DEFAULT 0,
    download_status INTEGER DEFAULT 0,
    read_status INTEGER DEFAULT 0,
    local_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    payment_status INTEGER DEFAULT 0
);

-- Table for tracking stripe locations
CREATE TABLE IF NOT EXISTS received_stripes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tell_id INTEGER,
    server_ip TEXT,
    stripe_id INTEGER,
    is_parity BOOLEAN,
    port INTEGER, -- FIXED: Added missing column
    stripe_hash TEXT,
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





def init_database(db_path: str, logger: Any = None) -> Tuple[DatabaseErrorCode, Optional[DatabaseHandle]]:
    """
    Initialize database connection and create all tables.
    FIXED: Auto-migrates missing columns (UseForParity, PingMS) to prevent crashes.
    """
    import sqlite3
    import os
    from src.database import DatabaseErrorCode, DatabaseHandle, SCHEMA_SQL
    from src.logger import log_info, log_error

    if not db_path: 
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # 1. Directory Safety
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
            log_info(logger, "Database", f"Created directory: {db_dir}")
        except OSError as e:
            if logger: log_error(logger, "Database", "Directory creation failed", str(e))
            return DatabaseErrorCode.ERR_IO, None

    try:
        # 2. Connection
        connection = sqlite3.connect(db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        cursor = connection.cursor()

        # 3. Create Tables (If they don't exist)
        cursor.executescript(SCHEMA_SQL)

        # 4. MIGRATION: Fix Servers Table (This fixes your crash)
        cursor.execute("PRAGMA table_info(Servers)")
        server_cols = [col[1] for col in cursor.fetchall()]
        
        if 'UseForParity' not in server_cols:
            log_info(logger, "Database", "Migrating: Adding UseForParity to Servers")
            cursor.execute("ALTER TABLE Servers ADD COLUMN UseForParity INTEGER DEFAULT 0")
            
        if 'PingMS' not in server_cols:
            log_info(logger, "Database", "Migrating: Adding PingMS to Servers")
            cursor.execute("ALTER TABLE Servers ADD COLUMN PingMS INTEGER DEFAULT 0")

        # 5. MIGRATION: Fix Users Table (Preserving your existing checks)
        cursor.execute("PRAGMA table_info(Users)")
        user_cols = [col[1] for col in cursor.fetchall()]
        
        if 'contact_count' not in user_cols:
            cursor.execute("ALTER TABLE Users ADD COLUMN contact_count INTEGER DEFAULT 0")
        
        if 'last_contacted_timestamp' not in user_cols:
            cursor.execute("ALTER TABLE Users ADD COLUMN last_contacted_timestamp INTEGER")

        # 6. MIGRATION: PendingTells locker columns
        cursor.execute("PRAGMA table_info(PendingTells)")
        pt_cols = [col[1] for col in cursor.fetchall()]

        if 'BeaconLockerHex' not in pt_cols:
            log_info(logger, "Database", "Migrating: Adding BeaconLockerHex to PendingTells")
            cursor.execute("ALTER TABLE PendingTells ADD COLUMN BeaconLockerHex TEXT")

        if 'InboxLockerHex' not in pt_cols:
            log_info(logger, "Database", "Migrating: Adding InboxLockerHex to PendingTells")
            cursor.execute("ALTER TABLE PendingTells ADD COLUMN InboxLockerHex TEXT")

        # 7. MIGRATION: received_tells sender_sn column (for existing databases)
        try:
            cursor.execute("ALTER TABLE received_tells ADD COLUMN sender_sn INTEGER DEFAULT 0")
            log_info(logger, "Database", "Migrating: Adding sender_sn to received_tells")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE received_tells ADD COLUMN total_file_size INTEGER DEFAULT 0")
            log_info(logger, "Database", "Migrating: Adding total_file_size to received_tells")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE received_tells ADD COLUMN payment_status INTEGER DEFAULT 0")
            log_info(logger, "Database", "Migrating: Adding payment_status to received_tells")
        except sqlite3.OperationalError:
            pass  # Column already exists

        connection.commit()
        log_info(logger, "Database", f"Database initialized and migrated: {db_path}")
        
        handle = DatabaseHandle(connection=connection, path=db_path, logger=logger)
        return DatabaseErrorCode.SUCCESS, handle

    except sqlite3.Error as e:
        if logger: log_error(logger, "Database", "Initialization failed", str(e))
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

def store_email(handle: Any, email: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[bytes]]:
    """
    Store an email in the database.
    

    Args:
        handle: Database handle
        email: Dictionary with email data:
            - email_id: bytes (GUID)
            - subject: str
            - body: str
            - sender_sn: int (SerialNumber)
            - recipient_sns: List[int] (SerialNumbers)
            - cc_sns: List[int] (SerialNumbers)
            - folder: str
            - received_timestamp: int (Unix)
            - sent_timestamp: int (Unix)
    """
    import sqlite3
    import uuid
    from src.database import DatabaseErrorCode
    from src.logger import log_error, log_debug

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # Generate or parse email ID
    email_id = email.get('email_id')
    if email_id is None:
        email_id = uuid.uuid4().bytes
    elif isinstance(email_id, str):
        try:
            email_id = bytes.fromhex(email_id)
        except ValueError:
            return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        # 1. Insert into Emails table (update if exists)
        folder = email.get('folder', 'inbox')
        is_read = email.get('is_read', 0)
        
        cursor.execute("""
            INSERT INTO Emails (
                EmailID, Subject, Body, ReceivedTimestamp, 
                SentTimestamp, Meta, Style, folder, is_read
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(EmailID) DO UPDATE SET
                Subject = excluded.Subject,
                Body = excluded.Body,
                ReceivedTimestamp = COALESCE(excluded.ReceivedTimestamp, ReceivedTimestamp),
                SentTimestamp = COALESCE(excluded.SentTimestamp, SentTimestamp),
                Meta = COALESCE(excluded.Meta, Meta),
                Style = COALESCE(excluded.Style, Style),
                folder = excluded.folder,
                is_read = excluded.is_read
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

        
        # 2. Link sender (FROM) using SerialNumber (only if user exists)
        sender_sn = email.get('sender_sn')
        if sender_sn is not None:
            # Check if user exists before inserting junction
            cursor.execute("SELECT 1 FROM Users WHERE SerialNumber = ?", (sender_sn,))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO Junction_Email_Users (EmailID, SerialNumber, user_type)
                    VALUES (?, ?, 'FROM')
                """, (email_id, sender_sn))

        # 3. Link recipients (TO) using SerialNumber (only if user exists)
        for sn in email.get('recipient_sns', []):
            cursor.execute("SELECT 1 FROM Users WHERE SerialNumber = ?", (sn,))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO Junction_Email_Users (EmailID, SerialNumber, user_type)
                    VALUES (?, ?, 'TO')
                """, (email_id, sn))

        # 4. Link CC recipients using SerialNumber (only if user exists)
        for sn in email.get('cc_sns', []):
            cursor.execute("SELECT 1 FROM Users WHERE SerialNumber = ?", (sn,))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO Junction_Email_Users (EmailID, SerialNumber, user_type)
                    VALUES (?, ?, 'CC')
                """, (email_id, sn))

        handle.connection.commit()
        log_debug(handle.logger, "Database", f"Stored email: {email_id.hex()}")

        return DatabaseErrorCode.SUCCESS, email_id

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", "Failed to store email", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None

# ============================================================================
# UPDATE DRAFT
# ============================================================================

def update_draft(handle: DatabaseHandle, email_id: bytes, draft_data: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Update a draft email.
    FIXED: Uses 'SerialNumber' and integer timestamps.
    """
    import time
    import sqlite3

    if handle is None or handle.connection is None or email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()
        now_ts = int(time.time())

        # 1. Verify existence
        cursor.execute("SELECT 1 FROM Emails WHERE EmailID = ? AND folder = 'drafts'", (email_id,))
        if cursor.fetchone() is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        # 2. Update core fields
        set_parts = ["SentTimestamp = ?"]
        params = [now_ts]

        if 'subject' in draft_data:
            set_parts.append("Subject = ?")
            params.append(draft_data['subject'])
        if 'body' in draft_data:
            set_parts.append("Body = ?")
            params.append(draft_data['body'])

        params.append(email_id)
        query = f"UPDATE Emails SET {', '.join(set_parts)} WHERE EmailID = ?"
        cursor.execute(query, params)

        # 3. Update Recipients (TO) - FIXED to SerialNumber
        if 'recipient_ids' in draft_data:
            cursor.execute("DELETE FROM Junction_Email_Users WHERE EmailID = ? AND user_type = 'TO'", (email_id,))
            for sn in draft_data['recipient_ids']:
                cursor.execute("INSERT OR IGNORE INTO Junction_Email_Users (EmailID, SerialNumber, user_type) VALUES (?, ?, 'TO')", (email_id, sn))

        handle.connection.commit()
        
        # 4. Return fresh data with Case-Sensitive keys
        from src.database import retrieve_email
        return retrieve_email(handle, email_id)

    except sqlite3.Error:
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED, None


# ============================================================================
# RETRIEVE EMAIL
# ============================================================================

def retrieve_email(handle: Any, email_id: bytes) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Retrieve full email including Pretty addresses for Sender and Recipients.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None or email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # 1. Get Main Email Data
        cursor.execute("""
            SELECT EmailID, Subject, Body, ReceivedTimestamp, SentTimestamp,
                   Meta, Style, is_read, is_starred, is_trashed, folder
            FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        email = dict(row)
        email['email_id'] = row['EmailID'].hex()
        email['recipients'] = []
        email['cc'] = []
        email['sender'] = None
        email['attachments'] = []

        # 2. Get Pretty Sender
        cursor.execute("""
            SELECT u.SerialNumber, u.FirstName, u.LastName, u.auto_address
            FROM Junction_Email_Users j
            JOIN Users u ON j.SerialNumber = u.SerialNumber
            WHERE j.EmailID = ? AND j.user_type = 'FROM'
        """, (email_id,))
        s_row = cursor.fetchone()
        if s_row:
            email['sender'] = dict(s_row)

        # 3. Get Pretty Recipients (TO & CC)
        cursor.execute("""
            SELECT u.SerialNumber, u.FirstName, u.LastName, u.auto_address, j.user_type
            FROM Junction_Email_Users j
            JOIN Users u ON j.SerialNumber = u.SerialNumber
            WHERE j.EmailID = ? AND j.user_type IN ('TO', 'CC')
        """, (email_id,))
        for r in cursor.fetchall():
            info = dict(r)
            if r['user_type'] == 'TO':
                email['recipients'].append(info)
            else:
                email['cc'].append(info)

        return DatabaseErrorCode.SUCCESS, email

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", "Failed to retrieve email", str(e))
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
    FIXED: Uses SerialNumber for joins and returns Pretty Addresses.
    """
    if handle is None or handle.connection is None or email_id is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if isinstance(email_id, str):
        success, email_id, _ = _safe_hex_to_bytes(email_id, handle.logger)
        if not success: return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # 1. Get core metadata
        cursor.execute("""
            SELECT EmailID, Subject, ReceivedTimestamp, SentTimestamp,
                   is_read, is_starred, is_trashed, folder
            FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None: return DatabaseErrorCode.ERR_NOT_FOUND, None

        metadata = dict(row)
        metadata['email_id'] = row['EmailID'].hex()
        metadata['sender'] = None
        metadata['recipients'] = []
        metadata['cc'] = []
        metadata['attachments'] = []

        # 2. Get Pretty Sender (JOIN on SerialNumber)
        cursor.execute("""
            SELECT u.SerialNumber, u.FirstName, u.LastName, u.auto_address
            FROM Junction_Email_Users j
            JOIN Users u ON j.SerialNumber = u.SerialNumber
            WHERE j.EmailID = ? AND j.user_type = 'FROM'
        """, (email_id,))
        s_row = cursor.fetchone()
        if s_row: metadata['sender'] = dict(s_row)

        # 3. Get Pretty Recipients (JOIN on SerialNumber)
        cursor.execute("""
            SELECT u.SerialNumber, u.FirstName, u.LastName, u.auto_address, j.user_type
            FROM Junction_Email_Users j
            JOIN Users u ON j.SerialNumber = u.SerialNumber
            WHERE j.EmailID = ? AND j.user_type IN ('TO', 'CC')
        """, (email_id,))
        for r in cursor.fetchall():
            info = dict(r)
            if r['user_type'] == 'TO': metadata['recipients'].append(info)
            else: metadata['cc'].append(info)

        return DatabaseErrorCode.SUCCESS, metadata
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Metadata fetch failed", str(e))
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
    Get most popular contacts. FIXED: Returns SerialNumber and Pretty auto_address.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    limit = max(1, limit)
    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        query = """
            SELECT
                SerialNumber, FirstName, LastName, auto_address, Description, contact_count,
                CASE
                    WHEN last_contacted_timestamp IS NULL THEN 0
                    ELSE contact_count / (1.0 + (julianday('now') - julianday(last_contacted_timestamp)) * 0.1)
                END AS popularity
            FROM Users
            WHERE 1=1
        """
        params = []
        if first_name_like:
            query += " AND FirstName LIKE ?"; params.append(f"%{first_name_like}%")
        if last_name_like:
            query += " AND LastName LIKE ?"; params.append(f"%{last_name_like}%")
        if auto_address_like:
            query += " AND auto_address LIKE ?"; params.append(f"%{auto_address_like}%")

        query += " ORDER BY popularity DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        contacts = [dict(row) for row in cursor.fetchall()]
        return DatabaseErrorCode.SUCCESS, contacts
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Popular contacts failed", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


# ============================================================================
# CONTACT MANAGEMENT FUNCTIONS
# ============================================================================
def get_all_contacts(
    handle: Any,
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]], int]:
    """
    Get paginated list of all contacts with optional search.
    FIXED: Matches the new Integer SerialNumber and Pretty Address schema.

    Args:
        handle: Database handle
        page: Page number (1-indexed)
        limit: Results per page (max 200)
        search: Optional search term for name/pretty_address

    Returns:
        Tuple of (error_code, contacts_list, total_count)
    """
    from src.database import DatabaseErrorCode
    from src.logger import log_error, log_debug
    import sqlite3

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, [], 0

    # Pagination values clamp karein
    page = max(1, page)
    limit = max(1, min(limit, 200))
    offset = (page - 1) * limit

    try:
        # Dictionary access enable karein
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # 1. Search Logic
        where_clause = ""
        params = []
        if search and search.strip():
            search_pattern = f"%{search.strip()}%"
            # Hum FirstName, LastName aur Pretty Email (auto_address) teeno mein search karenge
            where_clause = """
                WHERE LOWER(FirstName) LIKE LOWER(?)
                   OR LOWER(LastName) LIKE LOWER(?)
                   OR LOWER(auto_address) LIKE LOWER(?)
                   OR LOWER(CustomSerialNumber) LIKE LOWER(?)
            """
            params = [search_pattern, search_pattern, search_pattern, search_pattern]

        # 2. Total Count Query (Search filter ke saath)
        count_query = f"SELECT COUNT(*) FROM Users {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # 3. Data Query (Sahi Column Names ke saath)
        # UserID ki jagah SerialNumber aur naye fields (Class, Denomination) include kiye hain
        data_query = f"""
            SELECT 
                SerialNumber, Denomination, CustomSerialNumber, 
                FirstName, LastName, auto_address, Description, 
                InboxFee, Class, Beacon, contact_count
            FROM Users
            {where_clause}
            ORDER BY FirstName ASC, LastName ASC
            LIMIT ? OFFSET ?
        """
        cursor.execute(data_query, params + [limit, offset])

        contacts = []
        for row in cursor.fetchall():
            # Dictionary banana taaki API handlers ko asani ho
            contacts.append({
                'serial_number': row['SerialNumber'],
                'denomination': row['Denomination'],
                'custom_sn': row['CustomSerialNumber'],
                'first_name': row['FirstName'],
                'last_name': row['LastName'],
                'auto_address': row['auto_address'], # Pretty Email Format
                'description': row['Description'],
                'inbox_fee': row['InboxFee'],
                'class': row['Class'],
                'beacon': row['Beacon'],
                'contact_count': row['contact_count']
            })

        log_debug(handle.logger, "Database", f"get_all_contacts: found {len(contacts)} of {total_count}")
        return DatabaseErrorCode.SUCCESS, contacts, total_count

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", "Failed to get all contacts", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, [], 0
def get_contact_by_id(
    handle: Any,
    serial_number: int
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get a single contact by their SerialNumber (Integer ID).
    FIXED: Uses SerialNumber as PK and returns all 'Pretty' fields.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    # SerialNumber must be a valid integer
    if serial_number is None or not isinstance(serial_number, int):
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # Query matches the new consolidated schema
        cursor.execute("""
            SELECT 
                SerialNumber, Denomination, CustomSerialNumber, 
                FirstName, LastName, auto_address, Description, 
                InboxFee, Class, Beacon, contact_count
            FROM Users
            WHERE SerialNumber = ?
        """, (serial_number,))

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        # Convert to dictionary for API handlers
        contact = dict(row)

        return DatabaseErrorCode.SUCCESS, contact

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", f"Failed to get contact {serial_number}", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None
def delete_contact(
    handle: Any,
    serial_number: int
) -> DatabaseErrorCode:
    """
    Hard delete a contact by SerialNumber.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error, log_debug

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    if serial_number is None or not isinstance(serial_number, int):
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        # Delete based on the new Primary Key
        cursor.execute("DELETE FROM Users WHERE SerialNumber = ?", (serial_number,))
        handle.connection.commit()

        if cursor.rowcount == 0:
            return DatabaseErrorCode.ERR_NOT_FOUND

        log_debug(handle.logger, "Database", f"Deleted contact: {serial_number}")
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", f"Failed to delete contact {serial_number}", str(e))
        handle.connection.rollback()
        return DatabaseErrorCode.ERR_QUERY_FAILED


def check_email_exists(
    handle: Any,
    pretty_address: str,
    exclude_sn: Optional[int] = None
) -> Tuple[DatabaseErrorCode, bool]:
    """
    Check if a Pretty Email address already exists (case-insensitive).
    FIXED: Uses SerialNumber for exclusion check during updates.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None or not pretty_address:
        return DatabaseErrorCode.ERR_INVALID_PARAM, False

    try:
        cursor = handle.connection.cursor()
        normalized_email = pretty_address.strip().lower()

        # Update ke waqt hum current user ko exclude karte hain comparison se
        if exclude_sn is not None:
            cursor.execute("""
                SELECT 1 FROM Users
                WHERE LOWER(auto_address) = ?
                AND SerialNumber != ?
                LIMIT 1
            """, (normalized_email, exclude_sn))
        else:
            cursor.execute("""
                SELECT 1 FROM Users
                WHERE LOWER(auto_address) = ?
                LIMIT 1
            """, (normalized_email,))

        exists = cursor.fetchone() is not None
        return DatabaseErrorCode.SUCCESS, exists

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", f"Failed to check email exists: {pretty_address}", str(e))
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

def store_server(handle: Any, server: Dict[str, Any]) -> Tuple[DatabaseErrorCode, Optional[int]]:
    """
    Store or update a QMail server record manually.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()
        server_id = server.get('server_id')
        
        # Note: This uses INSERT OR REPLACE which resets flags like UseForParity to default (0)
        cursor.execute("""
            INSERT OR REPLACE INTO Servers
            (ServerID, IPAddress, Port, ServerType, LastSeen, IsAvailable, CostPerMB, CostPer8Weeks)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            server_id,
            server.get('ip_address', ''),
            server.get('port', 50000),
            server.get('server_type', 'QMAIL'),
            int(time.time()),
            1,
            server.get('cost_per_mb', 1.0),
            server.get('cost_per_8_weeks', 1.0)
        ))

        # We generally track by ServerID (text), but if rowid is needed:
        row_id = cursor.lastrowid
        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS, row_id

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


def update_contact_stats(handle: DatabaseHandle, serial_number: int) -> bool:
    """
    Update contact statistics using the numeric SerialNumber as the key.
    """
    if handle is None or handle.connection is None or not isinstance(serial_number, int):
        return False

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            UPDATE Users
            SET contact_count = contact_count + 1,
                last_contacted_timestamp = datetime('now')
            WHERE SerialNumber = ?
        """, (serial_number,))
        handle.connection.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Stats update failed", str(e))
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
    handle: Any,
    folder: str = 'inbox',
    limit: int = 50,
    offset: int = 0,
    include_trashed: bool = False
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    List emails with Pretty Address of the sender/recipient.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_debug

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # Inbox logic pulls from received_tells (notifications)
        if folder == 'inbox':
            cursor.execute("""
                SELECT file_guid as EmailID, tell_type, created_at as ReceivedTimestamp, download_status
                FROM received_tells
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            
            emails = []
            for row in rows:
                emails.append({
                    'EmailID': row['EmailID'],
                    'Subject': f"New Mail ({row['EmailID'][:8]})",
                    'ReceivedTimestamp': row['ReceivedTimestamp'],
                    'is_read': bool(row['download_status']),
                    'folder': 'inbox'
                })
        else:
            # Sent/Drafts/Trash query with JOIN to get Pretty Name
            # We join with Junction table to find the main contact for the summary
            cursor.execute("""
                SELECT 
                    e.EmailID, e.Subject, e.ReceivedTimestamp, e.SentTimestamp,
                    e.is_read, e.is_starred, e.is_trashed, e.folder,
                    u.auto_address as contact_pretty
                FROM Emails e
                LEFT JOIN Junction_Email_Users j ON e.EmailID = j.EmailID 
                LEFT JOIN Users u ON j.SerialNumber = u.SerialNumber
                WHERE e.folder = ? 
                  AND (e.is_trashed = 0 OR e.is_trashed = ?)
                  AND (j.user_type = 'TO' OR j.user_type = 'FROM')
                GROUP BY e.EmailID
                ORDER BY e.ReceivedTimestamp DESC
                LIMIT ? OFFSET ?
            """, (folder, int(include_trashed), limit, offset))
            
            rows = cursor.fetchall()
            emails = [dict(row) for row in rows]
            for e in emails:
                e['is_read'] = bool(e['is_read'])
                e['is_starred'] = bool(e['is_starred'])
                e['is_trashed'] = bool(e['is_trashed'])

        log_debug(handle.logger, "Database", f"Listed {len(emails)} emails from '{folder}'")
        return DatabaseErrorCode.SUCCESS, emails

    except sqlite3.Error as e:
        return DatabaseErrorCode.ERR_INTERNAL, []

def list_drafts(handle, page: int = 1, limit: int = 50) -> Tuple[Any, List[Dict[str, Any]], int]:
    """
    List drafts with pagination and recipient preview.
    FIXED: Corrected JOIN logic to use 'SerialNumber' instead of 'UserID'.
    FIXED: Robust EmailID hex conversion for API handlers.
    """
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, [], 0

    # 1. PARAMETER NORMALIZATION
    page = max(1, page)
    limit = max(1, min(limit, 200))
    offset = (page - 1) * limit

    try:
        # Dictionary format mein results lene ke liye
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()

        # 2. GET TOTAL COUNT (Excluding trashed)
        cursor.execute("""
            SELECT COUNT(*) as total 
            FROM Emails 
            WHERE folder = 'drafts' AND is_trashed = 0
        """)
        row = cursor.fetchone()
        total_count = row['total'] if row else 0

        # 3. FETCH DRAFTS WITH RECIPIENT PREVIEW
        # FIXED: Joined on 'SerialNumber' to match the active schema
        cursor.execute("""
            SELECT
                e.EmailID, 
                e.Subject, 
                e.ReceivedTimestamp, 
                e.SentTimestamp,
                e.Body, 
                e.is_starred, 
                e.is_read,
                (SELECT COUNT(*) FROM Junction_Email_Users j
                 WHERE j.EmailID = e.EmailID AND j.user_type = 'TO') as recipient_count,
                (SELECT u.FirstName || ' ' || COALESCE(u.LastName, '')
                 FROM Junction_Email_Users j
                 JOIN Users u ON j.SerialNumber = u.SerialNumber
                 WHERE j.EmailID = e.EmailID AND j.user_type = 'TO'
                 LIMIT 1) as first_recipient_name
            FROM Emails e
            WHERE e.folder = 'drafts' AND e.is_trashed = 0
            ORDER BY e.SentTimestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        drafts = []
        for row in cursor.fetchall():
            # --- THE HEX BRIDGE: Robust Conversion ---
            # EmailID BLOB ko string mein badalna laazmi hai JSON ke liye
            raw_id = row['EmailID']
            email_id_hex = ""
            if isinstance(raw_id, bytes):
                email_id_hex = raw_id.hex()
            elif isinstance(raw_id, str):
                email_id_hex = raw_id
            
            # API Handler ki umeed ke mutabiq keys set karna
            drafts.append({
                'id': email_id_hex,
                'subject': row['Subject'] if row['Subject'] else "(No Subject)",
                'body': row['Body'] if row['Body'] else "",
                'received_timestamp': row['ReceivedTimestamp'],
                'sent_timestamp': row['SentTimestamp'],
                'is_read': bool(row['is_read']),
                'is_starred': bool(row['is_starred']),
                'recipient_count': row['recipient_count'],
                'first_recipient': row['first_recipient_name'] if row['first_recipient_name'] else "No Recipient"
            })

        return DatabaseErrorCode.SUCCESS, drafts, total_count

    except sqlite3.Error as e:
        if hasattr(handle, 'logger'):
            log_error(handle.logger, "DATABASE", "Draft list query failed", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, [], 0

def search_emails(
    handle: Any,
    search_term: str,
    limit: int = 50,
    offset: int = 0
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Search emails using FTS5 and return snippets.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None or not search_term:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()
        safe_term = search_term.replace('"', '""').strip()

        query = """
            SELECT e.EmailID, e.Subject, e.ReceivedTimestamp, e.is_read, e.folder,
                   u.auto_address as sender_pretty,
                   snippet(Emails_FTS, 1, '<mark>', '</mark>', '...', 32) as snippet
            FROM Emails_FTS
            JOIN Emails e ON Emails_FTS.rowid = e.rowid
            LEFT JOIN Junction_Email_Users j ON e.EmailID = j.EmailID AND j.user_type = 'FROM'
            LEFT JOIN Users u ON j.SerialNumber = u.SerialNumber
            WHERE Emails_FTS MATCH ?
            ORDER BY rank
            LIMIT ? OFFSET ?
        """

        cursor.execute(query, (f'"{safe_term}"', limit, offset))
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            res = dict(row)
            res['EmailID'] = row['EmailID'].hex()
            res['is_read'] = bool(row['is_read'])
            results.append(res)

        return DatabaseErrorCode.SUCCESS, results

    except sqlite3.Error as e:
        log_error(handle.logger, "Database", f"Search failed: {search_term}", str(e))
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

        # Query 1: Downloaded emails (standard folders) - exclude trashed
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

        # Query 2: Pending tells (not yet downloaded) - count as inbox
        cursor.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN read_status = 0 THEN 1 ELSE 0 END) as unread
            FROM received_tells
            WHERE download_status = 0
        """)

        tells_row = cursor.fetchone()
        if tells_row:
            counts['inbox']['total'] += tells_row['total'] or 0
            counts['inbox']['unread'] += tells_row['unread'] or 0

        # Query 3: Trash folder - count all trashed emails regardless of original folder
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
    

def get_user_payment_requirement(
    handle: Any, 
    serial_number: Union[int, str]
) -> Tuple[DatabaseErrorCode, Optional[float], Optional[str]]:
    """
    Look up a user's InboxFee and Class using their strict decoded SerialNumber.
    REMOVED FALLBACK: Ensures no collisions between '23' and 'C23'.
    """
    import sqlite3
    from protocol import custom_sn_to_int
    from database import DatabaseErrorCode

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None, None
    
    try:
        # 1. Decode to strict numeric SN (e.g., 'C23' -> 2841)
        # Agar numeric_sn galat hua toh lookup fail hona chahiye, fallback nahi
        target_numeric_sn = custom_sn_to_int(serial_number)
        
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()
        
        # 2. Strict Integer Query
        # SerialNumber column must contain the decoded integer (e.g., 2841)
        cursor.execute("""
            SELECT InboxFee, Class
            FROM Users
            WHERE SerialNumber = ?
        """, (target_numeric_sn,))
        
        row = cursor.fetchone()
        
        if not row:
            # Safer to fail than to pay the wrong person
            return DatabaseErrorCode.ERR_NOT_FOUND, None, None
        
        return DatabaseErrorCode.SUCCESS, row['InboxFee'], row['Class']
        
    except Exception as e:
        from src.logger import log_error
        log_error(handle.logger, "Database", "Strict lookup failed", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None, None
# ============================================================================
# USER AND SERVER SYNC FUNCTIONS (For data_sync.py integration)
# ============================================================================

def upsert_user(handle: Any, user_data: Dict[str, Any]) -> DatabaseErrorCode:
    """
    Inserts or updates a user from the RAIDA directory.
    FIXED: Aligned dictionary keys with parse_users_csv and added all Phase II columns.
    """
    import sqlite3
    # Inner import to prevent circular dependency with data_sync
    from data_sync import convert_to_custom_base32 
    from database import DatabaseErrorCode

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    # Mapping logic from parse_users_csv keys to database columns
    sn = int(user_data.get('serial_number', 0))
    dn = int(user_data.get('denomination', 0))
    custom_sn = user_data.get('custom_sn', '')
    
    # Pretty Address (Already generated in data_sync, but we fallback just in case)
    pretty_email = user_data.get('auto_address')
    if not pretty_email:
        first = user_data.get('first_name', 'User').strip().replace(' ', '.')
        last = user_data.get('last_name', '').strip().replace(' ', '.')
        desc = user_data.get('description', 'Member').strip().replace(' ', '.')
        base32_sn = custom_sn if custom_sn else convert_to_custom_base32(sn)
        class_map = {0: "Bit", 1: "Byte", 2: "Kilo", 3: "Mega", 4: "Giga"}
        user_class = user_data.get('class', class_map.get(dn, "Coin")).capitalize()
        pretty_email = f"{first}.{last}@{desc}#{base32_sn}.{user_class}"

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            INSERT INTO Users (
                SerialNumber, Denomination, CustomSerialNumber, 
                FirstName, LastName, auto_address, Description, 
                InboxFee, Class, Beacon
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(SerialNumber) DO UPDATE SET
                Denomination=excluded.Denomination,
                CustomSerialNumber=excluded.CustomSerialNumber,
                FirstName=excluded.FirstName,
                LastName=excluded.LastName,
                auto_address=excluded.auto_address,
                Description=excluded.Description,
                InboxFee=excluded.InboxFee,
                Class=excluded.Class,
                Beacon=excluded.Beacon
        """, (
            sn, dn, custom_sn,
            user_data.get('first_name'), user_data.get('last_name'),
            pretty_email, user_data.get('description'), 
            user_data.get('inbox_fee', 0.0), 
            user_data.get('class', 'Coin'), 
            user_data.get('beacon', 'RAIDA11')
        ))
        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS
    except sqlite3.Error as e:
        # Optionally log the error if handle.logger exists
        return DatabaseErrorCode.ERR_QUERY_FAILED

def upsert_server(handle: Any, server: Dict[str, Any]) -> DatabaseErrorCode:
    """
    Insert or update a QMail server from remote sync data.
    Matches 'Server Host File' fields to 'Servers' table.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    server_id = server.get('server_id')
    if not server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        
        # timestamp for LastSeen/SyncedAt
        now = int(time.time())

        # Extract values
        s_idx = server.get('server_index', 0)
        ip = server.get('ip_address', '')
        port = server.get('port', 50000)
        s_type = server.get('server_type', 'QMAIL')
        
        # Costs (Handle defaults)
        c_mb = float(server.get('cost_per_mb', 1.0))
        c_8w = float(server.get('cost_per_8_weeks', 1.0))
        
        uptime = server.get('percent_uptime', 100)
        perf = server.get('performance_benchmark_percentile', 0)
        region = server.get('region', '')
        desc = server.get('description', '')
        date_created = server.get('date_created', '')

        # Use UPSERT logic to preserve UseForParity if it exists
        sql = """
            INSERT INTO Servers (
                ServerID, ServerIndex, IPAddress, Port, ServerType,
                CostPerMB, CostPer8Weeks, PercentUptime, PerformancePercentile,
                Region, Description, IsAvailable, LastSeen, UseForParity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0)
            ON CONFLICT(ServerID) DO UPDATE SET
                ServerIndex=excluded.ServerIndex,
                IPAddress=excluded.IPAddress,
                Port=excluded.Port,
                CostPerMB=excluded.CostPerMB,
                CostPer8Weeks=excluded.CostPer8Weeks,
                PercentUptime=excluded.PercentUptime,
                PerformancePercentile=excluded.PerformancePercentile,
                Region=excluded.Region,
                Description=excluded.Description,
                LastSeen=excluded.LastSeen
        """
        
        cursor.execute(sql, (
            server_id, s_idx, ip, port, s_type,
            c_mb, c_8w, uptime, perf,
            region, desc, now
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
    Search users for autocomplete. FIXED: Matches on Pretty Format and returns Class.
    """
    if handle is None or handle.connection is None or not query:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()
        pattern = f"%{query.strip()}%"

        # Search in Name, Pretty Address, or Description
        cursor.execute("""
            SELECT SerialNumber, FirstName, LastName, auto_address, Description, Class, Beacon
            FROM Users
            WHERE FirstName LIKE ? OR LastName LIKE ? OR auto_address LIKE ? OR Description LIKE ?
            ORDER BY
                CASE
                    WHEN FirstName LIKE ? THEN 1
                    WHEN auto_address LIKE ? THEN 2
                    ELSE 3
                END, FirstName ASC
            LIMIT ?
        """, (pattern, pattern, pattern, pattern, f"{query.strip()}%", f"{query.strip()}%", limit))

        users = [dict(row) for row in cursor.fetchall()]
        log_debug(handle.logger, DB_CONTEXT, f"Search '{query}' found {len(users)} users")
        return DatabaseErrorCode.SUCCESS, users
    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "User search failed", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []

def get_all_servers(
    handle: DatabaseHandle,
    available_only: bool = True
) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get all QMail servers from database.
    Updated to match 'Servers' schema and 'cost_per_8_weeks' requirement.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()

        sql = """
            SELECT ServerID, ServerIndex, IPAddress, Port, ServerType,
                   CostPerMB, CostPer8Weeks, PingMS, PercentUptime, 
                   PerformancePercentile, IsAvailable, UseForParity, LastSeen,
                   Region, Description
            FROM Servers
        """
        if available_only:
            sql += " WHERE IsAvailable = 1"
        sql += " ORDER BY ServerIndex ASC"

        cursor.execute(sql)
        servers = []
        for row in cursor.fetchall():
            servers.append({
                'server_id': row['ServerID'],
                'server_index': row['ServerIndex'],
                'ip_address': row['IPAddress'],
                'port': row['Port'],
                'server_type': row['ServerType'],
                'cost_per_mb': row['CostPerMB'],
                'cost_per_8_weeks': row['CostPer8Weeks'],  # Crucial for payment.py
                'ping_ms': row['PingMS'],
                'percent_uptime': row['PercentUptime'],
                'performance_benchmark_percentile': row['PerformancePercentile'],
                'is_available': bool(row['IsAvailable']),
                'use_for_parity': bool(row['UseForParity']),
                'last_checked': row['LastSeen'],
                'region': row['Region'],
                'description': row['Description']
            })

        return DatabaseErrorCode.SUCCESS, servers

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get servers", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []


def get_stripe_servers(handle: Any) -> Tuple[DatabaseErrorCode, List[Dict[str, Any]]]:
    """
    Get servers to use for data stripes (excludes designated parity server).
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, []

    try:
        cursor = handle.connection.cursor()
        
        # Select servers that are Available AND NOT Parity
        cursor.execute("""
            SELECT ServerID, ServerIndex, IPAddress, Port, ServerType, IsAvailable
            FROM Servers
            WHERE IsAvailable = 1 AND UseForParity = 0
            ORDER BY ServerIndex ASC
        """)

        servers = []
        for row in cursor.fetchall():
            servers.append({
                'server_id': row['ServerID'],
                'server_index': row['ServerIndex'],
                'ip_address': row['IPAddress'],
                'port': row['Port'],
                'server_type': row['ServerType'],
                'is_available': bool(row['IsAvailable'])
            })

        return DatabaseErrorCode.SUCCESS, servers

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get stripe servers", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, []

def get_parity_server(handle: Any) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get the designated parity server.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = handle.connection.cursor()

        cursor.execute("""
            SELECT ServerID, ServerIndex, IPAddress, Port, ServerType,
                   PingMS, IsAvailable
            FROM Servers
            WHERE UseForParity = 1
            LIMIT 1
        """)

        row = cursor.fetchone()
        if row is None:
            return DatabaseErrorCode.SUCCESS, None

        server = {
            'server_id': row['ServerID'],
            'server_index': row['ServerIndex'],
            'ip_address': row['IPAddress'],
            'port': row['Port'],
            'server_type': row['ServerType'],
            'ping_ms': row['PingMS'],
            'is_available': bool(row['IsAvailable'])
        }

        return DatabaseErrorCode.SUCCESS, server

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to get parity server", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED, None
    
def set_parity_server(handle: Any, server_id: str) -> DatabaseErrorCode:
    """
    Designate a server as the parity server.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM
    if not server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()

        # Clear existing
        cursor.execute("UPDATE Servers SET UseForParity = 0")

        # Set new
        cursor.execute("UPDATE Servers SET UseForParity = 1 WHERE ServerID = ?", (server_id,))

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
    handle: Any,
    server_id: str,
    is_available: bool,
    ping_ms: int = None
) -> DatabaseErrorCode:
    """
    Update server availability status.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM
    if not server_id:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        now = int(time.time())

        if ping_ms is not None:
            cursor.execute("""
                UPDATE Servers
                SET IsAvailable = ?, PingMS = ?, LastSeen = ?
                WHERE ServerID = ?
            """, (1 if is_available else 0, ping_ms, now, server_id))
        else:
            cursor.execute("""
                UPDATE Servers
                SET IsAvailable = ?, LastSeen = ?
                WHERE ServerID = ?
            """, (1 if is_available else 0, now, server_id))

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, f"Failed to update status for {server_id}", str(e))
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


def get_server_count(handle: Any) -> Tuple[DatabaseErrorCode, int]:
    """
    Get total count of servers in database.
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, 0

    try:
        cursor = handle.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM Servers")
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
        cursor.execute("SELECT * FROM received_tells WHERE file_guid = ?", (file_guid.upper(),))
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
    
def update_payment_status(
    handle: DatabaseHandle,
    file_guid: str,
    payment_status: int
) -> DatabaseErrorCode:
    """
    Update payment status for a received tell.
    
    Args:
        handle: Database handle
        file_guid: File GUID
        payment_status: 0=no payment, 1=claimed, 2=failed
    """
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor()
        cursor.execute("""
            UPDATE received_tells
            SET payment_status = ?
            WHERE file_guid = ?
        """, (payment_status, file_guid))

        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(handle.logger, DB_CONTEXT, "Failed to update payment status", str(e))
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
    server_list_json: str,
    beacon_locker_hex: str = None,
    inbox_locker_hex: str = None
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
             LockerCode, BeaconLockerHex, InboxLockerHex, ServerListJSON, Status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (file_group_guid, recipient_address, recipient_type, beacon_server_id,
              locker_code, beacon_locker_hex, inbox_locker_hex, server_list_json))

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
                   BeaconServerID, LockerCode, BeaconLockerHex, InboxLockerHex,
                   ServerListJSON, CreatedTimestamp, RetryCount,
                   LastAttemptTimestamp, ErrorMessage, Status
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
                'beacon_locker_hex': row['BeaconLockerHex'],     
                'inbox_locker_hex': row['InboxLockerHex'],       
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
    handle: Any, 
    qmail_address: str
) -> Tuple[DatabaseErrorCode, Optional[Dict[str, Any]]]:
    """
    Get full user info by their Pretty Email Address OR Technical Address.
    FIXED: Explicitly returns 'denomination' which is required for technical addressing.
    """
    import sqlite3
    # Ensure these are available/imported
    # from src.database import DatabaseErrorCode
    # from src.logger import log_error

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    if not qmail_address:
        return DatabaseErrorCode.ERR_INVALID_PARAM, None

    try:
        # 1. Enable dictionary-like access
        handle.connection.row_factory = sqlite3.Row
        cursor = handle.connection.cursor()
        
        target_sn = None
        user_row = None

        # 2. Strategy A: Direct Lookup (Pretty Address)
        cursor.execute("""
            SELECT 
                SerialNumber, Denomination, CustomSerialNumber, 
                FirstName, LastName, auto_address, Description, 
                InboxFee, Class, Beacon
            FROM Users 
            WHERE auto_address = ?
        """, (qmail_address.strip(),))
        user_row = cursor.fetchone()

        # 3. Strategy B: Extract Serial Number from Technical String
        if user_row is None:
            clean_addr = qmail_address.strip()
            
            # Check for Dot-Delimited String (e.g. "0006.4.12355")
            parts = clean_addr.split('.')
            if len(parts) >= 2 and parts[-1].isdigit():
                try:
                    target_sn = int(parts[-1])
                except ValueError:
                    pass
            # Check for pure Integer string
            elif clean_addr.isdigit():
                target_sn = int(clean_addr)
            # Check for Custom Serial Number (e.g. "C23")
            else:
                cursor.execute("SELECT * FROM Users WHERE CustomSerialNumber = ?", (clean_addr,))
                user_row = cursor.fetchone()

            # If we found an SN, look up by Primary Key
            if target_sn is not None and user_row is None:
                cursor.execute("SELECT * FROM Users WHERE SerialNumber = ?", (target_sn,))
                user_row = cursor.fetchone()

        if user_row is None:
            return DatabaseErrorCode.ERR_NOT_FOUND, None

        # 4. CRITICAL FIX: Return a standardized dictionary with ALL required keys
        # We use lowercase keys to match Python standards
        user = {
            'serial_number': user_row['SerialNumber'],
            'denomination': user_row['Denomination'],  # <--- THIS WAS MISSING
            'custom_sn': user_row['CustomSerialNumber'],
            'first_name': user_row['FirstName'],
            'last_name': user_row['LastName'],
            'auto_address': user_row['auto_address'],
            'description': user_row['Description'],
            'inbox_fee': user_row['InboxFee'] if user_row['InboxFee'] is not None else 0.0,
            'class': user_row['Class'],
            'beacon_id': user_row['Beacon']
        }

        return DatabaseErrorCode.SUCCESS, user

    except sqlite3.Error as e:
        # log_error(handle.logger, "Database", f"Failed to get user {qmail_address}", str(e))
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
    """
    Checks if a GUID has already been cached in the database.
    FIXED: Converts binary GUID to Hex string for reliable comparison.
    """
    if not handle or not handle.connection:
        return False
        
    try:
        # 1. Binary ko Hex mein convert karo
        if isinstance(file_guid, bytes):
            guid_hex = file_guid.hex().upper()
        else:
            guid_hex = str(file_guid).upper()
            
        cursor = handle.connection.cursor()
        
        # 2. Database mein search karo
        cursor.execute("SELECT 1 FROM received_tells WHERE file_guid = ?", (guid_hex,))
        return cursor.fetchone() is not None
        
    except Exception:
        return False


def store_received_tell(
    handle: DatabaseHandle,
    file_guid: Any, 
    locker_code: bytes,
    tell_type: int = 0,
    sender_sn: int = 0,
    version: int = 1,
    file_size: int = 0,
    status: str = 'pending',
    total_file_size: int = 0
) -> Tuple[DatabaseErrorCode, int]:
    """
    Store a received tell notification in the database.
    FIXED: Converts both GUID and Locker Code to Hex strings.
    """
    import sqlite3
    
    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    if not file_guid or locker_code is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM, -1

    # 1. CONVERT TO HEX: Dono ko string format mein lana zaroori hai
    guid_hex = file_guid.hex().upper() if isinstance(file_guid, bytes) else str(file_guid).upper()
    locker_code_hex = locker_code.hex().upper() if isinstance(locker_code, bytes) else str(locker_code).upper()

    try:
        cursor = handle.connection.cursor()
        
        # 2. INSERT OR REPLACE: Duplicate GUID aane par ye record ko refresh kar dega
       
        cursor.execute("""
            INSERT OR REPLACE INTO received_tells
            (file_guid, locker_code, tell_type, sender_sn, total_file_size)
            VALUES (?, ?, ?, ?, ?)
        """, (guid_hex, locker_code_hex, tell_type, sender_sn, total_file_size))

        handle.connection.commit()
        tell_id = cursor.lastrowid

        from src.logger import log_info
        log_info(handle.logger, "Database", f"✓ Stored notification: {guid_hex}, id={tell_id}")
        return DatabaseErrorCode.SUCCESS, tell_id

    except sqlite3.Error as e:
        from src.logger import log_error
        log_error(handle.logger, "Database", "Failed to store received tell", str(e))
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

def store_sent_email_metadata(
    handle: DatabaseHandle, # Corrected type hint
    file_guid: str,
    subject: str,
    recipients: str,
    body: str,
    timestamp: int,
    stripe_count: int
) -> DatabaseErrorCode:
    """
    Store sent email metadata in the SQL database.
    FIXED: Uses handle.connection and correct logger API.
    """
    import sqlite3
    from src.database import DatabaseErrorCode
    from src.logger import log_error

    if handle is None or handle.connection is None:
        return DatabaseErrorCode.ERR_INVALID_PARAM

    try:
        cursor = handle.connection.cursor() # <--- FIXED: Added .connection
        
        # We store the first 200 chars as body_preview in the sent table
        body_preview = body[:200] if body else ""

        cursor.execute("""
            INSERT INTO sent_emails 
            (file_guid, subject, recipients, body_preview, timestamp, stripe_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (file_guid, subject, recipients, body_preview, timestamp, stripe_count))
        
        handle.connection.commit()
        return DatabaseErrorCode.SUCCESS
        
    except sqlite3.Error as e:
        log_error(handle.logger, "DatabaseMod", "Failed to store sent email metadata", str(e))
        return DatabaseErrorCode.ERR_QUERY_FAILED


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
