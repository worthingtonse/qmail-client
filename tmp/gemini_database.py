"""
gemini_database.py - Database Module for QMail Client Core (v2)

This module provides an interface for all SQLite database operations.
Version 2 incorporates superior design ideas from peer review, such as
a more detailed schema and more sophisticated query logic, while maintaining
adherence to the project's shared type system.

Author: Gemini
Phase: I
"""

import sqlite3
import os
from typing import List, Optional, Any, Dict

from . import logger
from .qmail_types import Email, User, Attachment

# Global logger instance
log = logger.init_logger(os.path.join('..', 'logs', 'gemini_database_v2.log'))

# --- SQL SCHEMA (v2) ---
# Incorporates ideas from opus45_database.py for better user/flag management
DB_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY,
    FirstName TEXT,
    MiddleName TEXT,
    LastName TEXT,
    Avatar BLOB,
    streak INTEGER DEFAULT 0,
    sending_fee TEXT,
    Description TEXT,
    auto_address TEXT,
    last_contacted_timestamp DATETIME,
    contact_count INTEGER DEFAULT 0
);

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

CREATE VIRTUAL TABLE IF NOT EXISTS Emails_FTS USING fts5(
    Subject,
    Body,
    content='Emails',
    content_rowid='rowid' -- Using rowid is generally safer for FTS
);

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

CREATE TABLE IF NOT EXISTS Junction_Email_Users (
    EmailID BLOB,
    UserID INTEGER,
    user_type TEXT CHECK(user_type IN ('TO', 'CC', 'BC', 'FROM')),
    PRIMARY KEY (EmailID, UserID, user_type),
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE,
    FOREIGN KEY(UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Attachments (
    Attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    EmailID BLOB,
    name TEXT,
    file_extension TEXT,
    storage_mode TEXT CHECK(storage_mode IN ('INTERNAL', 'EXTERNAL')),
    status TEXT,
    data_blob BLOB,
    file_path TEXT,
    FOREIGN KEY(EmailID) REFERENCES Emails(EmailID) ON DELETE CASCADE
);
"""

def init_database(db_path: str) -> Optional[sqlite3.Connection]:
    """Initializes the database, creating tables if they don't exist."""
    try:
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.executescript(DB_SCHEMA)
        conn.commit()
        logger.log_info(log, f"Database v2 initialized successfully at {db_path}")
        return conn
    except sqlite3.Error as e:
        logger.log_error(log, f"Database v2 initialization failed: {e}")
        return None

def close_database(handle: sqlite3.Connection) -> None:
    """Closes the database connection."""
    if handle:
        try:
            handle.commit()
            handle.close()
            logger.log_info(log, "Database connection closed.")
        except sqlite3.Error as e:
            logger.log_error(log, f"Error closing database: {e}")

def store_email(handle: sqlite3.Connection, email: Email) -> Optional[bytes]:
    """Stores a complete email dataclass object in the database."""
    if not email.EmailID:
        logger.log_error(log, "Cannot store email with no EmailID.")
        return None
    try:
        cursor = handle.cursor()
        cursor.execute(
            "INSERT INTO Emails (EmailID, Subject, Body, ReceivedTimestamp, SentTimestamp, Meta, Style, is_read, is_starred, is_trashed, folder) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (email.EmailID, email.Subject, email.Body, email.ReceivedTimestamp, email.SentTimestamp, email.Meta, email.Style, email.is_read, email.is_starred, email.is_trashed, email.folder)
        )
        for att in email.attachments:
            cursor.execute(
                "INSERT INTO Attachments (EmailID, name, file_extension, storage_mode, status, data_blob, file_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (email.EmailID, att.name, att.file_extension, att.storage_mode, att.status, att.data_blob, att.file_path)
            )
        for user in email.recipients:
            store_contact(handle, user) # Ensure user exists
            update_contact_stats(handle, user.UserID) # Update popularity stats
            cursor.execute(
                "INSERT INTO Junction_Email_Users (EmailID, UserID, user_type) VALUES (?, ?, ?)",
                (email.EmailID, user.UserID, 'TO')
            )
        handle.commit()
        logger.log_info(log, f"Successfully stored email {email.EmailID.hex()}.")
        return email.EmailID
    except sqlite3.Error as e:
        logger.log_error(log, f"Error storing email {email.EmailID.hex()}: {e}. Rolling back.")
        handle.rollback()
        return None

def retrieve_email(handle: sqlite3.Connection, email_id: bytes) -> Optional[Email]:
    """Retrieves a single, complete email object from the database by its ID."""
    try:
        handle.row_factory = sqlite3.Row
        cursor = handle.cursor()
        cursor.execute("SELECT * FROM Emails WHERE EmailID = ?", (email_id,))
        email_row = cursor.fetchone()
        if not email_row:
            return None

        cursor.execute("SELECT * FROM Attachments WHERE EmailID = ?", (email_id,))
        attachments = [Attachment(**dict(row)) for row in cursor.fetchall()]

        cursor.execute("SELECT u.* FROM Users u JOIN Junction_Email_Users jeu ON u.UserID = jeu.UserID WHERE jeu.EmailID = ? AND jeu.user_type = 'TO'", (email_id,))
        recipients = [User(**dict(row)) for row in cursor.fetchall()]
        
        email_data = dict(email_row)
        # Convert integer flags back to booleans
        email_data['is_read'] = bool(email_data.get('is_read', 0))
        email_data['is_starred'] = bool(email_data.get('is_starred', 0))
        email_data['is_trashed'] = bool(email_data.get('is_trashed', 0))
        email_data['attachments'] = attachments
        email_data['recipients'] = recipients

        logger.log_debug(log, f"Retrieved email {email_id.hex()}.")
        return Email(**email_data)
    except sqlite3.Error as e:
        logger.log_error(log, f"Error retrieving email {email_id.hex()}: {e}")
        return None
    finally:
        handle.row_factory = None

def store_contact(handle: sqlite3.Connection, contact: User) -> Optional[int]:
    """Stores a contact (User dataclass) in the database. Uses INSERT OR REPLACE."""
    try:
        cursor = handle.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO Users (UserID, FirstName, MiddleName, LastName, Avatar, streak, sending_fee, Description, auto_address, last_contacted_timestamp, contact_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (contact.UserID, contact.FirstName, contact.MiddleName, contact.LastName, contact.Avatar, contact.streak, contact.sending_fee, contact.Description, contact.auto_address, contact.last_contacted_timestamp, contact.contact_count)
        )
        handle.commit()
        logger.log_info(log, f"Stored contact with UserID {contact.UserID}.")
        return contact.UserID
    except sqlite3.Error as e:
        logger.log_error(log, f"Error storing contact {contact.UserID}: {e}. Rolling back.")
        handle.rollback()
        return None

def get_popular_contacts(handle: sqlite3.Connection, limit: int) -> List[User]:
    """
    Gets most popular contacts based on a decaying popularity algorithm.
    (Algorithm inspired by opus45_database)
    """
    try:
        handle.row_factory = sqlite3.Row
        cursor = handle.cursor()
        # Popularity formula: contact_count / (1 + days_since_last_contact * 0.1)
        cursor.execute("""
            SELECT *,
                CASE
                    WHEN last_contacted_timestamp IS NULL THEN 0
                    ELSE contact_count / (1.0 + (julianday('now') - julianday(last_contacted_timestamp)) * 0.1)
                END AS popularity
            FROM Users
            ORDER BY popularity DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        popular_contacts = [User(**dict(row)) for row in rows]
        logger.log_debug(log, f"Retrieved {len(popular_contacts)} popular contacts.")
        return popular_contacts
    except sqlite3.Error as e:
        logger.log_error(log, f"Error getting popular contacts: {e}")
        return []
    finally:
        handle.row_factory = None

def update_email_flags(handle: sqlite3.Connection, email_id: bytes, flags: Dict[str, Any]) -> bool:
    """Updates email flags (is_read, is_starred, etc.) from a dictionary."""
    if not flags:
        return True
    try:
        cursor = handle.cursor()
        set_parts = []
        params = []
        valid_flags = ['is_read', 'is_starred', 'is_trashed', 'folder']
        for key, value in flags.items():
            if key in valid_flags:
                set_parts.append(f"{key} = ?")
                params.append(value)
        
        if not set_parts:
            logger.log_warning(log, "update_email_flags called with no valid flags.")
            return False

        params.append(email_id)
        query = f"UPDATE Emails SET {', '.join(set_parts)} WHERE EmailID = ?"
        cursor.execute(query, params)
        if cursor.rowcount == 0:
            logger.log_warning(log, f"Attempted to update flags for non-existent email {email_id.hex()}.")
            return False
        handle.commit()
        logger.log_info(log, f"Updated flags for email {email_id.hex()}.")
        return True
    except sqlite3.Error as e:
        logger.log_error(log, f"Error updating flags for email {email_id.hex()}: {e}. Rolling back.")
        handle.rollback()
        return False

def execute_query(handle: sqlite3.Connection, sql: str, params: tuple = ()) -> Optional[List[Any]]:
    """Executes an arbitrary SQL query with parameters."""
    try:
        cursor = handle.cursor()
        cursor.execute(sql, params)
        results = cursor.fetchall()
        if not sql.strip().upper().startswith("SELECT"):
            handle.commit()
        logger.log_debug(log, f"Executed query: {sql}")
        return results
    except sqlite3.Error as e:
        logger.log_error(log, f"Error executing query '{sql}': {e}")
        return None

def update_contact_stats(handle: sqlite3.Connection, user_id: int) -> bool:
    """
    Update contact stats after an interaction.
    (Helper function inspired by opus45_database)
    """
    try:
        cursor = handle.cursor()
        cursor.execute("""
            UPDATE Users
            SET contact_count = contact_count + 1,
                last_contacted_timestamp = datetime('now')
            WHERE UserID = ?
        """, (user_id,))
        handle.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.log_error(log, f"Failed to update contact stats for UserID {user_id}: {e}")
        handle.rollback()
        return False
