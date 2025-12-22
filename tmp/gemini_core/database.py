# gemini_core/database.py
# Manages the local SQLite database for email metadata and user settings.

import sqlite3
import logging
from typing import Tuple, Optional, Dict, Any, List

from .types import ErrorCode, DatabaseHandle

DB_PATH = "qmail_client.db"

def initialize() -> Tuple[ErrorCode, Optional[DatabaseHandle]]:
    """
    Connects to the SQLite database and creates tables if they don't exist.
    
    Returns:
        A tuple of (ErrorCode, DatabaseHandle). The handle is None on failure.
    """
    try:
        logging.info(f"Initializing database at {DB_PATH}...")
        conn = sqlite3.connect(DB_PATH)
        handle = DatabaseHandle(connection=conn)
        
        # Create tables
        _create_tables(handle)

        logging.info("Database initialized successfully.")
        return ErrorCode.SUCCESS, handle
    except sqlite3.Error as e:
        logging.error(f"Database error during initialization: {e}")
        return ErrorCode.ERR_DATABASE, None

def _create_tables(handle: DatabaseHandle):
    """Creates the necessary database tables if they don't already exist."""
    try:
        cursor = handle.connection.cursor()
        
        # Email metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT,
                sender TEXT,
                recipients TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Other tables (contacts, settings, etc.) could be added here
        
        handle.connection.commit()
        logging.info("Database tables verified/created.")
    except sqlite3.Error as e:
        logging.error(f"Failed to create database tables: {e}")
        # This is a critical error, might be worth raising or handling differently
        raise

def close_database(handle: DatabaseHandle) -> ErrorCode:
    """
    Closes the database connection.
    """
    if handle and handle.connection:
        try:
            handle.connection.close()
            logging.info("Database connection closed.")
            return ErrorCode.SUCCESS
        except sqlite3.Error as e:
            logging.error(f"Error while closing the database: {e}")
            return ErrorCode.ERR_DATABASE
    return ErrorCode.SUCCESS

def store_email_metadata(handle: DatabaseHandle, metadata: Dict[str, Any]) -> Tuple[ErrorCode, Optional[int]]:
    """
    Stores email metadata in the database.

    Args:
        handle: The active database handle.
        metadata: A dictionary with keys 'subject', 'sender', 'recipients'.

    Returns:
        A tuple of (ErrorCode, last_row_id). The ID is None on failure.
    """
    try:
        cursor = handle.connection.cursor()
        recipients_str = ",".join(metadata.get('recipients', []))
        
        cursor.execute(
            "INSERT INTO emails (subject, sender, recipients) VALUES (?, ?, ?)",
            (metadata.get('subject', ''), metadata.get('sender', ''), recipients_str)
        )
        
        handle.connection.commit()
        last_id = cursor.lastrowid
        logging.info(f"Stored email metadata with ID: {last_id}")
        return ErrorCode.SUCCESS, last_id
    except sqlite3.Error as e:
        logging.error(f"Failed to store email metadata: {e}")
        return ErrorCode.ERR_DATABASE, None

def search_emails(handle: DatabaseHandle, criteria: str) -> Tuple[ErrorCode, Optional[List[Dict]]]:
    """
    Performs a simple search on the emails table.

    Args:
        handle: The active database handle.
        criteria: The search term to look for in subject, sender, or recipients.

    Returns:
        A tuple of (ErrorCode, list_of_results). The list is None on failure.
    """
    try:
        cursor = handle.connection.cursor()
        term = f"%{criteria}%"
        
        cursor.execute(
            "SELECT id, subject, sender, recipients, timestamp FROM emails WHERE subject LIKE ? OR sender LIKE ? OR recipients LIKE ?",
            (term, term, term)
        )
        
        rows = cursor.fetchall()
        results = [
            {
                "id": row[0],
                "subject": row[1],
                "sender": row[2],
                "recipients": row[3].split(','),
                "timestamp": row[4]
            } for row in rows
        ]
        logging.info(f"Email search for '{criteria}' found {len(results)} results.")
        return ErrorCode.SUCCESS, results
    except sqlite3.Error as e:
        logging.error(f"Failed to search emails: {e}")
        return ErrorCode.ERR_DATABASE, None
