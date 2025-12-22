"""
sonnet45_search_engine.py - Search Engine for QMail Client Core

This module handles search queries for emails, contacts, and servers using
SQLite's FTS5 (Full-Text Search) capabilities. Designed for easy translation
to C (search_engine.c/search_engine.h) in Phase III.

Author: Claude Sonnet 4.5 (sonnet45)
Phase: I
Version: 1.0.0

Functions (from plan 4.9):
    build_query(search_query)            -> sql_string
    search_emails(db, query)             -> SearchResult
    search_contacts(db, query)           -> SearchResult
    index_email(db, email)               -> void
    rebuild_index(db)                    -> void

C Notes: Full-text search via SQLite FTS5 extension. This Python implementation
uses the FTS5 virtual tables already configured in database.py.
"""

import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
from enum import IntEnum
from dataclasses import dataclass, field

# Try to import from package, fall back to direct import for standalone testing
try:
    from .logger import log_info, log_error, log_warning, log_debug
    from .database import DatabaseHandle, DatabaseErrorCode
except ImportError:
    # Fallback for standalone testing
    def log_info(handle, msg): print(f"[INFO] {msg}")
    def log_error(handle, msg): print(f"[ERROR] {msg}")
    def log_warning(handle, msg): print(f"[WARNING] {msg}")
    def log_debug(handle, msg): print(f"[DEBUG] {msg}")

    # Mock DatabaseHandle and ErrorCode for testing
    class DatabaseErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_PARAM = 5
        ERR_QUERY_FAILED = 3
        ERR_NOT_FOUND = 4

    class DatabaseHandle:
        def __init__(self, connection, path, logger=None):
            self.connection = connection
            self.path = path
            self.logger = logger


# ============================================================================
# SEARCH ERROR CODES (C-style error handling)
# ============================================================================

class SearchErrorCode(IntEnum):
    """
    Error codes for search operations.
    C: typedef enum { SEARCH_SUCCESS = 0, ... } SearchErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_QUERY = 1
    ERR_SEARCH_FAILED = 2
    ERR_INDEX_FAILED = 3
    ERR_INVALID_PARAM = 4
    ERR_NOT_FOUND = 5


# ============================================================================
# SEARCH QUERY STRUCTURE
# ============================================================================

@dataclass
class SearchQuery:
    """
    Represents a search query with filters and options.
    C: typedef struct SearchQuery { ... } SearchQuery;
    """
    # Search terms
    terms: str = ""                          # Main search terms (FTS5 query)

    # Filters
    sender_filter: Optional[str] = None      # Filter by sender name/address
    recipient_filter: Optional[str] = None   # Filter by recipient
    date_from: Optional[str] = None          # ISO datetime string
    date_to: Optional[str] = None            # ISO datetime string
    folder: Optional[str] = None             # Filter by folder (inbox, sent, etc.)
    has_attachments: Optional[bool] = None   # Only emails with attachments
    is_read: Optional[bool] = None           # Filter by read status
    is_starred: Optional[bool] = None        # Filter by starred status

    # Options
    limit: int = 50                          # Maximum results to return
    offset: int = 0                          # Pagination offset
    sort_by: str = "relevance"               # relevance, date_desc, date_asc

    # Contact search specific
    first_name_filter: Optional[str] = None
    last_name_filter: Optional[str] = None
    auto_address_filter: Optional[str] = None


@dataclass
class SearchResult:
    """
    Represents search results with metadata.
    C: typedef struct SearchResult { ... } SearchResult;
    """
    items: List[Dict[str, Any]] = field(default_factory=list)
    total_count: int = 0                     # Total matching items (before limit)
    returned_count: int = 0                  # Number of items in this result
    elapsed_time_ms: float = 0.0             # Search execution time
    query: str = ""                          # The SQL query that was executed
    has_more: bool = False                   # True if more results available


# ============================================================================
# BUILD QUERY
# ============================================================================

def build_query(search_query: SearchQuery, search_type: str = "email") -> Tuple[SearchErrorCode, Optional[str], List[Any]]:
    """
    Build SQL query from SearchQuery object.

    Args:
        search_query: SearchQuery object with search parameters
        search_type: Type of search - "email", "contact", or "server"

    Returns:
        Tuple of (error_code, sql_string, params_list)
        Returns (ERROR, None, []) on invalid input

    C signature: SearchErrorCode build_query(const SearchQuery* query,
                                              SearchType type,
                                              char* out_sql,
                                              int sql_buffer_size,
                                              void** out_params,
                                              int* out_param_count);
    """
    if search_query is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None, []

    if search_type not in ["email", "contact", "server"]:
        return SearchErrorCode.ERR_INVALID_QUERY, None, []

    try:
        if search_type == "email":
            return _build_email_query(search_query)
        elif search_type == "contact":
            return _build_contact_query(search_query)
        elif search_type == "server":
            return _build_server_query(search_query)

        return SearchErrorCode.ERR_INVALID_QUERY, None, []

    except Exception as e:
        log_error(None, f"Failed to build query: {e}")
        return SearchErrorCode.ERR_INVALID_QUERY, None, []


def _build_email_query(sq: SearchQuery) -> Tuple[SearchErrorCode, str, List[Any]]:
    """
    Build SQL query for email search.
    Uses FTS5 for full-text search if terms are provided.
    """
    params = []

    # Determine if we should use FTS5 or regular query
    use_fts = bool(sq.terms and sq.terms.strip())

    if use_fts:
        # Use FTS5 for full-text search with relevance ranking
        query = """
            SELECT
                e.EmailID,
                e.Subject,
                e.Body,
                e.ReceivedTimestamp,
                e.SentTimestamp,
                e.is_read,
                e.is_starred,
                e.is_trashed,
                e.folder,
                fts.rank AS relevance_score
            FROM Emails e
            JOIN Emails_FTS fts ON e.rowid = fts.rowid
            WHERE Emails_FTS MATCH ?
        """
        params.append(sq.terms)
    else:
        # Regular query without FTS5
        query = """
            SELECT
                EmailID,
                Subject,
                Body,
                ReceivedTimestamp,
                SentTimestamp,
                is_read,
                is_starred,
                is_trashed,
                folder,
                0 AS relevance_score
            FROM Emails
            WHERE 1=1
        """

    # Add filters
    if sq.sender_filter:
        query += """
            AND EmailID IN (
                SELECT j.EmailID FROM Junction_Email_Users j
                JOIN Users u ON j.UserID = u.UserID
                WHERE j.user_type = 'FROM'
                AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
            )
        """
        filter_term = f"%{sq.sender_filter}%"
        params.extend([filter_term, filter_term, filter_term])

    if sq.recipient_filter:
        query += """
            AND EmailID IN (
                SELECT j.EmailID FROM Junction_Email_Users j
                JOIN Users u ON j.UserID = u.UserID
                WHERE j.user_type IN ('TO', 'CC')
                AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
            )
        """
        filter_term = f"%{sq.recipient_filter}%"
        params.extend([filter_term, filter_term, filter_term])

    if sq.date_from:
        query += " AND (ReceivedTimestamp >= ? OR SentTimestamp >= ?)"
        params.extend([sq.date_from, sq.date_from])

    if sq.date_to:
        query += " AND (ReceivedTimestamp <= ? OR SentTimestamp <= ?)"
        params.extend([sq.date_to, sq.date_to])

    if sq.folder:
        query += " AND folder = ?"
        params.append(sq.folder)

    if sq.is_read is not None:
        query += " AND is_read = ?"
        params.append(1 if sq.is_read else 0)

    if sq.is_starred is not None:
        query += " AND is_starred = ?"
        params.append(1 if sq.is_starred else 0)

    if sq.has_attachments is not None:
        if sq.has_attachments:
            query += " AND EmailID IN (SELECT DISTINCT EmailID FROM Attachments)"
        else:
            query += " AND EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)"

    # Add ORDER BY
    if sq.sort_by == "relevance" and use_fts:
        query += " ORDER BY relevance_score DESC"
    elif sq.sort_by == "date_desc":
        query += " ORDER BY COALESCE(ReceivedTimestamp, SentTimestamp) DESC"
    elif sq.sort_by == "date_asc":
        query += " ORDER BY COALESCE(ReceivedTimestamp, SentTimestamp) ASC"
    else:
        query += " ORDER BY COALESCE(ReceivedTimestamp, SentTimestamp) DESC"

    # Add LIMIT and OFFSET
    query += " LIMIT ? OFFSET ?"
    params.extend([sq.limit, sq.offset])

    return SearchErrorCode.SUCCESS, query, params


def _build_contact_query(sq: SearchQuery) -> Tuple[SearchErrorCode, str, List[Any]]:
    """
    Build SQL query for contact search.
    """
    params = []

    query = """
        SELECT
            UserID,
            FirstName,
            MiddleName,
            LastName,
            auto_address,
            Description,
            Avatar,
            contact_count,
            last_contacted_timestamp,
            CASE
                WHEN last_contacted_timestamp IS NULL THEN 0
                ELSE contact_count / (1.0 + (julianday('now') - julianday(last_contacted_timestamp)) * 0.1)
            END AS popularity
        FROM Users
        WHERE 1=1
    """

    # Full-text search in name or description
    if sq.terms:
        query += " AND (FirstName LIKE ? OR LastName LIKE ? OR Description LIKE ? OR auto_address LIKE ?)"
        search_term = f"%{sq.terms}%"
        params.extend([search_term, search_term, search_term, search_term])

    # Specific filters
    if sq.first_name_filter:
        query += " AND FirstName LIKE ?"
        params.append(f"%{sq.first_name_filter}%")

    if sq.last_name_filter:
        query += " AND LastName LIKE ?"
        params.append(f"%{sq.last_name_filter}%")

    if sq.auto_address_filter:
        query += " AND auto_address LIKE ?"
        params.append(f"%{sq.auto_address_filter}%")

    # Order by popularity or name
    if sq.sort_by == "relevance":
        query += " ORDER BY popularity DESC"
    else:
        query += " ORDER BY FirstName, LastName"

    # Add LIMIT and OFFSET
    query += " LIMIT ? OFFSET ?"
    params.extend([sq.limit, sq.offset])

    return SearchErrorCode.SUCCESS, query, params


def _build_server_query(sq: SearchQuery) -> Tuple[SearchErrorCode, str, List[Any]]:
    """
    Build SQL query for server search.
    """
    params = []

    query = """
        SELECT
            QMailServerID,
            IPAddress,
            PortNumb,
            server_type,
            ping_ms,
            number_of_calls,
            number_of_megabytes
        FROM QMailServers
        WHERE 1=1
    """

    # Search in IP or type
    if sq.terms:
        query += " AND (IPAddress LIKE ? OR server_type LIKE ?)"
        search_term = f"%{sq.terms}%"
        params.extend([search_term, search_term])

    # Order by ping time (fastest first) or calls
    if sq.sort_by == "relevance":
        query += " ORDER BY ping_ms ASC"
    else:
        query += " ORDER BY number_of_calls DESC"

    # Add LIMIT and OFFSET
    query += " LIMIT ? OFFSET ?"
    params.extend([sq.limit, sq.offset])

    return SearchErrorCode.SUCCESS, query, params


# ============================================================================
# SEARCH EMAILS
# ============================================================================

def search_emails(
    db: DatabaseHandle,
    query: SearchQuery
) -> Tuple[SearchErrorCode, Optional[SearchResult]]:
    """
    Search emails using FTS5 full-text search and filters.

    Args:
        db: Database handle
        query: SearchQuery object with search parameters

    Returns:
        Tuple of (error_code, SearchResult or None)

    C signature: SearchErrorCode search_emails(DatabaseHandle* db,
                                                const SearchQuery* query,
                                                SearchResult* out_result);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None

    if query is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None

    start_time = time.time()

    try:
        # Build query
        err, sql, params = build_query(query, "email")
        if err != SearchErrorCode.SUCCESS or sql is None:
            return err, None

        log_debug(db.logger, f"Executing email search: {query.terms}")

        cursor = db.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # Convert rows to dicts
        items = []
        for row in rows:
            email = {
                'email_id': row['EmailID'].hex() if row['EmailID'] else None,
                'subject': row['Subject'],
                'body': row['Body'],
                'received_timestamp': row['ReceivedTimestamp'],
                'sent_timestamp': row['SentTimestamp'],
                'is_read': bool(row['is_read']),
                'is_starred': bool(row['is_starred']),
                'is_trashed': bool(row['is_trashed']),
                'folder': row['folder'],
                'relevance_score': row['relevance_score']
            }

            # Fetch sender for each email
            email_id = row['EmailID']
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
            else:
                email['sender'] = None

            items.append(email)

        # Get total count (without LIMIT)
        # Note: For production, consider caching this or using COUNT(*) in main query
        total_count = len(rows)  # Simplified for now

        elapsed_ms = (time.time() - start_time) * 1000

        result = SearchResult(
            items=items,
            total_count=total_count,
            returned_count=len(items),
            elapsed_time_ms=elapsed_ms,
            query=sql,
            has_more=(total_count > query.offset + len(items))
        )

        log_info(db.logger, f"Email search completed: {len(items)} results in {elapsed_ms:.2f}ms")

        return SearchErrorCode.SUCCESS, result

    except sqlite3.Error as e:
        log_error(db.logger, f"Email search failed: {e}")
        return SearchErrorCode.ERR_SEARCH_FAILED, None


# ============================================================================
# SEARCH CONTACTS
# ============================================================================

def search_contacts(
    db: DatabaseHandle,
    query: SearchQuery
) -> Tuple[SearchErrorCode, Optional[SearchResult]]:
    """
    Search contacts by name, address, or other attributes.

    Args:
        db: Database handle
        query: SearchQuery object with search parameters

    Returns:
        Tuple of (error_code, SearchResult or None)

    C signature: SearchErrorCode search_contacts(DatabaseHandle* db,
                                                  const SearchQuery* query,
                                                  SearchResult* out_result);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None

    if query is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None

    start_time = time.time()

    try:
        # Build query
        err, sql, params = build_query(query, "contact")
        if err != SearchErrorCode.SUCCESS or sql is None:
            return err, None

        log_debug(db.logger, f"Executing contact search: {query.terms}")

        cursor = db.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # Convert rows to dicts
        items = []
        for row in rows:
            contact = {
                'user_id': row['UserID'],
                'first_name': row['FirstName'],
                'middle_name': row['MiddleName'],
                'last_name': row['LastName'],
                'auto_address': row['auto_address'],
                'description': row['Description'],
                'contact_count': row['contact_count'],
                'last_contacted_timestamp': row['last_contacted_timestamp'],
                'popularity': row['popularity']
            }
            items.append(contact)

        total_count = len(rows)
        elapsed_ms = (time.time() - start_time) * 1000

        result = SearchResult(
            items=items,
            total_count=total_count,
            returned_count=len(items),
            elapsed_time_ms=elapsed_ms,
            query=sql,
            has_more=(total_count > query.offset + len(items))
        )

        log_info(db.logger, f"Contact search completed: {len(items)} results in {elapsed_ms:.2f}ms")

        return SearchErrorCode.SUCCESS, result

    except sqlite3.Error as e:
        log_error(db.logger, f"Contact search failed: {e}")
        return SearchErrorCode.ERR_SEARCH_FAILED, None


# ============================================================================
# INDEX EMAIL
# ============================================================================

def index_email(db: DatabaseHandle, email_id: bytes) -> SearchErrorCode:
    """
    Index an email for full-text search.

    Note: With the current FTS5 setup using triggers, this happens automatically
    when emails are inserted/updated. This function can be used to re-index
    a specific email if needed.

    Args:
        db: Database handle
        email_id: Email GUID as bytes

    Returns:
        SearchErrorCode indicating success or failure

    C signature: SearchErrorCode index_email(DatabaseHandle* db, const uint8_t* email_id);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    if email_id is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    # Convert string to bytes if needed
    if isinstance(email_id, str):
        email_id = bytes.fromhex(email_id.replace('-', ''))

    try:
        cursor = db.connection.cursor()

        # Get the email data
        cursor.execute("""
            SELECT rowid, Subject, Body FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return SearchErrorCode.ERR_NOT_FOUND

        rowid, subject, body = row['rowid'], row['Subject'], row['Body']

        # Delete old FTS entry and insert new one (re-index)
        cursor.execute("""
            INSERT INTO Emails_FTS(Emails_FTS, rowid, Subject, Body)
            VALUES('delete', ?, ?, ?)
        """, (rowid, subject, body))

        cursor.execute("""
            INSERT INTO Emails_FTS(rowid, Subject, Body)
            VALUES(?, ?, ?)
        """, (rowid, subject, body))

        db.connection.commit()

        log_debug(db.logger, f"Re-indexed email: {email_id.hex()}")
        return SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to index email: {e}")
        db.connection.rollback()
        return SearchErrorCode.ERR_INDEX_FAILED


# ============================================================================
# REBUILD INDEX
# ============================================================================

def rebuild_index(db: DatabaseHandle) -> SearchErrorCode:
    """
    Rebuild the entire FTS5 search index.

    This should be called if the FTS5 index becomes corrupted or out of sync
    with the main Emails table. Under normal operation, the triggers keep
    the index synchronized automatically.

    Args:
        db: Database handle

    Returns:
        SearchErrorCode indicating success or failure

    C signature: SearchErrorCode rebuild_index(DatabaseHandle* db);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    try:
        log_info(db.logger, "Rebuilding FTS5 index...")
        cursor = db.connection.cursor()

        # FTS5 rebuild command
        cursor.execute("INSERT INTO Emails_FTS(Emails_FTS) VALUES('rebuild')")

        db.connection.commit()

        log_info(db.logger, "FTS5 index rebuilt successfully")
        return SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to rebuild index: {e}")
        db.connection.rollback()
        return SearchErrorCode.ERR_INDEX_FAILED


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_search_stats(db: DatabaseHandle) -> Tuple[SearchErrorCode, Dict[str, int]]:
    """
    Get statistics about the search index.

    Args:
        db: Database handle

    Returns:
        Tuple of (error_code, dict with stats)

    C signature: SearchErrorCode get_search_stats(DatabaseHandle* db, SearchStats* out_stats);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM, {}

    try:
        cursor = db.connection.cursor()

        # Count indexed emails
        cursor.execute("SELECT COUNT(*) as cnt FROM Emails_FTS")
        fts_count = cursor.fetchone()['cnt']

        # Count total emails
        cursor.execute("SELECT COUNT(*) as cnt FROM Emails")
        total_emails = cursor.fetchone()['cnt']

        # Count total contacts
        cursor.execute("SELECT COUNT(*) as cnt FROM Users")
        total_contacts = cursor.fetchone()['cnt']

        # Count total servers
        cursor.execute("SELECT COUNT(*) as cnt FROM QMailServers")
        total_servers = cursor.fetchone()['cnt']

        stats = {
            'indexed_emails': fts_count,
            'total_emails': total_emails,
            'total_contacts': total_contacts,
            'total_servers': total_servers,
            'index_coverage': (fts_count / total_emails * 100) if total_emails > 0 else 100.0
        }

        return SearchErrorCode.SUCCESS, stats

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to get search stats: {e}")
        return SearchErrorCode.ERR_SEARCH_FAILED, {}


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import tempfile
    import os

    # Import database module for testing
    try:
        from database import init_database, close_database, store_email, store_contact
    except ImportError:
        print("ERROR: Cannot import database module. Make sure database.py is in the same directory.")
        print("This test requires the database.py module to be present.")
        exit(1)

    print("=" * 70)
    print("sonnet45_search_engine.py - Test Suite")
    print("=" * 70)

    # Create temporary database
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_search.db")

        # Initialize database
        print("\n1. Initializing database...")
        err, db = init_database(db_path)
        assert err == DatabaseErrorCode.SUCCESS
        print("   SUCCESS: Database initialized")

        # Create test contacts
        print("\n2. Creating test contacts...")
        contacts = [
            {'first_name': 'Alice', 'last_name': 'Anderson', 'auto_address': 'alice@qmail.net'},
            {'first_name': 'Bob', 'last_name': 'Brown', 'auto_address': 'bob@qmail.net'},
            {'first_name': 'Charlie', 'last_name': 'Chen', 'auto_address': 'charlie@qmail.net'},
            {'first_name': 'Diana', 'last_name': 'Davis', 'auto_address': 'diana@qmail.net'},
        ]
        contact_ids = []
        for contact in contacts:
            err, user_id = store_contact(db, contact)
            assert err == DatabaseErrorCode.SUCCESS
            contact_ids.append(user_id)
        print(f"   SUCCESS: Created {len(contact_ids)} contacts")

        # Create test emails
        print("\n3. Creating test emails...")
        emails = [
            {
                'subject': 'Meeting tomorrow about the project',
                'body': 'Let us discuss the quarterly project review and budget allocation.',
                'sender_id': contact_ids[0],
                'recipient_ids': [contact_ids[1], contact_ids[2]],
                'sent_timestamp': '2025-12-10T10:00:00'
            },
            {
                'subject': 'Budget report Q4 2025',
                'body': 'Please find attached the budget report for Q4. The project is on track.',
                'sender_id': contact_ids[1],
                'recipient_ids': [contact_ids[0]],
                'sent_timestamp': '2025-12-09T14:30:00'
            },
            {
                'subject': 'Quick question about lunch',
                'body': 'Are you available for lunch tomorrow? I want to discuss the new proposal.',
                'sender_id': contact_ids[2],
                'recipient_ids': [contact_ids[3]],
                'sent_timestamp': '2025-12-11T09:15:00'
            },
            {
                'subject': 'Project status update',
                'body': 'The project is progressing well. All milestones are being met on schedule.',
                'sender_id': contact_ids[3],
                'recipient_ids': [contact_ids[0], contact_ids[1]],
                'sent_timestamp': '2025-12-08T16:45:00'
            },
        ]

        email_ids = []
        for email in emails:
            err, email_id = store_email(db, email)
            assert err == DatabaseErrorCode.SUCCESS
            email_ids.append(email_id)
        print(f"   SUCCESS: Created {len(email_ids)} emails")

        # Test 1: Search emails by keyword "project"
        print("\n4. Testing email search (keyword: 'project')...")
        query = SearchQuery(terms="project", limit=10)
        err, result = search_emails(db, query)
        assert err == SearchErrorCode.SUCCESS
        assert result is not None
        assert result.returned_count >= 2  # Should find at least 2 emails with "project"
        print(f"   SUCCESS: Found {result.returned_count} emails in {result.elapsed_time_ms:.2f}ms")
        for item in result.items:
            print(f"     - {item['subject'][:50]}... (score: {item['relevance_score']})")

        # Test 2: Search emails by keyword "budget"
        print("\n5. Testing email search (keyword: 'budget')...")
        query = SearchQuery(terms="budget", limit=10)
        err, result = search_emails(db, query)
        assert err == SearchErrorCode.SUCCESS
        assert result.returned_count >= 1
        print(f"   SUCCESS: Found {result.returned_count} emails")

        # Test 3: Search with sender filter
        print("\n6. Testing email search with sender filter...")
        query = SearchQuery(sender_filter="Alice", limit=10)
        err, result = search_emails(db, query)
        assert err == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Found {result.returned_count} emails from Alice")

        # Test 4: Search contacts
        print("\n7. Testing contact search...")
        query = SearchQuery(terms="Bob", limit=10)
        err, result = search_contacts(db, query)
        assert err == SearchErrorCode.SUCCESS
        assert result.returned_count >= 1
        print(f"   SUCCESS: Found {result.returned_count} contacts")
        for contact in result.items:
            print(f"     - {contact['first_name']} {contact['last_name']} ({contact['auto_address']})")

        # Test 5: Build query function
        print("\n8. Testing build_query()...")
        query = SearchQuery(terms="test", date_from="2025-12-01", limit=20)
        err, sql, params = build_query(query, "email")
        assert err == SearchErrorCode.SUCCESS
        assert sql is not None
        assert len(params) > 0
        print(f"   SUCCESS: Built query with {len(params)} parameters")
        print(f"   Query preview: {sql[:100]}...")

        # Test 6: Index email (re-index)
        print("\n9. Testing index_email()...")
        err = index_email(db, email_ids[0])
        assert err == SearchErrorCode.SUCCESS
        print("   SUCCESS: Email re-indexed")

        # Test 7: Get search stats
        print("\n10. Testing get_search_stats()...")
        err, stats = get_search_stats(db)
        assert err == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Retrieved search statistics")
        print(f"     - Indexed emails: {stats['indexed_emails']}")
        print(f"     - Total emails: {stats['total_emails']}")
        print(f"     - Index coverage: {stats['index_coverage']:.1f}%")

        # Test 8: Rebuild index
        print("\n11. Testing rebuild_index()...")
        err = rebuild_index(db)
        assert err == SearchErrorCode.SUCCESS
        print("   SUCCESS: FTS5 index rebuilt")

        # Test 9: Advanced search with multiple filters
        print("\n12. Testing advanced search with multiple filters...")
        query = SearchQuery(
            terms="project",
            date_from="2025-12-08",
            sort_by="date_desc",
            limit=5
        )
        err, result = search_emails(db, query)
        assert err == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Found {result.returned_count} emails with advanced filters")

        # Close database
        print("\n13. Closing database...")
        success = close_database(db)
        assert success
        print("   SUCCESS: Database closed")

        print("\n" + "=" * 70)
        print("All tests passed!")
        print("=" * 70)
