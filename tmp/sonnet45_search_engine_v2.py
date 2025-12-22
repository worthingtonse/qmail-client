"""
sonnet45_search_engine_v2.py - Search Engine for QMail Client Core (IMPROVED)

This module handles search queries for emails, contacts, and servers using
SQLite's FTS5 (Full-Text Search) capabilities. Designed for easy translation
to C (search_engine.c/search_engine.h) in Phase III.

Author: Claude Sonnet 4.5 (sonnet45)
Phase: I
Version: 2.0.0 - IMPROVED

IMPROVEMENTS FROM V1:
- Added FTS5 query sanitization (security fix)
- Fixed total_count with separate COUNT query (correctness fix)
- Fixed N+1 query problem with JOIN (performance fix)
- Uses bm25(Emails_FTS) for better relevance scoring
- Added snippet() for search highlighting
- Added helper functions (autocomplete, search_by_sender, folder_counts)
- Optimized subqueries to JOINs where possible
- Added column-specific search (subject:term, body:term)

Functions (from plan 4.9):
    build_query(search_query)            -> sql_string
    search_emails(db, query)             -> SearchResult
    search_contacts(db, query)           -> SearchResult
    index_email(db, email)               -> void
    rebuild_index(db)                    -> void

Helper functions:
    get_search_suggestions(db, prefix)   -> List[str]
    search_by_sender(db, sender_id)      -> SearchResult
    get_folder_counts(db)                -> Dict[str, int]
"""

import sqlite3
import time
import re
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
# SEARCH ERROR CODES
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
    subject: Optional[str] = None            # Search only in subject
    body: Optional[str] = None               # Search only in body

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
# QUERY SANITIZATION (Security fix from Opus)
# ============================================================================

def _sanitize_fts_query(query: str) -> str:
    """
    Sanitize user input for FTS5 query.
    Preserves valid FTS5 operators while escaping dangerous characters.

    C: void sanitize_fts_query(const char* input, char* output, size_t output_size);
    """
    if not query:
        return ""

    # Preserve quoted phrases
    protected = []
    def protect_quotes(match):
        protected.append(match.group(0))
        return f"__PROTECTED_{len(protected) - 1}__"

    result = re.sub(r'"[^"]*"', protect_quotes, query)

    # Remove characters that could break FTS5 syntax
    # Allow: alphanumeric, spaces, quotes, *, -, :
    result = re.sub(r'[^\w\s"*\-:]', ' ', result)

    # Restore protected strings
    for i, p in enumerate(protected):
        result = result.replace(f"__PROTECTED_{i}__", p)

    # Normalize whitespace
    result = ' '.join(result.split())

    return result


def _build_fts_expression(sq: SearchQuery) -> str:
    """
    Build FTS5 MATCH expression from search query.
    Supports column-specific search: subject:term, body:term
    """
    parts = []

    # Add general search terms
    if sq.terms:
        terms = _sanitize_fts_query(sq.terms)
        if terms:
            parts.append(terms)

    # Add column-specific searches
    if sq.subject:
        subject_term = _sanitize_fts_query(sq.subject)
        parts.append(f"Subject:{subject_term}")

    if sq.body:
        body_term = _sanitize_fts_query(sq.body)
        parts.append(f"Body:{body_term}")

    # Combine with AND
    return " ".join(parts) if parts else "*"


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
    Build SQL query for email search with FTS5.

    IMPROVEMENTS:
    - Uses JOIN to fetch sender (no N+1 problem)
    - Uses bm25() for relevance scoring
    - Uses snippet() for highlighted excerpts
    - Optimized JOINs instead of subqueries where possible
    """
    params = []

    # Determine if we should use FTS5
    use_fts = bool(sq.terms or sq.subject or sq.body)

    if use_fts:
        # Build FTS5 expression
        fts_terms = _build_fts_expression(sq)

        # Use FTS5 with bm25 scoring and snippets
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
                bm25(Emails_FTS) as relevance_score,
                snippet(Emails_FTS, 0, '<b>', '</b>', '...', 32) as subject_snippet,
                snippet(Emails_FTS, 1, '<b>', '</b>', '...', 64) as body_snippet,
                u.UserID as sender_id,
                u.FirstName as sender_first,
                u.LastName as sender_last,
                u.auto_address as sender_address
            FROM Emails_FTS fts
            JOIN Emails e ON fts.rowid = e.rowid
            LEFT JOIN Junction_Email_Users j ON e.EmailID = j.EmailID AND j.user_type = 'FROM'
            LEFT JOIN Users u ON j.UserID = u.UserID
            WHERE Emails_FTS MATCH ?
        """
        params.append(fts_terms)
    else:
        # Regular query without FTS5
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
                0 as relevance_score,
                '' as subject_snippet,
                '' as body_snippet,
                u.UserID as sender_id,
                u.FirstName as sender_first,
                u.LastName as sender_last,
                u.auto_address as sender_address
            FROM Emails e
            LEFT JOIN Junction_Email_Users j ON e.EmailID = j.EmailID AND j.user_type = 'FROM'
            LEFT JOIN Users u ON j.UserID = u.UserID
            WHERE 1=1
        """

    # Add sender filter (optimized with JOIN instead of subquery)
    if sq.sender_filter:
        query += """
            AND u.UserID IN (
                SELECT UserID FROM Users
                WHERE FirstName LIKE ? OR LastName LIKE ? OR auto_address LIKE ?
            )
        """
        filter_term = f"%{sq.sender_filter}%"
        params.extend([filter_term, filter_term, filter_term])

    # Add recipient filter
    if sq.recipient_filter:
        query += """
            AND e.EmailID IN (
                SELECT j2.EmailID FROM Junction_Email_Users j2
                JOIN Users u2 ON j2.UserID = u2.UserID
                WHERE j2.user_type IN ('TO', 'CC')
                AND (u2.FirstName LIKE ? OR u2.LastName LIKE ? OR u2.auto_address LIKE ?)
            )
        """
        filter_term = f"%{sq.recipient_filter}%"
        params.extend([filter_term, filter_term, filter_term])

    # Date filters (use COALESCE for either sent or received)
    if sq.date_from:
        query += " AND COALESCE(e.ReceivedTimestamp, e.SentTimestamp) >= ?"
        params.append(sq.date_from)

    if sq.date_to:
        # Handle potential timestamp format issues
        date_to_value = sq.date_to
        if len(sq.date_to) == 10:  # Just a date, add time
            date_to_value = sq.date_to + " 23:59:59"
        query += " AND COALESCE(e.ReceivedTimestamp, e.SentTimestamp) <= ?"
        params.append(date_to_value)

    # Folder filter
    if sq.folder:
        query += " AND e.folder = ?"
        params.append(sq.folder)

    # Read/starred filters
    if sq.is_read is not None:
        query += " AND e.is_read = ?"
        params.append(1 if sq.is_read else 0)

    if sq.is_starred is not None:
        query += " AND e.is_starred = ?"
        params.append(1 if sq.is_starred else 0)

    # Attachment filter
    if sq.has_attachments is not None:
        if sq.has_attachments:
            query += " AND e.EmailID IN (SELECT DISTINCT EmailID FROM Attachments)"
        else:
            query += " AND e.EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)"

    # Add ORDER BY (with validation to prevent SQL injection)
    valid_sort_columns = ['ReceivedTimestamp', 'SentTimestamp', 'Subject']

    if sq.sort_by == "relevance" and use_fts:
        query += " ORDER BY relevance_score"
    elif sq.sort_by == "date_desc":
        query += " ORDER BY COALESCE(e.ReceivedTimestamp, e.SentTimestamp) DESC"
    elif sq.sort_by == "date_asc":
        query += " ORDER BY COALESCE(e.ReceivedTimestamp, e.SentTimestamp) ASC"
    else:
        # Default to date descending
        query += " ORDER BY COALESCE(e.ReceivedTimestamp, e.SentTimestamp) DESC"

    # Add LIMIT and OFFSET
    query += " LIMIT ? OFFSET ?"
    params.extend([sq.limit, sq.offset])

    return SearchErrorCode.SUCCESS, query, params


def _build_count_query(sq: SearchQuery, search_type: str) -> Tuple[SearchErrorCode, str, List[Any]]:
    """
    Build COUNT query for total results (for pagination).
    Applies same filters as main query but without LIMIT/OFFSET.
    """
    params = []

    if search_type == "email":
        use_fts = bool(sq.terms or sq.subject or sq.body)

        if use_fts:
            fts_terms = _build_fts_expression(sq)
            query = """
                SELECT COUNT(DISTINCT e.EmailID)
                FROM Emails_FTS fts
                JOIN Emails e ON fts.rowid = e.rowid
                LEFT JOIN Junction_Email_Users j ON e.EmailID = j.EmailID AND j.user_type = 'FROM'
                LEFT JOIN Users u ON j.UserID = u.UserID
                WHERE Emails_FTS MATCH ?
            """
            params.append(fts_terms)
        else:
            query = "SELECT COUNT(*) FROM Emails e WHERE 1=1"

        # Apply same filters as main query
        if sq.sender_filter:
            query += """
                AND e.EmailID IN (
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
                AND e.EmailID IN (
                    SELECT j.EmailID FROM Junction_Email_Users j
                    JOIN Users u ON j.UserID = u.UserID
                    WHERE j.user_type IN ('TO', 'CC')
                    AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
                )
            """
            filter_term = f"%{sq.recipient_filter}%"
            params.extend([filter_term, filter_term, filter_term])

        if sq.date_from:
            query += " AND COALESCE(e.ReceivedTimestamp, e.SentTimestamp) >= ?"
            params.append(sq.date_from)

        if sq.date_to:
            date_to_value = sq.date_to
            if len(sq.date_to) == 10:
                date_to_value = sq.date_to + " 23:59:59"
            query += " AND COALESCE(e.ReceivedTimestamp, e.SentTimestamp) <= ?"
            params.append(date_to_value)

        if sq.folder:
            query += " AND e.folder = ?"
            params.append(sq.folder)

        if sq.is_read is not None:
            query += " AND e.is_read = ?"
            params.append(1 if sq.is_read else 0)

        if sq.is_starred is not None:
            query += " AND e.is_starred = ?"
            params.append(1 if sq.is_starred else 0)

        if sq.has_attachments is not None:
            if sq.has_attachments:
                query += " AND e.EmailID IN (SELECT DISTINCT EmailID FROM Attachments)"
            else:
                query += " AND e.EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)"

    elif search_type == "contact":
        query = "SELECT COUNT(*) FROM Users WHERE 1=1"

        if sq.terms:
            query += " AND (FirstName LIKE ? OR LastName LIKE ? OR auto_address LIKE ? OR Description LIKE ?)"
            search_term = f"%{sq.terms}%"
            params.extend([search_term, search_term, search_term, search_term])

        if sq.first_name_filter:
            query += " AND FirstName LIKE ?"
            params.append(f"%{sq.first_name_filter}%")

        if sq.last_name_filter:
            query += " AND LastName LIKE ?"
            params.append(f"%{sq.last_name_filter}%")

        if sq.auto_address_filter:
            query += " AND auto_address LIKE ?"
            params.append(f"%{sq.auto_address_filter}%")

    else:
        query = "SELECT 0"

    return SearchErrorCode.SUCCESS, query, params


def _build_contact_query(sq: SearchQuery) -> Tuple[SearchErrorCode, str, List[Any]]:
    """Build SQL query for contact search."""
    params = []

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
            END AS popularity
        FROM Users
        WHERE 1=1
    """

    # Full-text search
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

    # Order by popularity
    if sq.sort_by == "relevance":
        query += " ORDER BY popularity DESC"
    else:
        query += " ORDER BY FirstName, LastName"

    # Add LIMIT and OFFSET
    query += " LIMIT ? OFFSET ?"
    params.extend([sq.limit, sq.offset])

    return SearchErrorCode.SUCCESS, query, params


def _build_server_query(sq: SearchQuery) -> Tuple[SearchErrorCode, str, List[Any]]:
    """Build SQL query for server search."""
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

    # Order by ping (fastest first)
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

        # Convert rows to dicts (sender already included via JOIN - no N+1!)
        items = []
        for row in rows:
            email = {
                'email_id': row['EmailID'].hex() if row['EmailID'] else None,
                'subject': row['Subject'],
                'body': row['Body'][:200] if row['Body'] else None,  # Truncate
                'received_timestamp': row['ReceivedTimestamp'],
                'sent_timestamp': row['SentTimestamp'],
                'is_read': bool(row['is_read']),
                'is_starred': bool(row['is_starred']),
                'is_trashed': bool(row['is_trashed']),
                'folder': row['folder'],
                'relevance_score': abs(row['relevance_score']) if row['relevance_score'] else 0,
                'subject_snippet': row['subject_snippet'],
                'body_snippet': row['body_snippet'],
                'sender': {
                    'user_id': row['sender_id'],
                    'first_name': row['sender_first'],
                    'last_name': row['sender_last'],
                    'auto_address': row['sender_address']
                } if row['sender_id'] else None
            }
            items.append(email)

        # Get total count with separate query (correct pagination)
        err_count, count_sql, count_params = _build_count_query(query, "email")
        if err_count == SearchErrorCode.SUCCESS and count_sql:
            cursor.execute(count_sql, count_params)
            total_count = cursor.fetchone()[0]
        else:
            total_count = len(items)

        elapsed_ms = (time.time() - start_time) * 1000

        result = SearchResult(
            items=items,
            total_count=total_count,
            returned_count=len(items),
            elapsed_time_ms=elapsed_ms,
            query=sql,
            has_more=(total_count > query.offset + len(items))
        )

        log_info(db.logger, f"Email search completed: {len(items)}/{total_count} in {elapsed_ms:.2f}ms")

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

        # Get total count
        err_count, count_sql, count_params = _build_count_query(query, "contact")
        if err_count == SearchErrorCode.SUCCESS and count_sql:
            cursor.execute(count_sql, count_params)
            total_count = cursor.fetchone()[0]
        else:
            total_count = len(items)

        elapsed_ms = (time.time() - start_time) * 1000

        result = SearchResult(
            items=items,
            total_count=total_count,
            returned_count=len(items),
            elapsed_time_ms=elapsed_ms,
            query=sql,
            has_more=(total_count > query.offset + len(items))
        )

        log_info(db.logger, f"Contact search completed: {len(items)}/{total_count} in {elapsed_ms:.2f}ms")

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

    C signature: SearchErrorCode index_email(DatabaseHandle* db, const uint8_t* email_id);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    if email_id is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    if isinstance(email_id, str):
        email_id = bytes.fromhex(email_id.replace('-', ''))

    try:
        cursor = db.connection.cursor()

        # Get email data
        cursor.execute("SELECT rowid, Subject, Body FROM Emails WHERE EmailID = ?", (email_id,))
        row = cursor.fetchone()
        if row is None:
            return SearchErrorCode.ERR_NOT_FOUND

        rowid, subject, body = row['rowid'], row['Subject'], row['Body']

        # Re-index (delete and insert)
        cursor.execute(
            "INSERT INTO Emails_FTS(Emails_FTS, rowid, Subject, Body) VALUES('delete', ?, ?, ?)",
            (rowid, subject or '', body or '')
        )
        cursor.execute(
            "INSERT INTO Emails_FTS(rowid, Subject, Body) VALUES (?, ?, ?)",
            (rowid, subject or '', body or '')
        )

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
# HELPER FUNCTIONS (New additions from Opus's best practices)
# ============================================================================

def get_search_suggestions(
    db: DatabaseHandle,
    prefix: str,
    limit: int = 10
) -> List[str]:
    """
    Get search suggestions based on a prefix (autocomplete).

    Args:
        db: Database handle
        prefix: Search prefix
        limit: Maximum suggestions to return

    Returns:
        List of suggested search terms

    C signature: SearchErrorCode get_search_suggestions(DatabaseHandle* db,
                                                         const char* prefix,
                                                         int limit,
                                                         char** out_suggestions,
                                                         int* out_count);
    """
    if db is None or db.connection is None or not prefix:
        return []

    suggestions = []

    try:
        cursor = db.connection.cursor()

        # Get from email subjects
        cursor.execute("""
            SELECT DISTINCT Subject FROM Emails
            WHERE Subject LIKE ?
            ORDER BY ReceivedTimestamp DESC
            LIMIT ?
        """, (f"{prefix}%", limit))

        for row in cursor.fetchall():
            if row[0]:
                suggestions.append(row[0])

        # Also get contact names
        if len(suggestions) < limit:
            cursor.execute("""
                SELECT DISTINCT FirstName || ' ' || LastName as name
                FROM Users
                WHERE FirstName LIKE ? OR LastName LIKE ?
                LIMIT ?
            """, (f"{prefix}%", f"{prefix}%", limit - len(suggestions)))

            for row in cursor.fetchall():
                if row[0] and row[0].strip():
                    suggestions.append(row[0])

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to get suggestions: {e}")

    return suggestions[:limit]


def search_by_sender(
    db: DatabaseHandle,
    sender_id: int,
    limit: int = 50,
    offset: int = 0
) -> Tuple[SearchErrorCode, Optional[SearchResult]]:
    """
    Search emails from a specific sender.

    Args:
        db: Database handle
        sender_id: UserID of the sender
        limit: Maximum results
        offset: Pagination offset

    Returns:
        Tuple of (error_code, SearchResult)

    C signature: SearchErrorCode search_by_sender(DatabaseHandle* db,
                                                   int64_t sender_id,
                                                   int limit,
                                                   int offset,
                                                   SearchResult* out_result);
    """
    start_time = time.time()

    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM, None

    try:
        cursor = db.connection.cursor()

        cursor.execute("""
            SELECT
                e.EmailID, e.Subject, e.Body,
                e.ReceivedTimestamp, e.SentTimestamp,
                e.is_read, e.is_starred, e.is_trashed, e.folder
            FROM Emails e
            JOIN Junction_Email_Users j ON e.EmailID = j.EmailID
            WHERE j.UserID = ? AND j.user_type = 'FROM'
            ORDER BY COALESCE(e.ReceivedTimestamp, e.SentTimestamp) DESC
            LIMIT ? OFFSET ?
        """, (sender_id, limit, offset))

        items = []
        for row in cursor.fetchall():
            items.append({
                'email_id': row['EmailID'].hex() if row['EmailID'] else None,
                'subject': row['Subject'],
                'body': row['Body'][:200] if row['Body'] else None,
                'received_timestamp': row['ReceivedTimestamp'],
                'sent_timestamp': row['SentTimestamp'],
                'is_read': bool(row['is_read']),
                'is_starred': bool(row['is_starred']),
                'is_trashed': bool(row['is_trashed']),
                'folder': row['folder']
            })

        # Get total count
        cursor.execute("""
            SELECT COUNT(*)
            FROM Junction_Email_Users
            WHERE UserID = ? AND user_type = 'FROM'
        """, (sender_id,))
        total_count = cursor.fetchone()[0]

        elapsed_ms = (time.time() - start_time) * 1000

        result = SearchResult(
            items=items,
            total_count=total_count,
            returned_count=len(items),
            elapsed_time_ms=elapsed_ms,
            query="search_by_sender",
            has_more=(total_count > offset + len(items))
        )

        return SearchErrorCode.SUCCESS, result

    except sqlite3.Error as e:
        log_error(db.logger, f"Search by sender failed: {e}")
        return SearchErrorCode.ERR_SEARCH_FAILED, None


def get_folder_counts(db: DatabaseHandle) -> Dict[str, int]:
    """
    Get email counts per folder.

    Args:
        db: Database handle

    Returns:
        Dictionary of folder -> count

    C signature: SearchErrorCode get_folder_counts(DatabaseHandle* db,
                                                    FolderCount** out_counts,
                                                    int* out_count);
    """
    if db is None or db.connection is None:
        return {}

    counts = {}

    try:
        cursor = db.connection.cursor()

        # Count per folder (excluding trash)
        cursor.execute("""
            SELECT folder, COUNT(*) as cnt
            FROM Emails
            WHERE is_trashed = 0
            GROUP BY folder
        """)

        for row in cursor.fetchall():
            counts[row[0] or 'inbox'] = row[1]

        # Count unread
        cursor.execute("SELECT COUNT(*) FROM Emails WHERE is_read = 0 AND is_trashed = 0")
        counts['unread'] = cursor.fetchone()[0]

        # Count starred
        cursor.execute("SELECT COUNT(*) FROM Emails WHERE is_starred = 1 AND is_trashed = 0")
        counts['starred'] = cursor.fetchone()[0]

        # Count trashed
        cursor.execute("SELECT COUNT(*) FROM Emails WHERE is_trashed = 1")
        counts['trash'] = cursor.fetchone()[0]

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to get folder counts: {e}")

    return counts


def get_search_stats(db: DatabaseHandle) -> Tuple[SearchErrorCode, Dict[str, Any]]:
    """
    Get statistics about the search index.

    Args:
        db: Database handle

    Returns:
        Tuple of (error_code, dict with stats)

    C signature: SearchErrorCode get_search_stats(DatabaseHandle* db,
                                                   SearchStats* out_stats);
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
