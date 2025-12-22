"""
opus45_search_engine.py - Search Engine Module for QMail Client Core

This module provides full-text search capabilities for emails, contacts, and
servers using SQLite FTS5 extension. Designed for easy translation to C
(search_engine.c/search_engine.h) in Phase III.

Author: Claude Opus 4.5 (opus45)
Phase: I
Version: 1.1.0

Changes in v1.1.0 (from peer reviews):
    - Added has_attachments filter (from Sonnet's suggestion)
    - Added sender_name and recipient_name filters (from Sonnet's suggestion)
    - Added search_by_recipient() helper (from Sonnet's suggestion)
    - Fixed date_to format validation (from Sonnet's suggestion)

Functions (from plan 4.9):
    build_query(search_query)            -> sql_string
    search_emails(db, query)             -> SearchResult
    search_contacts(db, query)           -> SearchResult
    index_email(db, email)               -> void
    rebuild_index(db)                    -> void

Additional helper functions:
    get_search_suggestions(db, prefix)   -> suggestions[]
    search_by_sender(db, sender_id)      -> SearchResult
    search_by_recipient(db, recipient_id)-> SearchResult
    get_folder_counts(db)                -> folder_counts{}

C Notes: Full-text search via SQLite FTS5 extension. The FTS5 extension
is included in SQLite by default since version 3.9.0 (2015).

Architecture Note (re: Gemini's review about qmail_types.py):
    This module defines its own SearchQuery and SearchResult dataclasses rather
    than importing from qmail_types.py. This is intentional because:
    1. qmail_types.py's SearchQuery is minimal (terms, filters dict, sort_by, limit, offset)
    2. This module needs rich, typed fields (has_attachments, sender_name, date_from, etc.)
    3. Self-contained types make standalone testing easier
    4. For C conversion, each module should define its own structs anyway
    If project architecture requires shared types, these can be merged into
    qmail_types.py in Phase II, but the current approach is valid for Phase I.

FTS5 Query Syntax Supported:
    - Simple terms: "hello world" matches emails containing both words
    - Phrases: '"exact phrase"' matches the exact phrase
    - OR operator: "hello OR world" matches either word
    - NOT operator: "hello NOT world" matches hello but not world
    - Prefix: "hel*" matches words starting with "hel"
    - Column filters: "subject:hello" searches only subject field
"""

import sqlite3
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import IntEnum

# Try to import from package, fall back to direct import for standalone testing
try:
    from .logger import log_info, log_error, log_warning, log_debug
    from .database import DatabaseHandle, DatabaseErrorCode, execute_query
except ImportError:
    # Fallback for standalone testing
    def log_info(handle, msg): print(f"[INFO] {msg}")
    def log_error(handle, msg): print(f"[ERROR] {msg}")
    def log_warning(handle, msg): print(f"[WARNING] {msg}")
    def log_debug(handle, msg): print(f"[DEBUG] {msg}")

    # Minimal stubs for standalone testing
    class DatabaseHandle:
        def __init__(self, connection, path, logger=None):
            self.connection = connection
            self.path = path
            self.logger = logger

    class DatabaseErrorCode(IntEnum):
        SUCCESS = 0
        ERR_QUERY_FAILED = 3
        ERR_INVALID_PARAM = 5


# ============================================================================
# ERROR CODES
# ============================================================================

class SearchErrorCode(IntEnum):
    """
    Error codes for search operations.
    C: typedef enum { SEARCH_SUCCESS = 0, ... } SearchErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_QUERY = 1
    ERR_DATABASE_ERROR = 2
    ERR_NO_RESULTS = 3
    ERR_INVALID_PARAM = 4
    ERR_INDEX_ERROR = 5


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SearchQuery:
    """
    Represents a search query with various filters.
    C: typedef struct SearchQuery { ... } SearchQuery;
    """
    # Full-text search terms
    terms: str = ""

    # Field-specific searches
    subject: Optional[str] = None
    body: Optional[str] = None
    sender: Optional[str] = None

    # Filters for emails
    folder: Optional[str] = None          # inbox, sent, drafts, trash, etc.
    is_read: Optional[bool] = None
    is_starred: Optional[bool] = None
    is_trashed: Optional[bool] = None
    has_attachments: Optional[bool] = None  # Filter by attachment presence

    # Sender/recipient filters (for name-based filtering)
    sender_name: Optional[str] = None     # Filter by sender name (partial match)
    recipient_name: Optional[str] = None  # Filter by recipient name (partial match)

    # Date range filters
    date_from: Optional[str] = None       # ISO format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
    date_to: Optional[str] = None         # ISO format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS

    # Pagination
    limit: int = 50
    offset: int = 0

    # Sort order
    order_by: str = "ReceivedTimestamp"   # Column to sort by
    order_desc: bool = True               # Descending order


@dataclass
class SearchResultItem:
    """
    Represents a single search result item.
    C: typedef struct SearchResultItem { ... } SearchResultItem;
    """
    id: Any                               # EmailID (bytes) or UserID (int)
    score: float = 0.0                    # Relevance score (from FTS5 bm25)
    snippet: str = ""                     # Text snippet with highlights
    data: Dict[str, Any] = field(default_factory=dict)  # Full row data


@dataclass
class SearchResult:
    """
    Represents search results with metadata.
    C: typedef struct SearchResult { ... } SearchResult;
    """
    items: List[SearchResultItem] = field(default_factory=list)
    total_count: int = 0                  # Total matches (before pagination)
    query_time_ms: float = 0.0            # Query execution time
    error_code: SearchErrorCode = SearchErrorCode.SUCCESS
    error_message: str = ""


# ============================================================================
# QUERY BUILDER
# ============================================================================

def build_query(search_query: SearchQuery, query_type: str = "emails") -> Tuple[str, List[Any]]:
    """
    Build a SQL query string from a SearchQuery object.

    Args:
        search_query: SearchQuery object with search parameters
        query_type: Type of search - "emails", "contacts", or "servers"

    Returns:
        Tuple of (sql_string, parameters_list)

    C signature: SearchErrorCode build_query(const SearchQuery* query, const char* query_type,
                                              char** out_sql, void** out_params, int* out_param_count);
    """
    params = []

    if query_type == "emails":
        return _build_email_query(search_query, params)
    elif query_type == "contacts":
        return _build_contact_query(search_query, params)
    elif query_type == "servers":
        return _build_server_query(search_query, params)
    else:
        return "", []


def _build_email_query(sq: SearchQuery, params: List[Any]) -> Tuple[str, List[Any]]:
    """
    Build FTS5 query for email search.
    Uses the Emails_FTS virtual table for full-text search.
    """
    # Check if we need FTS5 search
    use_fts = bool(sq.terms or sq.subject or sq.body)

    if use_fts:
        # Build FTS5 MATCH expression
        fts_terms = _build_fts_expression(sq)

        # Query using FTS5 with bm25 ranking
        # Join Emails_FTS with Emails to get full data and apply filters
        sql = """
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
                bm25(Emails_FTS) as score,
                snippet(Emails_FTS, 0, '<b>', '</b>', '...', 32) as subject_snippet,
                snippet(Emails_FTS, 1, '<b>', '</b>', '...', 64) as body_snippet
            FROM Emails_FTS
            JOIN Emails e ON Emails_FTS.rowid = e.rowid
            WHERE Emails_FTS MATCH ?
        """
        params.append(fts_terms)
    else:
        # No FTS needed, just filter query
        sql = """
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
                0 as score,
                '' as subject_snippet,
                '' as body_snippet
            FROM Emails e
            WHERE 1=1
        """

    # Apply filters
    if sq.folder is not None:
        sql += " AND e.folder = ?"
        params.append(sq.folder)

    if sq.is_read is not None:
        sql += " AND e.is_read = ?"
        params.append(1 if sq.is_read else 0)

    if sq.is_starred is not None:
        sql += " AND e.is_starred = ?"
        params.append(1 if sq.is_starred else 0)

    if sq.is_trashed is not None:
        sql += " AND e.is_trashed = ?"
        params.append(1 if sq.is_trashed else 0)

    # Has attachments filter (from Sonnet's review suggestion)
    if sq.has_attachments is not None:
        if sq.has_attachments:
            sql += " AND e.EmailID IN (SELECT DISTINCT EmailID FROM Attachments)"
        else:
            sql += " AND e.EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)"

    # Sender name filter (from Sonnet's review suggestion)
    if sq.sender_name is not None:
        sql += """
            AND e.EmailID IN (
                SELECT j.EmailID FROM Junction_Email_Users j
                JOIN Users u ON j.UserID = u.UserID
                WHERE j.user_type = 'FROM'
                AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
            )
        """
        sender_term = f"%{sq.sender_name}%"
        params.extend([sender_term, sender_term, sender_term])

    # Recipient name filter (from Sonnet's review suggestion)
    if sq.recipient_name is not None:
        sql += """
            AND e.EmailID IN (
                SELECT j.EmailID FROM Junction_Email_Users j
                JOIN Users u ON j.UserID = u.UserID
                WHERE j.user_type IN ('TO', 'CC')
                AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
            )
        """
        recipient_term = f"%{sq.recipient_name}%"
        params.extend([recipient_term, recipient_term, recipient_term])

    if sq.date_from is not None:
        sql += " AND e.ReceivedTimestamp >= ?"
        params.append(sq.date_from)

    if sq.date_to is not None:
        sql += " AND e.ReceivedTimestamp <= ?"
        # Fix from review: validate date format before appending time suffix
        # Only append " 23:59:59" if it looks like a date-only format (YYYY-MM-DD)
        date_to_val = sq.date_to
        if len(date_to_val) == 10 and date_to_val[4] == '-' and date_to_val[7] == '-':
            date_to_val = date_to_val + " 23:59:59"
        params.append(date_to_val)

    # Order by
    if use_fts:
        # For FTS, order by relevance score first
        sql += " ORDER BY score"
    else:
        # Validate order_by column to prevent SQL injection
        # SAFETY NOTE: Only allow known column names
        valid_columns = ['ReceivedTimestamp', 'SentTimestamp', 'Subject', 'is_read', 'is_starred', 'folder']
        order_col = sq.order_by if sq.order_by in valid_columns else 'ReceivedTimestamp'
        sql += f" ORDER BY e.{order_col}"

    sql += " DESC" if sq.order_desc else " ASC"

    # Pagination
    sql += " LIMIT ? OFFSET ?"
    params.append(sq.limit)
    params.append(sq.offset)

    return sql, params


def _build_contact_query(sq: SearchQuery, params: List[Any]) -> Tuple[str, List[Any]]:
    """
    Build query for contact/user search.
    Uses LIKE for partial matching on name fields.
    """
    sql = """
        SELECT
            UserID,
            FirstName,
            MiddleName,
            LastName,
            auto_address,
            Description,
            contact_count,
            last_contacted_timestamp
        FROM Users
        WHERE 1=1
    """

    # Search in name fields
    if sq.terms:
        # Search across all name-related fields
        sql += """ AND (
            FirstName LIKE ? OR
            LastName LIKE ? OR
            MiddleName LIKE ? OR
            auto_address LIKE ? OR
            Description LIKE ?
        )"""
        search_term = f"%{sq.terms}%"
        params.extend([search_term] * 5)

    # Order by popularity (contact_count) by default
    sql += " ORDER BY contact_count DESC, LastName ASC"

    # Pagination
    sql += " LIMIT ? OFFSET ?"
    params.append(sq.limit)
    params.append(sq.offset)

    return sql, params


def _build_server_query(sq: SearchQuery, params: List[Any]) -> Tuple[str, List[Any]]:
    """
    Build query for server search.
    """
    sql = """
        SELECT
            QMailServerID,
            IPAddress,
            PortNumb,
            server_type,
            ping_ms,
            number_of_calls,
            amount_of_credit
        FROM QMailServers
        WHERE 1=1
    """

    # Search in IP address or server type
    if sq.terms:
        sql += " AND (IPAddress LIKE ? OR server_type LIKE ?)"
        search_term = f"%{sq.terms}%"
        params.extend([search_term, search_term])

    # Order by ping time (fastest first)
    sql += " ORDER BY ping_ms ASC NULLS LAST"

    # Pagination
    sql += " LIMIT ? OFFSET ?"
    params.append(sq.limit)
    params.append(sq.offset)

    return sql, params


def _build_fts_expression(sq: SearchQuery) -> str:
    """
    Build FTS5 MATCH expression from search query.
    Handles special characters and operators.

    FTS5 query syntax:
        - word1 word2     -> AND (both required)
        - word1 OR word2  -> OR
        - "exact phrase"  -> phrase search
        - word*           -> prefix search
        - subject:word    -> column filter
        - -word           -> NOT (exclude)
    """
    parts = []

    # Add general search terms
    if sq.terms:
        # Escape special FTS5 characters but preserve operators
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


def _sanitize_fts_query(query: str) -> str:
    """
    Sanitize user input for FTS5 query.
    Preserves valid FTS5 operators while escaping dangerous characters.

    C: void sanitize_fts_query(const char* input, char* output, size_t output_size);
    """
    if not query:
        return ""

    # Preserve quoted phrases
    # First, extract and protect quoted strings
    protected = []
    def protect_quotes(match):
        protected.append(match.group(0))
        return f"__PROTECTED_{len(protected) - 1}__"

    result = re.sub(r'"[^"]*"', protect_quotes, query)

    # Remove characters that could break FTS5 syntax (except allowed operators)
    # Allow: alphanumeric, spaces, quotes, *, -, OR, AND, :
    result = re.sub(r'[^\w\s"*\-:]', ' ', result)

    # Restore protected strings
    for i, p in enumerate(protected):
        result = result.replace(f"__PROTECTED_{i}__", p)

    # Normalize whitespace
    result = ' '.join(result.split())

    return result


# ============================================================================
# SEARCH EMAILS
# ============================================================================

def search_emails(
    db: DatabaseHandle,
    query: SearchQuery
) -> SearchResult:
    """
    Search emails using FTS5 full-text search.

    Args:
        db: Database handle from init_database()
        query: SearchQuery object with search parameters

    Returns:
        SearchResult with matching emails

    C signature: SearchErrorCode search_emails(DatabaseHandle* db, const SearchQuery* query,
                                                SearchResult* out_result);
    """
    import time
    start_time = time.perf_counter()

    result = SearchResult()

    if db is None or db.connection is None:
        result.error_code = SearchErrorCode.ERR_INVALID_PARAM
        result.error_message = "Invalid database handle"
        return result

    try:
        # Build the query
        sql, params = build_query(query, "emails")

        if not sql:
            result.error_code = SearchErrorCode.ERR_INVALID_QUERY
            result.error_message = "Failed to build query"
            return result

        log_debug(db.logger, f"Search query: {sql[:100]}...")

        # Execute search
        cursor = db.connection.cursor()
        cursor.execute(sql, params)

        rows = cursor.fetchall()

        # Convert to SearchResultItems
        for row in rows:
            item = SearchResultItem(
                id=row[0],  # EmailID
                score=abs(row[9]) if row[9] else 0.0,  # bm25 returns negative values
                snippet=row[11] if row[11] else (row[10] if row[10] else ""),  # body_snippet or subject_snippet
                data={
                    'email_id': row[0].hex() if row[0] else None,
                    'subject': row[1],
                    'body': row[2][:200] if row[2] else None,  # Truncate body
                    'received_timestamp': row[3],
                    'sent_timestamp': row[4],
                    'is_read': bool(row[5]),
                    'is_starred': bool(row[6]),
                    'is_trashed': bool(row[7]),
                    'folder': row[8],
                    'subject_snippet': row[10],
                    'body_snippet': row[11]
                }
            )
            result.items.append(item)

        # Get total count (without pagination) for the same filters
        count_sql, count_params = _build_count_query(query, "emails")
        cursor.execute(count_sql, count_params)
        result.total_count = cursor.fetchone()[0]

        result.query_time_ms = (time.perf_counter() - start_time) * 1000
        result.error_code = SearchErrorCode.SUCCESS

        log_debug(db.logger, f"Search found {len(result.items)} results in {result.query_time_ms:.2f}ms")

    except sqlite3.Error as e:
        result.error_code = SearchErrorCode.ERR_DATABASE_ERROR
        result.error_message = str(e)
        log_error(db.logger, f"Search failed: {e}")

    return result


def _build_count_query(sq: SearchQuery, query_type: str) -> Tuple[str, List[Any]]:
    """Build a COUNT query for total results."""
    params = []

    if query_type == "emails":
        use_fts = bool(sq.terms or sq.subject or sq.body)

        if use_fts:
            fts_terms = _build_fts_expression(sq)
            sql = """
                SELECT COUNT(*)
                FROM Emails_FTS
                JOIN Emails e ON Emails_FTS.rowid = e.rowid
                WHERE Emails_FTS MATCH ?
            """
            params.append(fts_terms)
        else:
            sql = "SELECT COUNT(*) FROM Emails e WHERE 1=1"

        # Apply same filters as main query
        if sq.folder is not None:
            sql += " AND e.folder = ?"
            params.append(sq.folder)

        if sq.is_read is not None:
            sql += " AND e.is_read = ?"
            params.append(1 if sq.is_read else 0)

        if sq.is_starred is not None:
            sql += " AND e.is_starred = ?"
            params.append(1 if sq.is_starred else 0)

        if sq.is_trashed is not None:
            sql += " AND e.is_trashed = ?"
            params.append(1 if sq.is_trashed else 0)

        # Has attachments filter (must match main query)
        if sq.has_attachments is not None:
            if sq.has_attachments:
                sql += " AND e.EmailID IN (SELECT DISTINCT EmailID FROM Attachments)"
            else:
                sql += " AND e.EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)"

        # Sender name filter (must match main query)
        if sq.sender_name is not None:
            sql += """
                AND e.EmailID IN (
                    SELECT j.EmailID FROM Junction_Email_Users j
                    JOIN Users u ON j.UserID = u.UserID
                    WHERE j.user_type = 'FROM'
                    AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
                )
            """
            sender_term = f"%{sq.sender_name}%"
            params.extend([sender_term, sender_term, sender_term])

        # Recipient name filter (must match main query)
        if sq.recipient_name is not None:
            sql += """
                AND e.EmailID IN (
                    SELECT j.EmailID FROM Junction_Email_Users j
                    JOIN Users u ON j.UserID = u.UserID
                    WHERE j.user_type IN ('TO', 'CC')
                    AND (u.FirstName LIKE ? OR u.LastName LIKE ? OR u.auto_address LIKE ?)
                )
            """
            recipient_term = f"%{sq.recipient_name}%"
            params.extend([recipient_term, recipient_term, recipient_term])

        if sq.date_from is not None:
            sql += " AND e.ReceivedTimestamp >= ?"
            params.append(sq.date_from)

        if sq.date_to is not None:
            sql += " AND e.ReceivedTimestamp <= ?"
            # Fix from review: validate date format
            date_to_val = sq.date_to
            if len(date_to_val) == 10 and date_to_val[4] == '-' and date_to_val[7] == '-':
                date_to_val = date_to_val + " 23:59:59"
            params.append(date_to_val)

    elif query_type == "contacts":
        sql = "SELECT COUNT(*) FROM Users WHERE 1=1"
        if sq.terms:
            sql += """ AND (
                FirstName LIKE ? OR
                LastName LIKE ? OR
                MiddleName LIKE ? OR
                auto_address LIKE ? OR
                Description LIKE ?
            )"""
            search_term = f"%{sq.terms}%"
            params.extend([search_term] * 5)

    else:
        sql = "SELECT 0"

    return sql, params


# ============================================================================
# SEARCH CONTACTS
# ============================================================================

def search_contacts(
    db: DatabaseHandle,
    query: SearchQuery
) -> SearchResult:
    """
    Search contacts/users.

    Args:
        db: Database handle from init_database()
        query: SearchQuery object with search parameters

    Returns:
        SearchResult with matching contacts

    C signature: SearchErrorCode search_contacts(DatabaseHandle* db, const SearchQuery* query,
                                                  SearchResult* out_result);
    """
    import time
    start_time = time.perf_counter()

    result = SearchResult()

    if db is None or db.connection is None:
        result.error_code = SearchErrorCode.ERR_INVALID_PARAM
        result.error_message = "Invalid database handle"
        return result

    try:
        # Build the query
        sql, params = build_query(query, "contacts")

        log_debug(db.logger, f"Contact search: {sql[:100]}...")

        # Execute search
        cursor = db.connection.cursor()
        cursor.execute(sql, params)

        rows = cursor.fetchall()

        # Convert to SearchResultItems
        for row in rows:
            # Build display name for snippet
            name_parts = [p for p in [row[1], row[2], row[3]] if p]  # First, Middle, Last
            display_name = " ".join(name_parts) if name_parts else row[4] or "Unknown"

            item = SearchResultItem(
                id=row[0],  # UserID
                score=row[6] or 0,  # contact_count as relevance
                snippet=display_name,
                data={
                    'user_id': row[0],
                    'first_name': row[1],
                    'middle_name': row[2],
                    'last_name': row[3],
                    'auto_address': row[4],
                    'description': row[5],
                    'contact_count': row[6],
                    'last_contacted': row[7]
                }
            )
            result.items.append(item)

        # Get total count
        count_sql, count_params = _build_count_query(query, "contacts")
        cursor.execute(count_sql, count_params)
        result.total_count = cursor.fetchone()[0]

        result.query_time_ms = (time.perf_counter() - start_time) * 1000
        result.error_code = SearchErrorCode.SUCCESS

        log_debug(db.logger, f"Contact search found {len(result.items)} results")

    except sqlite3.Error as e:
        result.error_code = SearchErrorCode.ERR_DATABASE_ERROR
        result.error_message = str(e)
        log_error(db.logger, f"Contact search failed: {e}")

    return result


# ============================================================================
# INDEX EMAIL
# ============================================================================

def index_email(db: DatabaseHandle, email_id: bytes) -> SearchErrorCode:
    """
    Manually index or re-index a specific email in the FTS5 index.

    Note: The database triggers automatically handle indexing on INSERT/UPDATE/DELETE.
    This function is for manual re-indexing if needed.

    Args:
        db: Database handle
        email_id: Email GUID to index

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

        # Get the email's rowid and content
        cursor.execute("""
            SELECT rowid, Subject, Body FROM Emails WHERE EmailID = ?
        """, (email_id,))

        row = cursor.fetchone()
        if row is None:
            return SearchErrorCode.ERR_INVALID_PARAM

        rowid, subject, body = row

        # Delete existing FTS entry if any
        cursor.execute("""
            INSERT INTO Emails_FTS(Emails_FTS, rowid, Subject, Body)
            VALUES('delete', ?, ?, ?)
        """, (rowid, subject or '', body or ''))

        # Insert new FTS entry
        cursor.execute("""
            INSERT INTO Emails_FTS(rowid, Subject, Body) VALUES (?, ?, ?)
        """, (rowid, subject or '', body or ''))

        db.connection.commit()
        log_debug(db.logger, f"Indexed email: {email_id.hex()}")

        return SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to index email: {e}")
        db.connection.rollback()
        return SearchErrorCode.ERR_INDEX_ERROR


# ============================================================================
# REBUILD INDEX
# ============================================================================

def rebuild_index(db: DatabaseHandle) -> SearchErrorCode:
    """
    Rebuild the entire FTS5 search index.

    This is useful after bulk imports or if the index becomes corrupted.
    Warning: This can be slow for large databases.

    Args:
        db: Database handle

    Returns:
        SearchErrorCode indicating success or failure

    C signature: SearchErrorCode rebuild_index(DatabaseHandle* db);
    """
    if db is None or db.connection is None:
        return SearchErrorCode.ERR_INVALID_PARAM

    try:
        cursor = db.connection.cursor()

        log_info(db.logger, "Rebuilding FTS5 index...")

        # Use FTS5 rebuild command
        # This is the most efficient way to rebuild the index
        cursor.execute("INSERT INTO Emails_FTS(Emails_FTS) VALUES('rebuild')")

        db.connection.commit()

        # Get index stats
        cursor.execute("SELECT COUNT(*) FROM Emails")
        email_count = cursor.fetchone()[0]

        log_info(db.logger, f"FTS5 index rebuilt successfully. Indexed {email_count} emails.")

        return SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        log_error(db.logger, f"Failed to rebuild index: {e}")
        db.connection.rollback()
        return SearchErrorCode.ERR_INDEX_ERROR


# ============================================================================
# ADDITIONAL HELPER FUNCTIONS
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

    C signature: SearchErrorCode get_search_suggestions(DatabaseHandle* db, const char* prefix,
                                                         int limit, char** out_suggestions, int* out_count);
    """
    if db is None or db.connection is None or not prefix:
        return []

    suggestions = []

    try:
        cursor = db.connection.cursor()

        # Get suggestions from email subjects
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
) -> SearchResult:
    """
    Search emails from a specific sender.

    Args:
        db: Database handle
        sender_id: UserID of the sender
        limit: Maximum results
        offset: Pagination offset

    Returns:
        SearchResult with emails from the sender

    C signature: SearchErrorCode search_by_sender(DatabaseHandle* db, int64_t sender_id,
                                                   int limit, int offset, SearchResult* out_result);
    """
    import time
    start_time = time.perf_counter()

    result = SearchResult()

    if db is None or db.connection is None:
        result.error_code = SearchErrorCode.ERR_INVALID_PARAM
        return result

    try:
        cursor = db.connection.cursor()

        cursor.execute("""
            SELECT
                e.EmailID, e.Subject, e.Body, e.ReceivedTimestamp, e.SentTimestamp,
                e.is_read, e.is_starred, e.is_trashed, e.folder
            FROM Emails e
            JOIN Junction_Email_Users j ON e.EmailID = j.EmailID
            WHERE j.UserID = ? AND j.user_type = 'FROM'
            ORDER BY e.ReceivedTimestamp DESC
            LIMIT ? OFFSET ?
        """, (sender_id, limit, offset))

        for row in cursor.fetchall():
            item = SearchResultItem(
                id=row[0],
                score=0,
                snippet=row[1] or "",  # Subject as snippet
                data={
                    'email_id': row[0].hex() if row[0] else None,
                    'subject': row[1],
                    'body': row[2][:200] if row[2] else None,
                    'received_timestamp': row[3],
                    'sent_timestamp': row[4],
                    'is_read': bool(row[5]),
                    'is_starred': bool(row[6]),
                    'is_trashed': bool(row[7]),
                    'folder': row[8]
                }
            )
            result.items.append(item)

        # Get total count
        cursor.execute("""
            SELECT COUNT(*)
            FROM Junction_Email_Users
            WHERE UserID = ? AND user_type = 'FROM'
        """, (sender_id,))
        result.total_count = cursor.fetchone()[0]

        result.query_time_ms = (time.perf_counter() - start_time) * 1000
        result.error_code = SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        result.error_code = SearchErrorCode.ERR_DATABASE_ERROR
        result.error_message = str(e)
        log_error(db.logger, f"Search by sender failed: {e}")

    return result


def search_by_recipient(
    db: DatabaseHandle,
    recipient_id: int,
    limit: int = 50,
    offset: int = 0
) -> SearchResult:
    """
    Search emails sent to a specific recipient.

    Added based on Sonnet's review suggestion - complement to search_by_sender.

    Args:
        db: Database handle
        recipient_id: UserID of the recipient
        limit: Maximum results
        offset: Pagination offset

    Returns:
        SearchResult with emails sent to the recipient

    C signature: SearchErrorCode search_by_recipient(DatabaseHandle* db, int64_t recipient_id,
                                                      int limit, int offset, SearchResult* out_result);
    """
    import time
    start_time = time.perf_counter()

    result = SearchResult()

    if db is None or db.connection is None:
        result.error_code = SearchErrorCode.ERR_INVALID_PARAM
        return result

    try:
        cursor = db.connection.cursor()

        cursor.execute("""
            SELECT
                e.EmailID, e.Subject, e.Body, e.ReceivedTimestamp, e.SentTimestamp,
                e.is_read, e.is_starred, e.is_trashed, e.folder
            FROM Emails e
            JOIN Junction_Email_Users j ON e.EmailID = j.EmailID
            WHERE j.UserID = ? AND j.user_type IN ('TO', 'CC')
            ORDER BY e.ReceivedTimestamp DESC
            LIMIT ? OFFSET ?
        """, (recipient_id, limit, offset))

        for row in cursor.fetchall():
            item = SearchResultItem(
                id=row[0],
                score=0,
                snippet=row[1] or "",  # Subject as snippet
                data={
                    'email_id': row[0].hex() if row[0] else None,
                    'subject': row[1],
                    'body': row[2][:200] if row[2] else None,
                    'received_timestamp': row[3],
                    'sent_timestamp': row[4],
                    'is_read': bool(row[5]),
                    'is_starred': bool(row[6]),
                    'is_trashed': bool(row[7]),
                    'folder': row[8]
                }
            )
            result.items.append(item)

        # Get total count
        cursor.execute("""
            SELECT COUNT(*)
            FROM Junction_Email_Users
            WHERE UserID = ? AND user_type IN ('TO', 'CC')
        """, (recipient_id,))
        result.total_count = cursor.fetchone()[0]

        result.query_time_ms = (time.perf_counter() - start_time) * 1000
        result.error_code = SearchErrorCode.SUCCESS

    except sqlite3.Error as e:
        result.error_code = SearchErrorCode.ERR_DATABASE_ERROR
        result.error_message = str(e)
        log_error(db.logger, f"Search by recipient failed: {e}")

    return result


def get_folder_counts(db: DatabaseHandle) -> Dict[str, int]:
    """
    Get email counts per folder.

    Args:
        db: Database handle

    Returns:
        Dictionary of folder -> count

    C signature: SearchErrorCode get_folder_counts(DatabaseHandle* db, FolderCount** out_counts, int* out_count);
    """
    if db is None or db.connection is None:
        return {}

    counts = {}

    try:
        cursor = db.connection.cursor()

        cursor.execute("""
            SELECT folder, COUNT(*) as cnt
            FROM Emails
            WHERE is_trashed = 0
            GROUP BY folder
        """)

        for row in cursor.fetchall():
            counts[row[0] or 'inbox'] = row[1]

        # Also count unread
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


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import tempfile
    import os
    import sqlite3

    print("=" * 60)
    print("opus45_search_engine.py - Test Suite")
    print("=" * 60)

    # Create temporary database with schema
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_search.db")

        # Create database and schema manually for testing
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Create tables
        conn.executescript("""
            PRAGMA foreign_keys = ON;

            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY,
                FirstName TEXT,
                MiddleName TEXT,
                LastName TEXT,
                auto_address TEXT,
                Description TEXT,
                contact_count INTEGER DEFAULT 0,
                last_contacted_timestamp DATETIME
            );

            CREATE TABLE Emails (
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

            CREATE VIRTUAL TABLE Emails_FTS USING fts5(
                Subject,
                Body,
                content='Emails',
                content_rowid='rowid'
            );

            CREATE TRIGGER emails_ai AFTER INSERT ON Emails BEGIN
                INSERT INTO Emails_FTS(rowid, Subject, Body) VALUES (new.rowid, new.Subject, new.Body);
            END;

            CREATE TABLE Junction_Email_Users (
                EmailID BLOB,
                UserID INTEGER,
                user_type TEXT,
                PRIMARY KEY (EmailID, UserID, user_type)
            );

            CREATE TABLE QMailServers (
                QMailServerID INTEGER PRIMARY KEY,
                IPAddress TEXT,
                PortNumb INTEGER,
                server_type TEXT,
                ping_ms INTEGER,
                number_of_calls INTEGER DEFAULT 0,
                amount_of_credit TEXT
            );
        """)

        # Insert test data
        import uuid

        # Insert users
        conn.execute("INSERT INTO Users (UserID, FirstName, LastName, auto_address, contact_count) VALUES (1, 'John', 'Doe', 'john@qmail.net', 5)")
        conn.execute("INSERT INTO Users (UserID, FirstName, LastName, auto_address, contact_count) VALUES (2, 'Jane', 'Smith', 'jane@qmail.net', 3)")

        # Insert emails
        email1_id = uuid.uuid4().bytes
        email2_id = uuid.uuid4().bytes
        email3_id = uuid.uuid4().bytes

        conn.execute("""
            INSERT INTO Emails (EmailID, Subject, Body, ReceivedTimestamp, folder, is_read)
            VALUES (?, 'Hello World', 'This is a test email about Python programming.', '2025-12-10 10:00:00', 'inbox', 0)
        """, (email1_id,))

        conn.execute("""
            INSERT INTO Emails (EmailID, Subject, Body, ReceivedTimestamp, folder, is_read, is_starred)
            VALUES (?, 'Meeting Tomorrow', 'Lets discuss the project timeline and deliverables.', '2025-12-11 09:00:00', 'inbox', 1, 1)
        """, (email2_id,))

        conn.execute("""
            INSERT INTO Emails (EmailID, Subject, Body, ReceivedTimestamp, folder, is_trashed)
            VALUES (?, 'Old Newsletter', 'Subscribe to our Python newsletter for tips.', '2025-12-01 08:00:00', 'inbox', 1)
        """, (email3_id,))

        # Link emails to users
        conn.execute("INSERT INTO Junction_Email_Users VALUES (?, 1, 'FROM')", (email1_id,))
        conn.execute("INSERT INTO Junction_Email_Users VALUES (?, 2, 'FROM')", (email2_id,))

        conn.commit()

        # Create database handle
        handle = DatabaseHandle(connection=conn, path=db_path, logger=None)

        print(f"\n   Database created with test data at {db_path}")

        # Test 1: Simple full-text search
        print("\n1. Testing search_emails() with FTS...")
        query = SearchQuery(terms="Python")
        result = search_emails(handle, query)
        assert result.error_code == SearchErrorCode.SUCCESS
        assert len(result.items) >= 1
        print(f"   SUCCESS: Found {len(result.items)} email(s) matching 'Python'")
        for item in result.items:
            print(f"     - {item.data['subject']} (score: {item.score:.2f})")

        # Test 2: Phrase search
        print("\n2. Testing phrase search...")
        query = SearchQuery(terms='"test email"')
        result = search_emails(handle, query)
        assert result.error_code == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Found {len(result.items)} email(s) matching '\"test email\"'")

        # Test 3: Filter by folder
        print("\n3. Testing folder filter...")
        query = SearchQuery(folder="inbox", is_trashed=False)
        result = search_emails(handle, query)
        assert result.error_code == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Found {len(result.items)} email(s) in inbox (not trashed)")

        # Test 4: Filter by read status
        print("\n4. Testing read status filter...")
        query = SearchQuery(is_read=False)
        result = search_emails(handle, query)
        print(f"   SUCCESS: Found {len(result.items)} unread email(s)")

        # Test 5: Search contacts
        print("\n5. Testing search_contacts()...")
        query = SearchQuery(terms="John")
        result = search_contacts(handle, query)
        assert result.error_code == SearchErrorCode.SUCCESS
        assert len(result.items) >= 1
        print(f"   SUCCESS: Found {len(result.items)} contact(s) matching 'John'")
        for item in result.items:
            print(f"     - {item.snippet} ({item.data['auto_address']})")

        # Test 6: Build query
        print("\n6. Testing build_query()...")
        query = SearchQuery(terms="hello", folder="inbox", is_read=True)
        sql, params = build_query(query, "emails")
        assert "MATCH" in sql
        assert "folder" in sql
        print(f"   SUCCESS: Built FTS query with {len(params)} parameters")

        # Test 7: Index email
        print("\n7. Testing index_email()...")
        err = index_email(handle, email1_id)
        assert err == SearchErrorCode.SUCCESS
        print("   SUCCESS: Re-indexed email")

        # Test 8: Rebuild index
        print("\n8. Testing rebuild_index()...")
        err = rebuild_index(handle)
        assert err == SearchErrorCode.SUCCESS
        print("   SUCCESS: Rebuilt FTS5 index")

        # Test 9: Get folder counts
        print("\n9. Testing get_folder_counts()...")
        counts = get_folder_counts(handle)
        assert 'inbox' in counts or 'unread' in counts
        print(f"   SUCCESS: Got folder counts:")
        for folder, count in counts.items():
            print(f"     - {folder}: {count}")

        # Test 10: Search by sender
        print("\n10. Testing search_by_sender()...")
        result = search_by_sender(handle, sender_id=1)
        assert result.error_code == SearchErrorCode.SUCCESS
        print(f"   SUCCESS: Found {len(result.items)} email(s) from sender 1")

        # Test 11: Query sanitization
        print("\n11. Testing query sanitization...")
        dangerous = 'test; DROP TABLE Emails; --'
        sanitized = _sanitize_fts_query(dangerous)
        assert "DROP" not in sanitized or ";" not in sanitized
        print(f"   SUCCESS: Sanitized '{dangerous}' -> '{sanitized}'")

        # Cleanup
        conn.close()

        print("\n" + "=" * 60)
        print("All tests passed!")
        print("=" * 60)
