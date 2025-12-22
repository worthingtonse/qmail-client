"""
gemini_search_engine.py - Search Engine Module for QMail Client Core (v2)

This module provides functions for building and executing search queries.
Version 2 is enhanced with features inspired by peer review (opus45),
such as FTS5 snippets, relevance ranking, and more detailed query filters,
while maintaining architectural integrity by using shared data types.

Author: Gemini
Phase: I
"""

import time
import re
from typing import List, Optional, Tuple, Dict, Any

# The user stated opus45_database.py was promoted, so we will use it.
# It is assumed to be available as 'database.py'.
from . import opus45_database as database
from .qmail_types import SearchQuery, SearchResult, SearchResultItem

# ============================================================================
# HELPER - FTS Query Sanitizer
# ============================================================================

def _sanitize_fts_query(query: str) -> str:
    """
    Sanitizes user input for FTS5 queries.
    Preserves valid operators (OR, AND, NOT, -, *) and phrases.
    """
    if not query:
        return ""
    # Protect phrases in quotes
    phrases = re.findall(r'"[^"]+"', query)
    placeholder = "__PHRASE_{}__"
    
    # Replace phrases with placeholders
    for i, phrase in enumerate(phrases):
        query = query.replace(phrase, placeholder.format(i))
    
    # Allow specific keywords and characters, remove the rest
    # Allowed: alphanumeric, *, -, and the placeholders
    query = ' '.join(re.findall(r'__PHRASE_\d+__|[a-zA-Z0-9\*\-]+|OR|AND|NOT', query, re.IGNORECASE))
    
    # Put phrases back
    for i, phrase in enumerate(phrases):
        query = query.replace(placeholder.format(i), phrase)
        
    return query

# ============================================================================
# QUERY BUILDER (v2)
# ============================================================================

def build_query(search_type: str, query: SearchQuery, is_count_query: bool = False) -> Tuple[str, list]:
    """
    Builds a SQL query string and parameter list from a SearchQuery object.
    (v2 is enhanced with features from opus45_search_engine)
    """
    params = []
    
    if search_type == "emails":
        # Combine main terms and field-specific terms into an FTS expression
        fts_parts = []
        if query.terms: fts_parts.append(_sanitize_fts_query(query.terms))
        if query.subject: fts_parts.append(f"Subject:{_sanitize_fts_query(query.subject)}")
        if query.body: fts_parts.append(f"Body:{_sanitize_fts_query(query.body)}")
        fts_expression = " ".join(fts_parts)

        # Base query structure
        select_clause = "SELECT COUNT(*) as cnt" if is_count_query else "SELECT e.*, bm25(Emails_FTS) as score, snippet(Emails_FTS, 0, '<b>', '</b>', '...', 20) as snippet"
        sql = f"{select_clause} FROM Emails e JOIN Emails_FTS fts ON e.rowid = fts.rowid"
        
        where_clauses = []
        if fts_expression:
            where_clauses.append("fts.Emails_FTS MATCH ?")
            params.append(fts_expression)

        # Add filters from the SearchQuery object
        if query.folder:
            where_clauses.append("e.folder = ?")
            params.append(query.folder)
        if query.is_read is not None:
            where_clauses.append("e.is_read = ?")
            params.append(1 if query.is_read else 0)
        if query.is_starred is not None:
            where_clauses.append("e.is_starred = ?")
            params.append(1 if query.is_starred else 0)
        if query.date_from:
            where_clauses.append("e.ReceivedTimestamp >= ?")
            params.append(query.date_from)
        if query.date_to:
            where_clauses.append("e.ReceivedTimestamp <= ?")
            params.append(query.date_to + " 23:59:59")
        if query.has_attachments is not None:
            if query.has_attachments:
                where_clauses.append("e.EmailID IN (SELECT DISTINCT EmailID FROM Attachments)")
            else:
                where_clauses.append("e.EmailID NOT IN (SELECT DISTINCT EmailID FROM Attachments)")

        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)

        if not is_count_query:
            # Sorting
            if query.sort_by == 'rank' and fts_expression:
                # bm25 returns lower values for more relevant, so ASC
                sql += " ORDER BY score"
            elif query.sort_by:
                order_dir = "DESC" if query.sort_desc else "ASC"
                # Prevent SQL injection by checking against a safe list of columns
                if query.sort_by in ['ReceivedTimestamp', 'SentTimestamp', 'Subject', 'folder']:
                    sql += f" ORDER BY e.{query.sort_by} {order_dir}"

            # Pagination
            sql += " LIMIT ? OFFSET ?"
            params.extend([query.limit, query.offset])

    elif search_type == "contacts":
        # Similar logic for contacts
        select_clause = "SELECT COUNT(*) as cnt" if is_count_query else "SELECT *"
        sql = f"{select_clause} FROM Users"
        
        if query.terms:
            like_term = f"%{query.terms}%"
            sql += " WHERE (FirstName LIKE ? OR LastName LIKE ? OR auto_address LIKE ?)"
            params.extend([like_term, like_term, like_term])
        
        if not is_count_query:
            sql += " ORDER BY contact_count DESC LIMIT ? OFFSET ?"
            params.extend([query.limit, query.offset])
    else:
        raise ValueError(f"Unknown search_type: {search_type}")

    return sql, params

# ============================================================================
# CORE SEARCH FUNCTIONS (v2)
# ============================================================================

def search_emails(db: database.DatabaseHandle, query: SearchQuery) -> Tuple[database.DatabaseErrorCode, Optional[SearchResult]]:
    """Searches emails using FTS5, with enhanced features."""
    start_time = time.time()
    try:
        # Build main query
        sql, params = build_query("emails", query)
        error_code, results_data = database.execute_query(db, sql, tuple(params))
        if error_code != database.DatabaseErrorCode.SUCCESS:
            return error_code, None
            
        # Build count query
        count_sql, count_params = build_query("emails", query, is_count_query=True)
        count_error_code, count_results = database.execute_query(db, count_sql, tuple(count_params))
        total_count = count_results[0]['cnt'] if count_error_code == database.DatabaseErrorCode.SUCCESS and count_results else 0
        
        # Package results into SearchResultItem objects
        items = [SearchResultItem(id=row['EmailID'], score=row.get('score', 0), snippet=row.get('snippet', ''), data=row) for row in results_data]

        search_result = SearchResult(
            items=items,
            total_count=total_count,
            elapsed_time=time.time() - start_time
        )
        return database.DatabaseErrorCode.SUCCESS, search_result
        
    except Exception as e:
        database.log_error(db.logger, f"An unexpected error occurred in search_emails: {e}")
        return database.DatabaseErrorCode.ERR_QUERY_FAILED, None

def search_contacts(db: database.DatabaseHandle, query: SearchQuery) -> Tuple[database.DatabaseErrorCode, Optional[SearchResult]]:
    """Searches contacts using SQL LIKE queries."""
    start_time = time.time()
    try:
        sql, params = build_query("contacts", query)
        error_code, results_data = database.execute_query(db, sql, tuple(params))
        if error_code != database.DatabaseErrorCode.SUCCESS:
            return error_code, None

        count_sql, count_params = build_query("contacts", query, is_count_query=True)
        count_error_code, count_results = database.execute_query(db, count_sql, tuple(count_params))
        total_count = count_results[0]['cnt'] if count_error_code == database.DatabaseErrorCode.SUCCESS and count_results else 0

        items = [SearchResultItem(id=row['UserID'], data=row) for row in results_data]

        search_result = SearchResult(
            items=items,
            total_count=total_count,
            elapsed_time=time.time() - start_time
        )
        return database.DatabaseErrorCode.SUCCESS, search_result
        
    except Exception as e:
        database.log_error(db.logger, f"An unexpected error occurred in search_contacts: {e}")
        return database.DatabaseErrorCode.ERR_QUERY_FAILED, None

def index_email(db: database.DatabaseHandle, email: dict) -> None:
    """No-op due to automatic FTS5 triggers."""
    database.log_debug(db.logger, "index_email is a no-op due to automatic FTS5 triggers.")
    pass

def rebuild_index(db: database.DatabaseHandle) -> Tuple[database.DatabaseErrorCode, None]:
    """Triggers a rebuild of the FTS index."""
    sql = "INSERT INTO Emails_FTS(Emails_FTS) VALUES('rebuild');"
    error_code, _ = database.execute_query(db, sql)
    if error_code == database.DatabaseErrorCode.SUCCESS:
        database.log_info(db.logger, "Successfully triggered FTS index rebuild.")
    else:
        database.log_error(db.logger, "Failed to trigger FTS index rebuild.")
    return error_code, None

# ============================================================================
# HELPER FUNCTIONS (Inspired by opus45)
# ============================================================================

def get_folder_counts(db: database.DatabaseHandle) -> Tuple[database.DatabaseErrorCode, Optional[Dict[str, int]]]:
    """Gets email counts per folder and for special views like 'unread'."""
    if not db or not db.connection:
        return database.DatabaseErrorCode.ERR_INVALID_PARAM, None
    try:
        sql = """
            SELECT folder, COUNT(*) FROM Emails WHERE is_trashed = 0 GROUP BY folder
            UNION ALL
            SELECT 'unread', COUNT(*) FROM Emails WHERE is_read = 0 AND is_trashed = 0
            UNION ALL
            SELECT 'starred', COUNT(*) FROM Emails WHERE is_starred = 1 AND is_trashed = 0
            UNION ALL
            SELECT 'trash', COUNT(*) FROM Emails WHERE is_trashed = 1
        """
        error_code, results = database.execute_query(db, sql)
        if error_code != database.DatabaseErrorCode.SUCCESS:
            return error_code, None
        
        counts = {row[0]: row[1] for row in results if row and row[0]}
        return database.DatabaseErrorCode.SUCCESS, counts

    except Exception as e:
        database.log_error(db.logger, f"Failed to get folder counts: {e}")
        return database.DatabaseErrorCode.ERR_QUERY_FAILED, None

def get_search_suggestions(db: database.DatabaseHandle, prefix: str, limit: int = 10) -> Tuple[database.DatabaseErrorCode, Optional[List[str]]]:
    """Gets search term suggestions based on a prefix from subjects and contacts."""
    if not db or not db.connection or not prefix:
        return database.DatabaseErrorCode.ERR_INVALID_PARAM, None
    try:
        sql = "SELECT DISTINCT Subject FROM Emails WHERE Subject LIKE ? LIMIT ?"
        error_code, results = database.execute_query(db, sql, (f"{prefix}%", limit))
        if error_code != database.DatabaseErrorCode.SUCCESS:
            return error_code, None
        
        suggestions = [row['Subject'] for row in results]
        return database.DatabaseErrorCode.SUCCESS, suggestions
        
    except Exception as e:
        database.log_error(db.logger, f"Failed to get suggestions: {e}")
        return database.DatabaseErrorCode.ERR_QUERY_FAILED, None
