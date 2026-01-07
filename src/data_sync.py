"""
data_sync.py - External Data Synchronization Module

Downloads and syncs user directory and server list from RAIDA.
Designed for easy C portability using standard HTTP and JSON.

Author: Claude Opus 4.5
Date: 2025-12-17
Phase: I
"""

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from enum import IntEnum
from datetime import datetime

# Import database functions
from database import (
    DatabaseHandle,
    DatabaseErrorCode,
    upsert_user,
    upsert_server,
    get_parity_server,
    set_parity_server,
    get_user_count,
    get_server_count
)

# Import logger functions
from logger import log_info, log_error, log_warning, log_debug

# Module context for logging
SYNC_CONTEXT = "DataSync"


# ============================================================================
# ERROR CODES
# ============================================================================

class SyncErrorCode(IntEnum):
    """Error codes for sync operations."""
    SUCCESS = 0
    ERR_NETWORK = 1
    ERR_PARSE = 2
    ERR_DATABASE = 3
    ERR_INVALID_DATA = 4
    ERR_TIMEOUT = 5


# ============================================================================
# JSON DOWNLOAD
# ============================================================================

def download_json(
    url: str,
    timeout_sec: int = 30,
    logger_handle=None
) -> Tuple[SyncErrorCode, Optional[Dict]]:
    """
    Download JSON data from URL.

    Uses urllib (standard library) for C portability.
    C equivalent: libcurl or platform HTTP APIs.

    Args:
        url: URL to fetch
        timeout_sec: Request timeout in seconds
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, parsed JSON dict or None)

    C signature: SyncErrorCode download_json(const char* url, int timeout_sec,
                                              JsonObject** out_json);
    """
    log_debug(logger_handle, SYNC_CONTEXT, f"Downloading: {url}")

    try:
        # Create request with timeout
        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'QMail-Client/1.0'}
        )

        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            # Read response body
            body = response.read().decode('utf-8')

            # Parse JSON
            try:
                data = json.loads(body)
                log_debug(logger_handle, SYNC_CONTEXT,
                          f"Downloaded {len(body)} bytes from {url}")
                return SyncErrorCode.SUCCESS, data
            except json.JSONDecodeError as e:
                log_error(logger_handle, SYNC_CONTEXT,
                          f"JSON parse error from {url}", str(e))
                return SyncErrorCode.ERR_PARSE, None

    except urllib.error.URLError as e:
        log_error(logger_handle, SYNC_CONTEXT,
                  f"Network error fetching {url}", str(e))
        return SyncErrorCode.ERR_NETWORK, None
    except TimeoutError:
        log_error(logger_handle, SYNC_CONTEXT, f"Timeout fetching {url}")
        return SyncErrorCode.ERR_TIMEOUT, None
    except Exception as e:
        log_error(logger_handle, SYNC_CONTEXT,
                  f"Unexpected error fetching {url}", str(e))
        return SyncErrorCode.ERR_NETWORK, None


# ============================================================================
# CSV DOWNLOAD AND PARSING
# ============================================================================

def download_text(
    url: str,
    timeout_sec: int = 30,
    logger_handle=None
) -> Tuple[SyncErrorCode, Optional[str]]:
    """
    Download text/CSV data from URL.

    Uses urllib (standard library) for C portability.

    Args:
        url: URL to fetch
        timeout_sec: Request timeout in seconds
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, text content or None)

    C signature: SyncErrorCode download_text(const char* url, int timeout_sec,
                                              char** out_text);
    """
    log_debug(logger_handle, SYNC_CONTEXT, f"Downloading text: {url}")

    try:
        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'QMail-Client/1.0'}
        )

        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            body = response.read().decode('utf-8')
            log_debug(logger_handle, SYNC_CONTEXT,
                      f"Downloaded {len(body)} bytes from {url}")
            return SyncErrorCode.SUCCESS, body

    except urllib.error.URLError as e:
        log_error(logger_handle, SYNC_CONTEXT,
                  f"Network error fetching {url}", str(e))
        return SyncErrorCode.ERR_NETWORK, None
    except TimeoutError:
        log_error(logger_handle, SYNC_CONTEXT, f"Timeout fetching {url}")
        return SyncErrorCode.ERR_TIMEOUT, None
    except Exception as e:
        log_error(logger_handle, SYNC_CONTEXT,
                  f"Unexpected error fetching {url}", str(e))
        return SyncErrorCode.ERR_NETWORK, None


def parse_users_csv(csv_text: str, logger_handle=None) -> List[Dict]:
    """
    Parses the new Supervisor CSV format:
    FirstName, LastName, CustomSerialNumber, Description, InboxFee, Class, Beacon
    """
    import csv
    import io
    
    users = []
    # Use csv module to handle potential quotes or commas in descriptions
    f = io.StringIO(csv_text.strip())
    reader = csv.reader(f)
    
    header_skipped = False
    line_num = 0
    
    for row in reader:
        line_num += 1
        if not row: continue
        
        # 1. Skip Header
        if not header_skipped:
            header_skipped = True
            continue
            
        try:
            # 2. Map indices to new Supervisor format
            # row[0]: FirstName, row[1]: LastName, row[2]: CustomSerialNumber
            # row[3]: Description, row[4]: InboxFee, row[5]: Class, row[6]: Beacon
            
            first_name = row[0].strip()
            last_name = row[1].strip()
            custom_sn = row[2].strip() # e.g., "C23"
            description = row[3].strip()
            
            # InboxFee normalization (Flat fee per message)
            try:
                inbox_fee = float(row[4].strip())
            except:
                inbox_fee = 0.0
                
            user_class = row[5].strip()
            beacon = row[6].strip()
            
            # 3. Create standardized user dictionary
            user_dict = {
                'custom_sn': custom_sn,
                'first_name': first_name,
                'last_name': last_name,
                'description': description,
                'inbox_fee': inbox_fee,
                'class': user_class,
                'beacon': beacon
            }
            users.append(user_dict)
            
        except Exception as e:
            from logger import log_warning
            log_warning(logger_handle, "DataSync", f"Line {line_num}: Parse error ({e}), skipping")
            
    return users

# ============================================================================
# DATA VALIDATION
# ============================================================================

def validate_user(user: Dict) -> bool:
    """
    Validate user data from CSV or JSON.

    Simple manual validation (no external dependencies).

    Args:
        user: User dict to validate

    Returns:
        True if valid, False otherwise

    C signature: bool validate_user(const JsonObject* user);
    """
    # Required fields
    if 'user_id' not in user:
        return False

    # Type checks
    user_id = user.get('user_id')
    if not isinstance(user_id, (int, float)):
        return False

    # Optional field type checks
    if 'first_name' in user and not isinstance(user['first_name'], str):
        return False
    if 'last_name' in user and not isinstance(user['last_name'], str):
        return False
    if 'streak' in user and not isinstance(user['streak'], (int, float)):
        return False

    return True


def validate_server(server: Dict) -> bool:
    """
    Validate server data from JSON.

    Args:
        server: Server dict to validate

    Returns:
        True if valid, False otherwise

    C signature: bool validate_server(const JsonObject* server);
    """
    # Required fields
    if 'server_id' not in server:
        return False
    if 'ip_address' not in server:
        return False

    # Type checks
    if not isinstance(server['server_id'], str):
        return False
    if not isinstance(server['ip_address'], str):
        return False
    if 'port' in server and not isinstance(server['port'], (int, float)):
        return False

    return True


# ============================================================================
# SYNC USERS
# ============================================================================

def sync_users(
    db_handle,
    url: str,
    timeout_sec: int = 30,
    logger_handle=None
) -> Tuple[SyncErrorCode, int]:
    """
    Download users CSV and sync to database using the new Supervisor format.
    """
    from data_sync import download_text, SyncErrorCode
    from database import upsert_user, DatabaseErrorCode
    from logger import log_info, log_warning
    
    log_info(logger_handle, "DataSync", f"Syncing users from: {url}")

    # 1. Download CSV text
    err, csv_text = download_text(url, timeout_sec, logger_handle)
    if err != SyncErrorCode.SUCCESS:
        return err, 0

    if not csv_text:
        log_warning(logger_handle, "DataSync", "Empty response from users URL")
        return SyncErrorCode.SUCCESS, 0

    # 2. Parse CSV (Using the corrected helper above)
    users = parse_users_csv(csv_text, logger_handle)

    if not users:
        log_warning(logger_handle, "DataSync", "No users found in CSV or parse failed")
        return SyncErrorCode.SUCCESS, 0

    # 3. Sync to database
    synced_count = 0
    for user in users:
        # Upsert ensures we update existing 'C23' records
        db_err = upsert_user(db_handle, user)
        if db_err == DatabaseErrorCode.SUCCESS:
            synced_count += 1

    log_info(logger_handle, "DataSync", f"Synced {synced_count} users successfully")
    return SyncErrorCode.SUCCESS, synced_count


# ============================================================================
# SYNC SERVERS
# ============================================================================

def sync_servers(
    db_handle: DatabaseHandle,
    url: str,
    timeout_sec: int = 30,
    logger_handle=None
) -> Tuple[SyncErrorCode, int]:
    """
    Download QMail servers from server and sync to database.

    Also handles automatic parity server designation if not set.

    Args:
        db_handle: Database handle
        url: Servers JSON URL
        timeout_sec: Request timeout
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, number of servers synced)

    C signature: SyncErrorCode sync_servers(DatabaseHandle* db, const char* url,
                                             int timeout_sec, int* out_count);
    """
    log_info(logger_handle, SYNC_CONTEXT, f"Syncing servers from: {url}")

    # Download JSON
    err, data = download_json(url, timeout_sec, logger_handle)
    if err != SyncErrorCode.SUCCESS:
        return err, 0

    # Extract servers array - handle both wrapped and unwrapped formats
    servers = []
    if isinstance(data, list):
        servers = data
    elif isinstance(data, dict):
        servers = data.get('servers', [])

    if not servers:
        log_warning(logger_handle, SYNC_CONTEXT,
                    "No servers found in response")
        return SyncErrorCode.SUCCESS, 0

    # Sync each server to database
    synced_count = 0
    invalid_count = 0
    last_server_id = None

    for server in servers:
        # Validate
        if not validate_server(server):
            invalid_count += 1
            continue

        # Upsert to database
        db_err = upsert_server(db_handle, server)
        if db_err == DatabaseErrorCode.SUCCESS:
            synced_count += 1
            last_server_id = server.get('server_id')
        else:
            log_warning(logger_handle, SYNC_CONTEXT,
                        f"Failed to sync server {server.get('server_id')}: {db_err}")

    if invalid_count > 0:
        log_warning(logger_handle, SYNC_CONTEXT,
                    f"Skipped {invalid_count} invalid server records")

    # Auto-configure parity server if not set
    if synced_count > 0:
        _, parity_server = get_parity_server(db_handle)
        if parity_server is None and last_server_id:
            log_info(logger_handle, SYNC_CONTEXT,
                     f"Auto-configuring parity server: {last_server_id}")
            set_parity_server(db_handle, last_server_id)

    log_info(logger_handle, SYNC_CONTEXT, f"Synced {synced_count} servers")
    return SyncErrorCode.SUCCESS, synced_count


# ============================================================================
# SYNC ALL
# ============================================================================

def sync_all(
    db_handle: DatabaseHandle,
    users_url: str,
    servers_url: str,
    timeout_sec: int = 30,
    logger_handle=None
) -> Tuple[SyncErrorCode, Dict[str, int]]:
    """
    Perform full sync of users and servers.

    Called on startup and available via API for manual refresh.

    Args:
        db_handle: Database handle
        users_url: URL for users JSON
        servers_url: URL for servers JSON
        timeout_sec: Request timeout
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, {"users": count, "servers": count})

    C signature: SyncErrorCode sync_all(DatabaseHandle* db, const char* users_url,
                                         const char* servers_url, int timeout_sec,
                                         SyncResult* out_result);
    """
    log_info(logger_handle, SYNC_CONTEXT, "Starting full data sync...")

    result = {"users": 0, "servers": 0}
    overall_error = SyncErrorCode.SUCCESS

    # Sync users
    users_err, users_count = sync_users(
        db_handle, users_url, timeout_sec, logger_handle)
    result["users"] = users_count
    if users_err != SyncErrorCode.SUCCESS:
        log_warning(logger_handle, SYNC_CONTEXT,
                    f"User sync failed: {users_err}")
        overall_error = users_err

    # Sync servers
    servers_err, servers_count = sync_servers(
        db_handle, servers_url, timeout_sec, logger_handle)
    result["servers"] = servers_count
    if servers_err != SyncErrorCode.SUCCESS:
        log_warning(logger_handle, SYNC_CONTEXT,
                    f"Server sync failed: {servers_err}")
        # Only update overall error if users didn't fail
        if overall_error == SyncErrorCode.SUCCESS:
            overall_error = servers_err

    # Get final counts from database
    _, total_users = get_user_count(db_handle)
    _, total_servers = get_server_count(db_handle)

    log_info(logger_handle, SYNC_CONTEXT,
             f"Sync complete. Database now has {total_users} users and {total_servers} servers")

    return overall_error, result


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import sys
    import os

    # Add project root to path
    _src_dir = os.path.dirname(os.path.abspath(__file__))
    _project_root = os.path.dirname(_src_dir)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    os.chdir(_project_root)

    from src.database import init_database, close_database
    from src.logger import init_logger, close_logger

    print("=" * 60)
    print("data_sync.py - Test Suite")
    print("=" * 60)

    # Initialize logger
    logger = init_logger("Data/test_sync.mlog")

    # Initialize database
    db_err, db_handle = init_database("Data/test_sync.db", logger=logger)
    if db_err != DatabaseErrorCode.SUCCESS:
        print(f"Failed to init database: {db_err}")
        sys.exit(1)

    # Test URLs (using the real RAIDA server)
    USERS_URL = "https://raida11.cloudcoin.global/service/users"
    SERVERS_URL = "https://raida11.cloudcoin.global/service/qmail_servers"

    print(f"\n1. Testing download_json()...")
    err, data = download_json(USERS_URL, timeout_sec=30, logger_handle=logger)
    if err == SyncErrorCode.SUCCESS:
        print(f"   SUCCESS: Downloaded users data")
        if isinstance(data, dict):
            print(f"   Format: Object with keys: {list(data.keys())}")
        elif isinstance(data, list):
            print(f"   Format: Array with {len(data)} items")
    else:
        print(f"   ERROR: {err}")

    print(f"\n2. Testing sync_all()...")
    err, result = sync_all(db_handle, USERS_URL, SERVERS_URL,
                           timeout_sec=30, logger_handle=logger)
    print(f"   Result: {err}")
    print(f"   Users synced: {result['users']}")
    print(f"   Servers synced: {result['servers']}")

    # Verify parity server was auto-configured
    print(f"\n3. Checking parity server configuration...")
    _, parity = get_parity_server(db_handle)
    if parity:
        print(f"   Parity server: {parity['server_id']}")
    else:
        print("   No parity server configured")

    # Cleanup
    close_database(db_handle)
    close_logger(logger)

    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)
