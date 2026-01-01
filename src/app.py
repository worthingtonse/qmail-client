#!/usr/bin/env python3
"""
app.py - QMail Client Core Application Entry Point

This is the main entry point for the QMail Client Core application.
It initializes all components and starts the REST API server.

Usage:
    python src/app.py --port 8080
    python src/app.py --port 8080 --config config/qmail.toml

Author: Claude Opus 4.5
Date: 2025-12-16
Phase: I (Stub Implementation)
"""

import sys
import os
import argparse
import time
from dataclasses import dataclass
from typing import Any, Optional

# Detect if running as a bundled EXE or as a script
if getattr(sys, 'frozen', False):
    # Running as EXE: Use the directory of the executable
    _project_root = os.path.dirname(sys.executable)
else:
    # Running as script: Use the directory of app.py and go up one level
    _src_dir = os.path.dirname(os.path.abspath(__file__))
    _project_root = os.path.dirname(_src_dir)

# Add project root to path so 'src' can be imported as a package
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Change to project root so relative paths in config work correctly
os.chdir(_project_root)

# Import src modules - use package imports to ensure relative imports work in modules
from src.config import load_config, validate_config, print_config_summary, get_default_config_path
from src.logger import init_logger, close_logger, log_info, log_error, log_warning, LogLevel
from src.api_server import APIServer
from src.api_handlers import register_all_routes
from src.database import (
    init_database, close_database, DatabaseErrorCode,
    store_received_tell, store_received_stripe, get_all_servers
)
from src.beacon import init_beacon, start_beacon_monitor, stop_beacon_monitor, do_peek
from src.thread_pool import create_pool, destroy_pool
from src.task_manager import init_task_manager, shutdown_task_manager
from src.data_sync import sync_all, SyncErrorCode
from src.wallet_structure import initialize_wallet_structure
import threading


# ============================================================================
# APP CONTEXT
# ============================================================================

@dataclass
class AppContext:
    """
    Shared application resources available to all handlers.

    Handlers access this via: request_handler.server_instance.app_context

    Task Manager Lifecycle:
        - Initialized: run_server() calls init_task_manager(logger) before creating AppContext
        - Stored: Assigned to app_context.task_manager during AppContext creation
        - Used: API handlers access via app_ctx.task_manager for async task tracking
        - Shutdown: run_server() calls shutdown_task_manager() during cleanup
        - May be None if initialization fails (handlers should check before use)
    """
    config: Any
    db_handle: Any
    logger: Any
    thread_pool: Any = None      # Thread pool for parallel tasks
    task_manager: Any = None     # Task tracking system (see docstring for lifecycle)
    beacon_handle: Any = None    # Optional - may fail to init if keys not configured
    # Thread-safe storage for beacon notifications
    _notifications: list = None
    _notifications_lock: threading.Lock = None
    # Server IP cache for beacon callback (refreshable)
    _server_cache: dict = None

    def __post_init__(self):
        """Initialize thread-safe notification storage and server cache."""
        self._notifications = []
        self._notifications_lock = threading.Lock()
        self._server_cache = {}

    def add_notifications(self, notifications):
        """Thread-safe method to add new notifications from beacon callback."""
        with self._notifications_lock:
            self._notifications.extend(notifications)

    def get_and_clear_notifications(self):
        """Thread-safe method to get and clear pending notifications."""
        with self._notifications_lock:
            result = self._notifications.copy()
            self._notifications.clear()
            return result

    def get_notifications(self):
        """Thread-safe method to get notifications without clearing."""
        with self._notifications_lock:
            return self._notifications.copy()

    def refresh_server_cache(self):
        """
        Refresh the server IP cache from database.
        Handles both integer and 'RAIDAxx' string IDs.
        """
        if self.db_handle is None:
            return False

        err, servers = get_all_servers(self.db_handle, available_only=False)
        if err == DatabaseErrorCode.SUCCESS:
            new_cache = {}
            for srv in servers:
                # Use server_id if available, else id, else -1
                raw_id = srv.get('server_id', srv.get('id', -1))
                ip_address = srv.get('ip_address', srv.get('IPAddress', ''))
                
                #  Verify the ID is valid (int >= 0 OR a non-empty string)
                is_valid = (isinstance(raw_id, int) and raw_id >= 0) or \
                           (isinstance(raw_id, str) and raw_id.strip() != "")
                
                if is_valid and ip_address:
                    new_cache[raw_id] = ip_address
            
            self._server_cache = new_cache
            if self.logger:
                log_info(self.logger, "AppContext", 
                         f"Server cache refreshed: {len(new_cache)} servers")
            return True
        return False

    def get_server_ip(self, server_id: int) -> str:
        """
        Get server IP from cache.

        Args:
            server_id: The server ID to look up

        Returns:
            str: IP address or empty string if not found
        """
        return self._server_cache.get(server_id, '')


# ============================================================================
# CONSTANTS
# ============================================================================

APP_NAME = "QMail Client Core"
APP_VERSION = "1.0.0-phase1"


# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_arguments():
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace with parsed arguments
    """
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} - Headless Email Backend Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python src/app.py                    # Start on default port 8080
    python src/app.py --port 8091        # Start on port 8091
    python src/app.py --debug            # Enable debug logging
    python src/app.py --skip-sync        # Skip data sync on startup

API Endpoints:
    GET  /api/health                - Health check
    GET  /api/qmail/ping            - Check for new mail (beacon)
    POST /api/mail/send             - Send email
    GET  /api/mail/download/{id}    - Download email
    GET  /api/mail/list             - List emails in folder
    POST /api/mail/create-mailbox   - Create new mailbox
    GET  /api/data/contacts/popular - Get frequent contacts
    GET  /api/data/emails/search    - Search emails
    GET  /api/data/users/search     - Search users
    GET  /api/data/servers          - Get QMail servers
    POST /api/admin/sync            - Trigger data sync
    POST /api/admin/servers/parity  - Set parity server
    GET  /api/task/status/{id}      - Check task status
    POST /api/task/cancel/{id}      - Cancel task
        """
    )

    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port number for the API server (default: 8080)'
    )

    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to configuration file (default: config/qmail.toml)'
    )

    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging level'
    )

    parser.add_argument(
        '--no-beacon',
        action='store_true',
        help='Disable beacon monitoring'
    )

    parser.add_argument(
        '--skip-sync',
        action='store_true',
        help='Skip user/server data sync on startup'
    )

    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'{APP_NAME} {APP_VERSION}'
    )

    return parser.parse_args()


# ============================================================================
# INITIALIZATION
# ============================================================================
def initialize_application(args):
    """
    Initialize all application components.
    FIXED: Robust identity scanner detects coins by SN pattern (Hex or Decimal).
    """
    # Determine config path
    config_path = args.config if args.config else get_default_config_path()
    print(f"[INIT] Loading configuration from: {config_path}")

    # Load configuration
    config = load_config(config_path)
    if config is None:
        print(f"[ERROR] Failed to load configuration from: {config_path}")
        return None, None

    # Validate configuration
    validation = validate_config(config)
    if validation.errors:
        print("[ERROR] Configuration validation failed:")
        for error in validation.errors:
            print(f"  - {error}")
        return None, None

    # Initialize logger
    log_level = LogLevel.DEBUG if args.debug else LogLevel.INFO
    logger = init_logger(config.paths.log_path, min_level=log_level)
    if logger is None:
        print(f"[ERROR] Failed to initialize logger at: {config.paths.log_path}")
        return None, None

    log_info(logger, "App", f"{APP_NAME} {APP_VERSION} starting...")

    # Initialize database
    print(f"[INIT] Initializing database: {config.paths.db_path}")
    db_err, db_handle = init_database(config.paths.db_path, logger=logger)
    if db_err != DatabaseErrorCode.SUCCESS:
        log_error(logger, "App", "Failed to initialize database", f"Error code: {db_err}")
        close_logger(logger)
        return None, None

    # Initialize thread pool
    thread_pool = create_pool(config.threading.pool_size, logger)
    if thread_pool is None:
        close_database(db_handle)
        close_logger(logger)
        return None, None

    # Initialize task manager
    task_manager = init_task_manager(logger_handle=logger)
    if task_manager is None:
        destroy_pool(thread_pool)
        close_database(db_handle)
        close_logger(logger)
        return None, None

    # =========================================================================
    # ROBUST IDENTITY SCANNER
    # =========================================================================
    beacon_handle = None
    state_file_path = "Data/beacon_state.json"
    
    # 1. Define search patterns (Hex: 00002564 and Decimal: 9572)
    sn_hex = f"{config.identity.serial_number:08X}"
    sn_dec = str(config.identity.serial_number)
    bank_dir = "Data/Wallets/Default/Bank"
    
    key_file_to_use = None

    if os.path.exists(bank_dir):
        # Scan Bank folder for any file containing the SN pattern
        for f_name in os.listdir(bank_dir):
            upper_name = f_name.upper()
            # Match if file has .BIN/.KEY extension AND contains the SN (Hex or Dec)
            if upper_name.endswith(('.BIN', '.KEY')) and (sn_hex in upper_name or sn_dec in upper_name):
                # Skip hidden files (starting with dot)
                if f_name.startswith('.'):
                    continue
                    
                key_file_to_use = os.path.join(bank_dir, f_name)
                log_info(logger, "App", f"Identity coin discovered: {f_name}")
                break

    # Fallback to legacy keys.txt if no .bin/.key file was found
    if not key_file_to_use:
        legacy_path = "Data/keys.txt"
        if os.path.exists(legacy_path):
            key_file_to_use = legacy_path
            log_info(logger, "App", "No .bin identity found; falling back to keys.txt")

    # 2. Initialize Beacon
    if key_file_to_use and os.path.exists(key_file_to_use):
        print(f"[INIT] Initializing beacon monitor using: {key_file_to_use}")
        beacon_handle = init_beacon(
            identity_config=config.identity,
            beacon_config=config.beacon,
            network_config=config.network,
            key_file_path=key_file_to_use,
            state_file_path=state_file_path,
            logger_handle=logger
        )
        if beacon_handle:
            log_info(logger, "App", "Beacon initialized successfully")
        else:
            log_warning(logger, "App", "Beacon initialization failed - mail notifications disabled")
            print("[WARNING] Beacon initialization failed - mail notifications disabled")
    else:
        log_warning(logger, "App", "No identity file found - beacon disabled")
        print("[WARNING] No identity file found - beacon disabled")

    # Create app context and API server
    app_context = AppContext(
        config=config,
        db_handle=db_handle,
        logger=logger,
        thread_pool=thread_pool,
        task_manager=task_manager,
        beacon_handle=beacon_handle
    )

    try:
        server = APIServer(logger=logger, host=config.api.host, port=args.port)
        server.app_context = app_context
        register_all_routes(server)
    except Exception as e:
        log_error(logger, "App", "Failed to create API server", str(e))
        return None, None

    return app_context, server

def move_identity_to_fracked(identity_config, beacon_handle, logger=None):
    """
    Moves all identity files (.bin/.key) belonging to this SN to Fracked for repair.
    """
    import shutil
    import os
    import threading
    from src.beacon import stop_beacon_monitor
    from src.heal import heal_wallet

    # 1. STOP THE MONITOR IMMEDIATELY
    # Prevents the connection flood while files are in transit.
    if beacon_handle and beacon_handle.is_running:
        if logger: log_info(logger, "App", f"Stopping beacon SN {identity_config.serial_number} for repair.")
        stop_beacon_monitor(beacon_handle)

    bank_dir = "Data/Wallets/Default/Bank"
    fracked_dir = "Data/Wallets/Default/Fracked"
    os.makedirs(fracked_dir, exist_ok=True)
    
    # Target pattern: Hex SN (e.g., '00001AEB')
    sn_hex_pattern = f"{identity_config.serial_number:08X}"
    files_moved = 0

    # 2. SCAN BANK FOLDER BY EXTENSION AND SN PATTERN
    if os.path.exists(bank_dir):
        for f_name in os.listdir(bank_dir):
            # Only process relevant extensions
            if not f_name.lower().endswith(('.bin', '.key')):
                continue
                
            # Match strictly if the Hex Serial Number is in the filename
            if sn_hex_pattern in f_name.upper():
                src = os.path.join(bank_dir, f_name)
                dst = os.path.join(fracked_dir, f_name)
                try:
                    shutil.move(src, dst)
                    if logger: log_info(logger, "App", f"Moved identity file {f_name} to Fracked.")
                    files_moved += 1
                except Exception as e:
                    if logger: log_error(logger, "App", f"Failed to move {f_name}: {e}")

    # 3. TRIGGER BACKGROUND HEAL
    if files_moved > 0:
        threading.Thread(
            target=heal_wallet, 
            args=("Data/Wallets/Default",), 
            name="AutoHealTrigger", 
            daemon=True
        ).start()
    else:
        if logger: log_warning(logger, "App", f"No identity files found for SN {sn_hex_pattern} in Bank.")



def start_periodic_healer(wallet_path: str, logger: Any, interval_hours: int = 1):
     """
    Background task that periodically ensures the entire wallet is healthy.
    Runs in a separate thread to avoid blocking the main application.
    """
     import time
    # This import must be here or at the top of app.py
     from src.heal import heal_wallet 
    
     def healer_loop():
        # Wait 30 seconds after app start to let RAIDA servers stabilize
        time.sleep(30) 
        
        while True:
            log_info(logger, "PeriodicHeal", "Starting scheduled wallet health check.")
            try:
                # The yellow line appeared here because 'wallet_path' 
                # wasn't in the function arguments or scope.
                heal_wallet(wallet_path) 
                log_info(logger, "PeriodicHeal", "Scheduled health check completed.")
            except Exception as e:
                log_error(logger, "PeriodicHeal", f"Scheduled heal failed: {e}")
            
            # The yellow line appeared here because 'interval_hours' 
            # wasn't defined in the function signature.
            log_info(logger, "PeriodicHeal", f"Next check in {interval_hours} hours.")
            time.sleep(interval_hours * 3600)

    # Starts the healer in the background immediately
     healer_thread = threading.Thread(target=healer_loop, name="ScheduledHealer", daemon=True)
     healer_thread.start()


      

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """
    Main application entry point.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Parse arguments
    args = parse_arguments()

    # Validate port range
    if args.port < 1 or args.port > 65535:
        print(f"[ERROR] Invalid port number: {args.port}. Must be 1-65535.")
        return 1

    # Initialize wallet folder structure (Data/Wallets/Default, Data/Wallets/Mailbox)
    # This creates the folder structure if it doesn't exist, preserving existing files
    print("[INIT] Checking wallet folder structure...")
    wallet_success, wallet_result = initialize_wallet_structure()
    if not wallet_success:
        print("[ERROR] Failed to initialize wallet structure:")
        for error in wallet_result.get('errors', []):
            print(f"  - {error}")
        return 1

    if wallet_result['created']:
        print(f"[INIT] Created {len(wallet_result['created'])} wallet folders/files")
    else:
        print("[INIT] Wallet structure verified (already exists)")

    # Initialize application
    app_context, server = initialize_application(args)

    if app_context is None:
        return 1
    
    default_wallet_path = "Data/Wallets/Default"

    start_periodic_healer(
        wallet_path=default_wallet_path, 
        logger=app_context.logger, 
        interval_hours=24
    )

    # Shortcuts for common context items
    config = app_context.config
    logger = app_context.logger

    # Print configuration summary
    print()
    print_config_summary(config)
    print()

    # Perform data sync (unless --skip-sync flag is used)
    if not args.skip_sync:
        print("[INIT] Syncing user and server data from RAIDA...")
        log_info(logger, "App", "Starting data sync...")

        sync_err, sync_result = sync_all(
            app_context.db_handle,
            config.sync.users_url,
            config.sync.servers_url,
            config.sync.timeout_sec,
            logger
        )

        if sync_err == SyncErrorCode.SUCCESS:
            print(f"[INIT] Data sync complete: {sync_result['users']} users, {sync_result['servers']} servers")
            log_info(logger, "App", f"Data sync complete: {sync_result['users']} users, {sync_result['servers']} servers")
        else:
            print(f"[WARNING] Data sync failed (error {sync_err}) - continuing with cached data")
            log_warning(logger, "App", f"Data sync failed: {sync_err} - using cached data")
    else:
        print("[INIT] Skipping data sync (--skip-sync flag)")
        log_info(logger, "App", "Data sync skipped (--skip-sync flag)")

    # Start the server
    server.start()

    # Start beacon monitor if initialized
    if app_context.beacon_handle:
        # Initialize server cache for IP lookups (can be refreshed via app_context.refresh_server_cache())
        app_context.refresh_server_cache()
        app_context.beacon_handle.on_an_invalid = lambda id: move_identity_to_fracked(
            id, app_context.beacon_handle, logger
        )
        

        def _extract_server_ip(server_location):
            """
            Extract server IP from ServerLocation.

            Priority:
            1. Look up server_id in AppContext server cache
            2. Try raw_entry bytes [22:26] if valid IPv4
            3. Use fallback hostname pattern

            Args:
                server_location: ServerLocation object from TellNotification

            Returns:
                str: Server IP address or hostname
            """
            server_id = getattr(server_location, 'server_id', None)

            # Try AppContext cache first (most reliable, refreshable)
            if server_id is not None:
                ip = app_context.get_server_ip(server_id)
                if ip:
                    return ip

            # Try extracting from raw_entry if available
            if hasattr(server_location, 'raw_entry') and len(server_location.raw_entry) >= 26:
                ip_bytes = server_location.raw_entry[22:26]
                # Check if it's a valid non-zero IP (0.0.0.0 is invalid)
                if any(b != 0 for b in ip_bytes):
                    return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"

            # Fallback to hostname pattern
            if server_id is not None:
                return f"raida{server_id}.cloudcoin.global"
            return "unknown.server"
        


        def on_mail_received(notifications):
            """
            Callback invoked when beacon detects new mail.
            Handles AS8D-HJL formats, 'Download Once' policy, and batch healing.
            
            This version includes full internal imports and detailed logging to 
            ensure a robust background process.
            """
            # Internal imports to ensure no 'yellow lines' or scope issues
            import time
            import threading
            from logger import log_info, log_error, log_debug, log_warning
            from database import (
                is_guid_in_database, 
                store_received_tell, 
                store_received_stripe, 
                DatabaseErrorCode
            )

            log_info(logger, "Beacon", f"New mail detected: {len(notifications)} notification(s)")
            
            # Persist in memory for immediate UI/API access
            app_context.add_notifications(notifications)

            successful_count = 0
            failed_count = 0
            new_locker_found = False

            for notification in notifications:
                try:
                    # 1. EXTRACT & VALIDATE GUID
                    if not hasattr(notification, 'file_guid') or not notification.file_guid:
                        log_warning(logger, "Beacon", "Received notification with missing or empty file_guid.")
                        failed_count += 1
                        continue
                        
                    file_guid = notification.file_guid.hex() if hasattr(notification.file_guid, 'hex') else str(notification.file_guid)

                    # 2. DOWNLOAD ONCE CHECK (Policy enforcement)
                    # We check the database to see if we've already stored this GUID.
                    if is_guid_in_database(app_context.db_handle, file_guid):
                        log_debug(logger, "Beacon", f"Email {file_guid[:8]} already exists in local database. Skipping redundant processing.")
                        continue

                    # 3. LOCKER CODE CLEANING (Format: AS8D-HJL -> AS8DHJL)
                    locker_code = getattr(notification, 'locker_code', None)
                    if locker_code:
                        if isinstance(locker_code, str):
                            clean_code = locker_code.replace('-', '').strip().upper()
                            # Pad to 8 bytes with nulls for C-compatibility
                            locker_code = clean_code.encode('ascii').ljust(8, b'\x00')
                            log_debug(logger, "Beacon", f"Cleaned/Padded locker: {clean_code} -> {locker_code.hex()}")
                        new_locker_found = True
                        
                        new_locker_found = True
                    else:
                        log_debug(logger, "Beacon", f"Notification {file_guid[:8]} does not contain a locker code.")

                    # 4. STORE METADATA (received_tells table)
                    # We store the metadata so the download_handler can find it later.
                    err, tell_id = store_received_tell(
                        app_context.db_handle,
                        file_guid=file_guid,
                        locker_code=locker_code,
                        tell_type=getattr(notification, 'tell_type', 0)
                    )

                    if err != DatabaseErrorCode.SUCCESS:
                        log_error(logger, "Beacon", f"Database error ({err}) while storing tell metadata for {file_guid[:8]}")
                        failed_count += 1
                        continue

                    # 5. STORE STRIPE LOCATIONS (received_stripes table)
                    # This maps which RAIDA servers actually have the data.
                    server_list = getattr(notification, 'server_list', [])
                    stripes_stored = 0
                    
                    for server in server_list:
                        # Use the helper defined in the app.py scope to get IP
                        server_ip = _extract_server_ip(server)
                        
                        # Determine indices and parity status
                        stripe_index = getattr(server, 'stripe_index', 0)
                        # In the protocol, stripe_type 1 is usually Parity
                        is_parity = (getattr(server, 'stripe_type', 0) == 1)

                        s_err = store_received_stripe(
                            app_context.db_handle,
                            tell_id=tell_id,
                            server_ip=server_ip,
                            stripe_index=stripe_index,
                            is_parity=is_parity
                        )
                        
                        if s_err == DatabaseErrorCode.SUCCESS:
                            stripes_stored += 1
                        else:
                            log_error(logger, "Beacon", f"Failed to cache stripe {stripe_index} for tell {file_guid[:8]}")

                    log_info(logger, "Beacon", f"Successfully cached metadata for {file_guid[:8]} with {stripes_stored} server locations.")
                    successful_count += 1

                except Exception as e:
                    log_error(logger, "Beacon", f"Critical error processing notification GUID {getattr(notification, 'file_guid', 'UNKNOWN')}: {str(e)}")
                    failed_count += 1

            # 6. LOG BATCH SUMMARY
            if len(notifications) > 0:
                log_info(logger, "Beacon", f"Batch Processing Complete: {successful_count} stored, {failed_count} failed.")

            # 7. BATCH HEALING TRIGGER
            # If any payments or staking coins were found, we need to fix them.
            if new_locker_found:
                def run_batch_heal():
                    # Import inside the thread to avoid circular dependencies
                    from heal import heal_wallet
                    
                    # 10-second delay to allow background download tasks to settle 
                    # before the healing orchestrator locks the wallet files.
                    time.sleep(10)
                    
                    log_info(logger, "HealTask", "Starting background batch healing pass for 'Default' wallet.")
                    try:
                        # Points to your standard CloudCoin wallet path
                        heal_wallet("Data/Wallets/Default")
                        log_info(logger, "HealTask", "Background batch healing pass completed successfully.")
                    except Exception as he:
                        log_error(logger, "HealTask", f"Batch healing pass failed: {he}")
                
                # Daemon thread ensures the healing process doesn't hang the app shutdown
                heal_thread = threading.Thread(target=run_batch_heal, name="BatchHealWorker", daemon=True)
                heal_thread.start()

        if start_beacon_monitor(app_context.beacon_handle, on_mail_received):
            log_info(logger, "App", "Beacon monitor started - watching for new mail")
            print("[INIT] Beacon monitor started - watching for new mail")
        else:
            log_warning(logger, "App", "Failed to start beacon monitor")
            print("[WARNING] Failed to start beacon monitor")

    # Print startup message
    base_url = f"http://{config.api.host}:{args.port}"
    print(f"{APP_NAME} running at {base_url}")
    print()
    print("API Endpoints:")
    print("\n[ Health & Status ]")
    print(f"  GET  {base_url}/api/health                - Health check")
    print(f"  GET  {base_url}/api/qmail/ping            - Beacon check for new mail")
    
    print("\n[ Mail Operations ]")
    print(f"  POST {base_url}/api/mail/send             - Send email")
    print(f"  GET  {base_url}/api/mail/download/{{id}}    - Download email by GUID")
    print(f"  GET  {base_url}/api/mail/list             - List emails (inbox, sent, etc.)")
    print(f"  POST {base_url}/api/mail/create-mailbox   - Create new mailbox (Stake)")
    print(f"  GET  {base_url}/api/mail/folders          - List available mail folders")
    print(f"  GET  {base_url}/api/mail/count            - Get unread/total counts")
    
    print("\n[ Individual Email Management ]")
    print(f"  GET  {base_url}/api/mail/{{id}}             - Get email metadata")
    print(f"  DELETE {base_url}/api/mail/{{id}}           - Move email to trash")
    print(f"  PUT  {base_url}/api/mail/{{id}}/move        - Move email to folder")
    print(f"  PUT  {base_url}/api/mail/{{id}}/read        - Mark email read/unread")
    
    print("\n[ Attachments ]")
    print(f"  GET  {base_url}/api/mail/{{id}}/attachments     - List attachments for email")
    print(f"  GET  {base_url}/api/mail/{{id}}/attachment/{{n}} - Download specific attachment")
    
    print("\n[ Contacts & Users ]")
    print(f"  GET  {base_url}/api/contacts              - List/Search all contacts")
    print(f"  POST {base_url}/api/contacts              - Add a new contact")
    print(f"  DELETE {base_url}/api/contacts/{{id}}       - Delete a contact")
    print(f"  GET  {base_url}/api/data/contacts/popular - Get frequent contacts")
    print(f"  GET  {base_url}/api/data/users/search     - Search users for autocomplete")
    
    print("\n[ Drafts ]")
    print(f"  GET  {base_url}/api/mail/drafts           - List all drafts")
    print(f"  POST {base_url}/api/mail/draft            - Save a new draft")
    print(f"  PUT  {base_url}/api/mail/draft/{{id}}       - Update an existing draft")
    
    print("\n[ System & Data ]")
    print(f"  GET  {base_url}/api/data/emails/search    - Full-text search (FTS5)")
    print(f"  GET  {base_url}/api/data/servers          - Get QMail/RAIDA server list")
    print(f"  GET  {base_url}/api/wallet/balance        - Get full wallet balance")
    print(f"  POST {base_url}/api/locker/download       - Manual coin download via code")
    
    print("\n[ Administration & Sync ]")
    print(f"  POST {base_url}/api/admin/sync            - Trigger manual RAIDA data sync")
    print(f"  GET  {base_url}/api/admin/servers/parity  - Get current parity server")
    print(f"  POST {base_url}/api/admin/servers/parity  - Set parity server configuration")
    
    print("\n[ Task Management ]")
    print(f"  GET  {base_url}/api/task/status/{{id}}      - Check async task status")
    print(f"  POST {base_url}/api/task/cancel/{{id}}      - Cancel a pending task")
    print()
    print("Press Ctrl+C to stop the server...")
    print()

    log_info(logger, "App", f"Server started on {base_url}")

    # Run until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("Shutdown requested...")

    # Cleanup
    log_info(logger, "App", "Shutting down...")
    server.stop()

    # Stop beacon monitor
    if app_context.beacon_handle:
        log_info(logger, "App", "Stopping beacon monitor...")
        stop_beacon_monitor(app_context.beacon_handle)

    # Shutdown task manager
    if app_context.task_manager:
        log_info(logger, "App", "Shutting down task manager...")
        shutdown_task_manager(app_context.task_manager)

    # Destroy thread pool
    if app_context.thread_pool:
        log_info(logger, "App", "Destroying thread pool...")
        destroy_pool(app_context.thread_pool)

    # Close database
    log_info(logger, "App", "Closing database...")
    close_database(app_context.db_handle)

    log_info(logger, "App", f"{APP_NAME} stopped")
    close_logger(logger)

    print(f"{APP_NAME} stopped.")
    return 0


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    sys.exit(main())
