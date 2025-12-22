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

        Call this after any operation that modifies the server list,
        such as data sync or server configuration changes.

        Returns:
            bool: True if cache was refreshed successfully
        """
        if self.db_handle is None:
            return False

        err, servers = get_all_servers(self.db_handle, available_only=False)
        if err == DatabaseErrorCode.SUCCESS:
            # Build new cache (atomic replacement)
            new_cache = {}
            for srv in servers:
                server_id = srv.get('server_id', srv.get('id', -1))
                ip_address = srv.get('IPAddress', '')
                if server_id >= 0 and ip_address:
                    new_cache[server_id] = ip_address
            # Replace cache atomically
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

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (app_context, server) on success, or (None, None) on failure
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

    if validation.warnings:
        print("[WARNING] Configuration warnings:")
        for warning in validation.warnings:
            print(f"  - {warning}")

    # Initialize logger
    log_level = LogLevel.DEBUG if args.debug else LogLevel.INFO
    logger = init_logger(
        config.paths.log_path,
        min_level=log_level
    )

    if logger is None:
        print(f"[ERROR] Failed to initialize logger at: {config.paths.log_path}")
        return None, None

    log_info(logger, "App", f"{APP_NAME} {APP_VERSION} starting...")
    log_info(logger, "App", f"Configuration loaded from: {config_path}")
    log_info(logger, "App", f"Log level: {'DEBUG' if args.debug else 'INFO'}")

    # Initialize database
    print(f"[INIT] Initializing database: {config.paths.db_path}")
    db_err, db_handle = init_database(config.paths.db_path, logger=logger)

    if db_err != DatabaseErrorCode.SUCCESS:
        log_error(logger, "App", "Failed to initialize database", f"Error code: {db_err}")
        print(f"[ERROR] Failed to initialize database (error {db_err})")
        close_logger(logger)
        return None, None

    log_info(logger, "App", f"Database initialized: {config.paths.db_path}")

    # Initialize thread pool
    print(f"[INIT] Initializing thread pool ({config.threading.pool_size} workers)...")
    thread_pool = create_pool(config.threading.pool_size, logger)
    if thread_pool is None:
        log_error(logger, "App", "Failed to initialize thread pool")
        print("[ERROR] Failed to initialize thread pool")
        close_database(db_handle)
        close_logger(logger)
        return None, None

    log_info(logger, "App", f"Thread pool initialized with {config.threading.pool_size} workers")

    # Initialize task manager
    print("[INIT] Initializing task manager...")
    task_manager = init_task_manager(logger_handle= logger)
    # print(f"!!! DEBUG: Task Manager Max History is {task_manager.max_history} (Should be 1000) !!!")
    if task_manager is None:
        log_error(logger, "App", "Failed to initialize task manager")
        print("[ERROR] Failed to initialize task manager")
        destroy_pool(thread_pool)
        close_database(db_handle)
        close_logger(logger)
        return None, None

    log_info(logger, "App", "Task manager initialized")

    # Initialize beacon (optional - continues if fails)
    beacon_handle = None
    key_file_path = "Data/keys.txt"
    state_file_path = "Data/beacon_state.json"

    if os.path.exists(key_file_path):
        print(f"[INIT] Initializing beacon monitor...")
        beacon_handle = init_beacon(
            identity_config=config.identity,
            beacon_config=config.beacon,
            network_config=config.network,
            key_file_path=key_file_path,
            state_file_path=state_file_path,
            logger_handle=logger
        )

        if beacon_handle:
            log_info(logger, "App", "Beacon initialized successfully")
        else:
            log_warning(logger, "App", "Beacon initialization failed - continuing without beacon")
            print("[WARNING] Beacon initialization failed - mail notifications disabled")
    else:
        log_warning(logger, "App", f"Key file not found: {key_file_path} - beacon disabled")
        print(f"[WARNING] Key file not found: {key_file_path} - beacon disabled")

    # Create app context
    app_context = AppContext(
        config=config,
        db_handle=db_handle,
        logger=logger,
        thread_pool=thread_pool,
        task_manager=task_manager,
        beacon_handle=beacon_handle
    )

    # Create API server
    try:
        server = APIServer(
            logger=logger,
            host=config.api.host,
            port=args.port
        )
    except ValueError as e:
        log_error(logger, "App", "Failed to create API server", str(e))
        print(f"[ERROR] Failed to create API server: {e}")
        close_database(db_handle)
        close_logger(logger)
        return None, None

    # Attach app context to server (handlers access via request_handler.server_instance.app_context)
    server.app_context = app_context

    # Register all API routes
    register_all_routes(server)
    log_info(logger, "App", f"Registered {len(server.routes)} API routes")

    return app_context, server


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

            Stores tells in database for later download.

            Args:
                notifications: List of TellNotification objects from beacon

            Note: This is a closure with access to logger, app_context, and _extract_server_ip
            """
            log_info(logger, "Beacon",
                     f"New mail detected: {len(notifications)} notification(s)")

            # Keep in-memory copy for immediate API access
            app_context.add_notifications(notifications)

            # Persist each tell to database
            successful_count = 0
            failed_count = 0

            for notification in notifications:
                try:
                    # Validate notification has required fields
                    if not hasattr(notification, 'file_guid') or not notification.file_guid:
                        log_error(logger, "Beacon", "Notification missing file_guid")
                        failed_count += 1
                        continue

                    if not hasattr(notification, 'locker_code') or not notification.locker_code:
                        log_error(logger, "Beacon", "Notification missing locker_code")
                        failed_count += 1
                        continue

                    # Extract file_guid as hex string
                    file_guid = notification.file_guid.hex() if isinstance(
                        notification.file_guid, bytes) else str(notification.file_guid)

                    # Ensure locker_code is bytes
                    locker_code = notification.locker_code
                    if not isinstance(locker_code, bytes):
                        if isinstance(locker_code, str):
                            locker_code = bytes.fromhex(locker_code)
                        else:
                            log_error(logger, "Beacon",
                                      f"Invalid locker_code type for {file_guid[:16]}...: {type(locker_code)}")
                            failed_count += 1
                            continue

                    # Get tell_type with fallback
                    tell_type = getattr(notification, 'tell_type', 0)

                    # Store tell metadata
                    err, tell_id = store_received_tell(
                        app_context.db_handle,
                        file_guid=file_guid,
                        locker_code=locker_code,
                        file_type=tell_type,
                        version=1,
                        file_size=0  # Unknown until downloaded
                    )

                    if err != DatabaseErrorCode.SUCCESS:
                        log_error(logger, "Beacon",
                                  f"Failed to store tell {file_guid[:16]}...: {err}")
                        failed_count += 1
                        continue

                    # Get server_list with validation
                    server_list = getattr(notification, 'server_list', None)
                    if not server_list:
                        log_warning(logger, "Beacon",
                                    f"No server list for tell {file_guid[:16]}..., cannot download later")
                        # Still count as partial success since tell was stored
                        successful_count += 1
                        continue

                    # Store stripe/server information
                    stripes_stored = 0
                    for server in server_list:
                        # Extract server IP
                        server_ip = _extract_server_ip(server)

                        # Get stripe_index and total_stripes with fallbacks
                        stripe_index = getattr(server, 'stripe_index', 0)
                        total_stripes = getattr(server, 'total_stripes', 1)

                        # Determine if this is the parity stripe (last stripe)
                        is_parity = (stripe_index == total_stripes - 1)

                        err = store_received_stripe(
                            app_context.db_handle,
                            tell_id=tell_id,
                            server_ip=server_ip,
                            stripe_id=stripe_index,
                            is_parity=is_parity
                        )

                        if err != DatabaseErrorCode.SUCCESS:
                            log_error(logger, "Beacon",
                                      f"Failed to store stripe {stripe_index} for tell {tell_id}: {err}")
                        else:
                            stripes_stored += 1

                    log_info(logger, "Beacon",
                             f"Stored tell {file_guid[:16]}... with {stripes_stored}/{len(server_list)} stripes")
                    successful_count += 1

                except Exception as e:
                    log_error(logger, "Beacon", f"Error processing notification: {e}")
                    failed_count += 1

            # Log summary
            if len(notifications) > 0:
                log_info(logger, "Beacon",
                         f"Tell processing complete: {successful_count} successful, {failed_count} failed")

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
    print(f"  GET  {base_url}/api/health              - Health check")
    print(f"  GET  {base_url}/api/qmail/ping          - Check for new mail")
    print(f"  POST {base_url}/api/mail/send           - Send email")
    print(f"  GET  {base_url}/api/mail/download/{{id}}  - Download email")
    print(f"  GET  {base_url}/api/mail/list           - List emails (DB)")
    print(f"  POST {base_url}/api/mail/create-mailbox - Create mailbox")
    print(f"  GET  {base_url}/api/data/contacts/popular - Get contacts (DB)")
    print(f"  GET  {base_url}/api/data/emails/search  - Search emails (DB)")
    print(f"  GET  {base_url}/api/task/status/{{id}}    - Task status")
    print(f"  POST {base_url}/api/task/cancel/{{id}}    - Cancel task")
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
