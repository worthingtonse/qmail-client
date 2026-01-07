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

import threading
from config import load_config, validate_config, print_config_summary, get_default_config_path
from logger import init_logger, close_logger, log_info, log_error, log_warning, LogLevel
from api_server import APIServer
from api_handlers import register_all_routes
from database import (
    init_database, close_database, get_all_servers,
    is_guid_in_database, store_received_tell, store_received_stripe,
    DatabaseErrorCode
)
from beacon import init_beacon, start_beacon_monitor, stop_beacon_monitor, do_peek
from thread_pool import create_pool, destroy_pool
from task_manager import init_task_manager, shutdown_task_manager
from data_sync import sync_all, SyncErrorCode
from wallet_structure import initialize_wallet_structure
import sys
import os
import argparse
import time
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any
import struct

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
    # Task tracking system (see docstring for lifecycle)
    task_manager: Any = None
    beacon_handle: Any = None    # Optional - may fail to init if keys not configured
    # Thread-safe storage for beacon notifications
    _notifications: list = None
    _notifications_lock: threading.Lock = None
    # Server IP cache for beacon callback (refreshable)
    _server_cache: dict = None
    cc_handle: Any = None

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
        print(
            f"[ERROR] Failed to initialize logger at: {config.paths.log_path}")
        return None, None

    log_info(logger, "App", f"{APP_NAME} {APP_VERSION} starting...")

    # Initialize database
    print(f"[INIT] Initializing database: {config.paths.db_path}")
    db_err, db_handle = init_database(config.paths.db_path, logger=logger)
    if db_err != DatabaseErrorCode.SUCCESS:
        log_error(logger, "App", "Failed to initialize database",
                  f"Error code: {db_err}")
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

    from coin_scanner import find_identity_coin, load_coin_metadata
    import shutil

    key_file_to_use = None
    identity_coin = None
    
    # Priority: Mailbox/Bank > Mailbox/Fracked > Default/Bank (migrate)
    mailbox_bank = "Data/Wallets/Mailbox/Bank"
    mailbox_fracked = "Data/Wallets/Mailbox/Fracked"
    default_bank = "Data/Wallets/Default/Bank"
    
    # 1. Check Mailbox/Bank (correct location)
    if os.path.exists(mailbox_bank):
        all_coins = []
        for filename in os.listdir(mailbox_bank):
            if not filename.endswith('.bin'):
                continue
            filepath = os.path.join(mailbox_bank, filename)
            coin = load_coin_metadata(filepath)
            if coin:
                all_coins.append(coin)
        
        if all_coins:
            identity_coin = all_coins[0]
            key_file_to_use = identity_coin['file_path']
            log_info(logger, "App",
                     f"Identity found in Mailbox/Bank: SN={identity_coin['serial_number']}, DN={identity_coin['denomination']}")
    
    # 2. Check Mailbox/Fracked (needs healing)
    if not identity_coin and os.path.exists(mailbox_fracked):
        all_coins = []
        for filename in os.listdir(mailbox_fracked):
            if not filename.endswith('.bin'):
                continue
            filepath = os.path.join(mailbox_fracked, filename)
            coin = load_coin_metadata(filepath)
            if coin:
                all_coins.append(coin)
        
        if all_coins:
            identity_coin = all_coins[0]
            key_file_to_use = identity_coin['file_path']
            log_warning(logger, "App",
                       f"Identity found in Mailbox/Fracked (needs healing): SN={identity_coin['serial_number']}")
    
    # 3. Legacy: Check Default/Bank (migrate to Mailbox)
    if not identity_coin and os.path.exists(default_bank):
        all_coins = []
        for filename in os.listdir(default_bank):
            if not filename.endswith('.bin'):
                continue
            filepath = os.path.join(default_bank, filename)
            coin = load_coin_metadata(filepath)
            if coin:
                all_coins.append(coin)
        
        if all_coins:
            identity_coin = all_coins[0]
            old_path = identity_coin['file_path']
            
            log_info(logger, "App",
                     f"Legacy identity found in Default/Bank: SN={identity_coin['serial_number']}")
            log_info(logger, "App", "Migrating identity to Mailbox/Bank...")
            
            # Migrate to Mailbox/Bank
            try:
                os.makedirs(mailbox_bank, exist_ok=True)
                new_filename = os.path.basename(old_path)
                new_path = os.path.join(mailbox_bank, new_filename)
                shutil.move(old_path, new_path)
                
                # Update identity coin with new path
                identity_coin['file_path'] = new_path
                key_file_to_use = new_path
                
                log_info(logger, "App", f"Identity migrated successfully to Mailbox/Bank")
            except Exception as e:
                log_error(logger, "App", f"Failed to migrate identity: {e}")
                key_file_to_use = old_path
    
    if identity_coin:
        log_info(logger, "App",
                 f"Identity coin ready: SN={identity_coin['serial_number']}, "
                 f"DN={identity_coin['denomination']}, file={os.path.basename(key_file_to_use)}")
    else:
        log_warning(logger, "App", "No identity coin found in any wallet")

    # Fallback to legacy keys.txt if no .bin/.key file was found
    if not key_file_to_use:
        legacy_path = "Data/keys.txt"
        if os.path.exists(legacy_path):
            key_file_to_use = legacy_path
            log_info(logger, "App",
                     "No .bin identity found; falling back to keys.txt")

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
            log_warning(
                logger, "App", "Beacon initialization failed - mail notifications disabled")
            print(
                "[WARNING] Beacon initialization failed - mail notifications disabled")
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


def find_identity_coin_for_beacon(logger_handle=None):
    """
    Find identity coin for beacon initialization.
    Priority: Mailbox/Bank > Mailbox/Fracked > Default/Bank (legacy migration)
    
    Returns:
        tuple: (coin, wallet_path) or (None, None) if not found
    """
    import shutil
    from src.coin_scanner import scan_coins_from_dir
    from src.logger import log_info, log_warning, log_error
    
    wallet_root = "Data/Wallets"
    
    # 1. Check Mailbox/Bank (correct location for identity)
    mailbox_bank = os.path.join(wallet_root, "Mailbox", "Bank")
    if os.path.exists(mailbox_bank):
        coins = scan_coins_from_dir(mailbox_bank)
        if coins:
            coin = coins[0]
            log_info(logger_handle, "App", 
                    f"Identity found in Mailbox/Bank: SN={coin.serial_number}, DN={coin.denomination}")
            return coin, os.path.join(wallet_root, "Mailbox")
    
    # 2. Check Mailbox/Fracked (identity needs healing)
    mailbox_fracked = os.path.join(wallet_root, "Mailbox", "Fracked")
    if os.path.exists(mailbox_fracked):
        coins = scan_coins_from_dir(mailbox_fracked)
        if coins:
            coin = coins[0]
            log_warning(logger_handle, "App", 
                       f"Identity found in Mailbox/Fracked: SN={coin.serial_number}")
            log_warning(logger_handle, "App", 
                       "Identity needs healing before beacon can start properly")
            return coin, os.path.join(wallet_root, "Mailbox")
    
    # 3. Legacy: Check Default/Bank (migrate to Mailbox)
    default_bank = os.path.join(wallet_root, "Default", "Bank")
    if os.path.exists(default_bank):
        coins = scan_coins_from_dir(default_bank)
        if coins:
            coin = coins[0]
            log_info(logger_handle, "App", 
                    f"Legacy identity found in Default/Bank: SN={coin.serial_number}")
            
            # Migrate to Mailbox/Bank
            log_info(logger_handle, "App", "Migrating identity to Mailbox/Bank...")
            os.makedirs(mailbox_bank, exist_ok=True)
            
            old_path = coin.filepath
            new_filename = os.path.basename(old_path)
            new_path = os.path.join(mailbox_bank, new_filename)
            
            try:
                shutil.move(old_path, new_path)
                log_info(logger_handle, "App", f"Identity migrated successfully")
                
                # Re-scan to get updated filepath
                coins = scan_coins_from_dir(mailbox_bank)
                if coins:
                    return coins[0], os.path.join(wallet_root, "Mailbox")
            except Exception as e:
                log_error(logger_handle, "App", f"Failed to migrate identity: {e}")
                # Return the coin anyway with old path
                return coin, os.path.join(wallet_root, "Default")
    
    return None, None

def move_identity_to_fracked(identity_config, beacon_handle, logger=None):
    """
    Move identity coin to Fracked folder and rename it to reflect failure.
    FIXED: Updates POWN string and uses Go-style naming helper.
    """
    from src.coin_scanner import find_identity_coin
    from src.cloudcoin import get_int_name, write_coin_file, load_coin_metadata
    import shutil
    import os
    import threading
    import time
    from src.beacon import stop_beacon_monitor, start_beacon_monitor, init_beacon
    from src.heal import heal_wallet
    from src.logger import log_info, log_error, log_warning

    # 1. STOP THE MONITOR IMMEDIATELY
    if beacon_handle and beacon_handle.is_running:
        log_info(logger, "App", f"Stopping beacon for SN {identity_config.serial_number} (repairing identity)")
        stop_beacon_monitor(beacon_handle)

    # 2. IDENTIFY ACTIVE WALLET
    locations = [
        ("Data/Wallets/Mailbox", "Data/Wallets/Mailbox/Bank", "Data/Wallets/Mailbox/Fracked"),
        ("Data/Wallets/Default", "Data/Wallets/Default/Bank", "Data/Wallets/Default/Fracked")
    ]
    
    identity_coin_data = None
    active_wallet_path = None
    target_fracked_dir = None
    target_bank_dir = None

    for wallet_path, bank_dir, fracked_dir in locations:
        if os.path.exists(bank_dir):
            identity_coin_data = find_identity_coin(bank_dir, identity_config.serial_number)
            if identity_coin_data:
                active_wallet_path = wallet_path
                target_fracked_dir = fracked_dir
                target_bank_dir = bank_dir
                break

    if not identity_coin_data:
        # Check if already in Fracked... (same as your logic)
        for _, _, fracked_dir in locations:
            if os.path.exists(fracked_dir):
                identity_coin_data = find_identity_coin(fracked_dir, identity_config.serial_number)
                if identity_coin_data:
                    active_wallet_path = os.path.dirname(fracked_dir)
                    target_bank_dir = os.path.join(active_wallet_path, "Bank")
                    break
        
        if not identity_coin_data:
            log_error(logger, "App", "Critical: Identity coin not found. Manual intervention required.")
            return

    # 3. UPDATE POWN AND RENAME (The "Go Alignment" Fix)
    if "Bank" in identity_coin_data['file_path']:
        os.makedirs(target_fracked_dir, exist_ok=True)
        
        # Mark RAIDA 11 as 'f' (failed)
        pown_list = list(identity_config.pown_string if hasattr(identity_config, 'pown_string') else 'p' * 25)
        if len(pown_list) >= 12:
            pown_list[11] = 'f'
        new_pown = "".join(pown_list)
        identity_config.pown_string = new_pown

        # Generate the correct Go-style name
        new_filename = get_int_name(identity_config.denomination, identity_config.serial_number, new_pown)
        dst_path = os.path.join(target_fracked_dir, new_filename)
        
        try:
            # We move the file then update its internal header if necessary, 
            # but usually, just moving it is enough if heal_wallet handles the rest.
            shutil.move(identity_coin_data['file_path'], dst_path)
            log_info(logger, "App", f"Moved identity to Fracked as: {new_filename}")
        except Exception as e:
            log_error(logger, "App", f"Failed to move identity: {e}")
            return

    # 4. TRIGGER RECOVERY LOOP
    def identity_recovery_loop():
        """
        Background task: repeatedly attempt to heal the identity until it's back in Bank.
        """
        retry_count = 0
        retry_delay = 300 # 5 minutes
        
        while True:
            try:
                retry_count += 1
                log_info(logger, "IdentityHeal", f"Attempt {retry_count}: Healing identity in {active_wallet_path}")
                
                # Execute healing
                heal_wallet(active_wallet_path)
                
                time.sleep(2) # Settle filesystem
                
                # Check if coin returned to Bank
                identity_coin_fixed = find_identity_coin(target_bank_dir, identity_config.serial_number)
                
                if identity_coin_fixed:
                    log_info(logger, "IdentityHeal", f"✓ Success! Identity SN {identity_config.serial_number} recovered to Bank.")
                    
                    # RE-START BEACON
                    new_handle = init_beacon(
                        identity_config=identity_config,
                        beacon_config=beacon_handle.beacon_config,
                        network_config=beacon_handle.network_config,
                        key_file_path=identity_coin_fixed['file_path'],
                        state_file_path="Data/beacon_state.json",
                        logger_handle=logger
                    )
                    
                    if new_handle:
                        if start_beacon_monitor(new_handle, beacon_handle.on_mail_received):
                            log_info(logger, "IdentityHeal", "✓ Beacon monitor restarted successfully.")
                            if hasattr(beacon_handle, 'on_restart_callback') and beacon_handle.on_restart_callback:
                                beacon_handle.on_restart_callback(new_handle)
                            return # EXIT THE LOOP - Recovery complete
                    
                    log_error(logger, "IdentityHeal", "Healed but failed to restart Beacon monitor.")
                    return # Exit loop since coin is fixed even if beacon failed
                
                else:
                    log_warning(logger, "IdentityHeal", 
                               f"Attempt {retry_count} failed (Network issue). Retrying in {retry_delay/60} minutes...")
                    time.sleep(retry_delay)
            
            except Exception as e:
                log_error(logger, "IdentityHeal", f"Unexpected error in recovery loop: {e}")
                time.sleep(retry_delay)

    # Start the persistent recovery loop
    thread = threading.Thread(target=identity_recovery_loop, name="IdentityRecovery", daemon=True)
    thread.start()
def validate_tell_payment_sync(
    locker_code_16bytes: Optional[bytes],
    recipient_user_id: int,
    db_handle: Any,
    logger: Any
) -> Tuple[bool, float, str]:
    """
    Validate that tell payment meets recipient's minimum requirements.

    Queries ALL 25 RAIDAs in parallel and uses consensus (13/25 minimum).
    This matches the Go client's approach.

    Args:
        locker_code_16bytes: 16-byte locker code from tell footer (Optional[bytes])
        recipient_user_id: Recipient's user ID (int)
        db_handle: Database handle (Any)
        logger: Logger handle (Any)

    Returns:
        Tuple[bool, float, str]: (is_valid, actual_amount, message)
    """
    # Import required modules at function level
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        from protocol import build_peek_locker_request, parse_peek_locker_response, ProtocolErrorCode
        from network import connect, send_raw_request, disconnect, NetworkErrorCode, ServerInfo, NetworkConfig
        from database import get_raida_servers, get_user_payment_requirement, DatabaseErrorCode
        from locker_download import derive_locker_keys
        from logger import log_info, log_error, log_debug, log_warning
    except ImportError as e:
        if logger is not None:
            try:
                from logger import log_error as log_err
                log_err(logger, "Beacon",
                        f"Import error in payment validation: {e}")
            except:
                pass
        return False, 0.0, f"Import error: {e}"

    # Constants for consensus
    RAIDA_COUNT: int = 25
    MINIMUM_QUORUM: int = 13

    # Normalize locker code to 8 bytes (with explicit None check)
    locker_code: bytes = b'\x00' * 8

    if locker_code_16bytes is not None and isinstance(locker_code_16bytes, bytes):
        code_len: int = len(locker_code_16bytes)
        if code_len >= 8:
            locker_code = locker_code_16bytes[:8]
        elif code_len > 0:
            locker_code = locker_code_16bytes.ljust(8, b'\x00')

    # Check if locker code is all zeros (no payment)
    if locker_code == b'\x00' * 8:
        try:
            err, min_payment_result = get_user_payment_requirement(
                db_handle, recipient_user_id)
        except Exception as e:
            log_warning(logger, "Beacon",
                        f"Exception fetching payment requirement: {e}")
            return True, 0.0, "Payment validation skipped - error fetching requirements"

        if err != DatabaseErrorCode.SUCCESS:
            log_warning(logger, "Beacon",
                        f"Could not fetch payment requirement for user {recipient_user_id}")
            return True, 0.0, "Payment validation skipped - user data unavailable"

        if min_payment_result is None or min_payment_result == 0:
            return True, 0.0, "No payment required"
        else:
            return False, 0.0, f"Payment required but none attached (minimum: {min_payment_result} CC)"

    # Get recipient's payment requirement
    min_payment: Optional[float] = None
    try:
        err, min_payment = get_user_payment_requirement(
            db_handle, recipient_user_id)
    except Exception as e:
        log_warning(logger, "Beacon",
                    f"Exception fetching payment requirement: {e}")
        return True, 0.0, "Payment validation skipped - exception occurred"

    if err != DatabaseErrorCode.SUCCESS:
        log_warning(logger, "Beacon",
                    "Could not fetch payment requirement - accepting tell")
        return True, 0.0, "Payment validation skipped"

    if min_payment is None or min_payment == 0:
        log_info(logger, "Beacon", "Recipient does not require payment")
        return True, 0.0, "No payment required"

    # At this point min_payment is guaranteed non-zero
    required_payment: float = float(min_payment)

    # Derive locker IDs
    locker_ids: list = []
    try:
        locker_ids = derive_locker_keys(locker_code)
    except Exception as e:
        log_error(logger, "Beacon", f"Failed to derive locker keys: {e}")
        return False, 0.0, "Cannot verify payment - key derivation failed"

    # Get RAIDA servers
    servers: list = []
    try:
        err, servers = get_raida_servers(db_handle)
    except Exception as e:
        log_error(logger, "Beacon", f"Failed to get RAIDA servers: {e}")
        return False, 0.0, "Cannot verify payment - server lookup failed"

    if err != DatabaseErrorCode.SUCCESS or not servers:
        log_error(logger, "Beacon", "Cannot verify payment - no RAIDA servers")
        return False, 0.0, "Cannot verify payment - no server list"

    # Create network config
    net_config: Optional[Any] = None
    try:
        net_config = NetworkConfig()
    except Exception:
        pass

    log_debug(logger, "Beacon",
              f"Querying all {RAIDA_COUNT} RAIDAs for payment verification...")

    # Thread-safe results storage
    results_lock: threading.Lock = threading.Lock()
    peek_results: Dict[int, float] = {}

    def peek_single_raida(raida_id: int) -> None:
        """Worker function to PEEK a single RAIDA."""
        server = next(
            (s for s in servers if s['server_index'] == raida_id), None)
        if not server:
            log_debug(logger, "Beacon", f"RAIDA{raida_id} not in server list")
            return

        try:
            locker_id: bytes = locker_ids[raida_id]
            err_proto, peek_req, _, _ = build_peek_locker_request(
                raida_id, locker_id)

            if err_proto != ProtocolErrorCode.SUCCESS:
                log_debug(logger, "Beacon",
                          f"RAIDA{raida_id}: Failed to build PEEK request")
                return

            server_info = ServerInfo(
                host=server['ip_address'],
                port=server['port'],
                index=raida_id
            )

            err_conn, conn = connect(
                server_info, timeout_ms=5000, logger_handle=logger)
            if err_conn != NetworkErrorCode.SUCCESS:
                log_debug(logger, "Beacon",
                          f"RAIDA{raida_id}: Connection failed")
                return

            net_err, resp_h, resp_b = send_raw_request(
                conn,
                peek_req,
                timeout_ms=5000,
                config=net_config,
                logger_handle=logger
            )
            disconnect(conn, logger)

            if net_err != NetworkErrorCode.SUCCESS:
                log_debug(logger, "Beacon", f"RAIDA{raida_id}: Request failed")
                return

            if resp_h.status != 241:
                log_debug(logger, "Beacon",
                          f"RAIDA{raida_id}: Status {resp_h.status}")
                return

            coin_count, coins = parse_peek_locker_response(resp_b)

            if coin_count == 0:
                with results_lock:
                    peek_results[raida_id] = 0.0
                return

            total_value: float = sum(coin['value'] for coin in coins)

            log_debug(logger, "Beacon",
                      f"RAIDA{raida_id}: {coin_count} coins, {total_value} CC")

            with results_lock:
                peek_results[raida_id] = total_value

        except Exception as e:
            log_debug(logger, "Beacon", f"RAIDA{raida_id}: Exception - {e}")

    # Query all 25 RAIDAs in parallel
    try:
        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(peek_single_raida, i)
                       for i in range(RAIDA_COUNT)]

            for future in as_completed(futures, timeout=10):
                try:
                    future.result()
                except Exception as e:
                    log_debug(logger, "Beacon", f"Worker exception: {e}")
    except Exception as e:
        log_error(logger, "Beacon", f"ThreadPool exception: {e}")
        return False, 0.0, "Cannot verify payment - threading error"

    # Check quorum
    response_count: int = len(peek_results)

    if response_count < MINIMUM_QUORUM:
        log_error(logger, "Beacon",
                  f"Insufficient RAIDA responses ({response_count}/{RAIDA_COUNT} < {MINIMUM_QUORUM})")
        return False, 0.0, f"Cannot verify payment - insufficient responses ({response_count}/{MINIMUM_QUORUM})"

    log_info(logger, "Beacon",
             f"Received {response_count}/{RAIDA_COUNT} responses (quorum: {MINIMUM_QUORUM})")

    # Use consensus
    value_counts: Dict[float, int] = {}
    for value in peek_results.values():
        value_counts[value] = value_counts.get(value, 0) + 1

    if not value_counts:
        log_error(logger, "Beacon", "No values to determine consensus")
        return False, 0.0, "Cannot verify payment - no consensus data"

    consensus_value = max(value_counts.items(), key=lambda x: x[1])
    actual_amount: float = consensus_value[0]
    vote_count: int = consensus_value[1]

    log_info(logger, "Beacon",
             f"Consensus: {actual_amount} CC ({vote_count}/{response_count} RAIDAs agree)")

    # Check if meets minimum
    if actual_amount >= required_payment:
        log_info(logger, "Beacon",
                 f"✓ Payment validated: {actual_amount} CC >= {required_payment} CC required")
        return True, actual_amount, f"Payment verified: {actual_amount} CC"
    else:
        log_warning(logger, "Beacon",
                    f"✗ Insufficient payment: {actual_amount} CC < {required_payment} CC required")
        return False, actual_amount, f"Insufficient payment: {actual_amount} CC < {required_payment} CC"


def start_periodic_healer(wallet_path: str, logger: Any, interval_hours: int = 1):
    """
   Background task that periodically ensures the entire wallet is healthy.
   Runs in a separate thread to avoid blocking the main application.
   """
    import time
    # This import must be here or at the top of app.py
    from heal import heal_wallet

    def healer_loop():
        # Wait 30 seconds after app start to let RAIDA servers stabilize
        time.sleep(30)

        while True:
            log_info(logger, "PeriodicHeal",
                     "Starting scheduled wallet health check.")
            try:
                # The yellow line appeared here because 'wallet_path'
                # wasn't in the function arguments or scope.
                heal_wallet(wallet_path)
                log_info(logger, "PeriodicHeal",
                         "Scheduled health check completed.")
            except Exception as e:
                log_error(logger, "PeriodicHeal",
                          f"Scheduled heal failed: {e}")

            # The yellow line appeared here because 'interval_hours'
            # wasn't defined in the function signature.
            log_info(logger, "PeriodicHeal",
                     f"Next check in {interval_hours} hours.")
            time.sleep(interval_hours * 3600)

    # Starts the healer in the background immediately
    healer_thread = threading.Thread(
        target=healer_loop, name="ScheduledHealer", daemon=True)
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
        print(
            f"[INIT] Created {len(wallet_result['created'])} wallet folders/files")
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
            print(
                f"[INIT] Data sync complete: {sync_result['users']} users, {sync_result['servers']} servers")
            log_info(
                logger, "App", f"Data sync complete: {sync_result['users']} users, {sync_result['servers']} servers")
        else:
            print(
                f"[WARNING] Data sync failed (error {sync_err}) - continuing with cached data")
            log_warning(logger, "App",
                        f"Data sync failed: {sync_err} - using cached data")
    else:
        print("[INIT] Skipping data sync (--skip-sync flag)")
        log_info(logger, "App", "Data sync skipped (--skip-sync flag)")

    # Start the server
    server.start()

    # Start beacon monitor if initialized
    if app_context.beacon_handle:
        # Initialize server cache for IP lookups (can be refreshed via app_context.refresh_server_cache())
        app_context.refresh_server_cache()

        # Callback to update beacon handle after restart
        def update_beacon_handle(new_handle):
            """Update the beacon handle reference after auto-restart"""
            app_context.beacon_handle = new_handle
            # Re-register the on_an_invalid callback
            new_handle.on_an_invalid = lambda id: move_identity_to_fracked(
                app_context.config.identity, new_handle, logger
            )
            log_info(logger, "App", "Beacon handle updated after auto-restart")
        
        app_context.beacon_handle.on_restart_callback = update_beacon_handle


        app_context.beacon_handle.on_an_invalid = lambda id: move_identity_to_fracked(
            id, app_context.beacon_handle, logger
        )

        def _extract_server_info(server_location):
            """
    Extract IP and port from ServerLocation raw_entry.

    server_loc_t structure (32 bytes):
        Bytes 0-1:   stripe_index + stripe_type
        Bytes 2-9:   stripe_id (reserved)
        Bytes 10-25: ip_address (IPv4 in last 4 bytes: 22-25)
        Bytes 26-27: port (Big Endian uint16)
        Bytes 28-31: reserved
         """
            if not hasattr(server_location, 'raw_entry') or len(server_location.raw_entry) < 28:
                # Fallback if raw_entry not available
                server_id = getattr(server_location, 'server_id', 0)
                return f"raida{server_id}.cloudcoin.global", 50000 + server_id

            raw = server_location.raw_entry

    # Extract IPv4 from bytes 22-25 (last 4 bytes of ip_address field)
            ip_bytes = raw[22:26]
            ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"

    # Extract port from bytes 26-27 (Big Endian)
            port = struct.unpack('>H', raw[26:28])[0]

            return ip, port

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

            if not app_context.db_handle or not app_context.db_handle.connection:
                return

            log_info(logger, "Beacon",
                     f"New mail detected: {len(notifications)} notification(s)")

            # Persist in memory for immediate UI/API access
            app_context.add_notifications(notifications)

            successful_count = 0
            failed_count = 0
            new_locker_found = False

            for notification in notifications:
                try:
                    # 1. EXTRACT & VALIDATE GUID
                    if not hasattr(notification, 'file_guid') or not notification.file_guid:
                        log_warning(
                            logger, "Beacon", "Received notification with missing or empty file_guid.")
                        failed_count += 1
                        continue

                    file_guid = notification.file_guid.hex() if hasattr(
                        notification.file_guid, 'hex') else str(notification.file_guid)

                    # 2. DOWNLOAD ONCE CHECK (Policy enforcement)
                    # We check the database to see if we've already stored this GUID.
                    if is_guid_in_database(app_context.db_handle, file_guid):
                        log_debug(
                            logger, "Beacon", f"Email {file_guid[:8]} already exists in local database. Skipping redundant processing.")
                        continue

                    # 3. LOCKER CODE CLEANING (Format: AS8D-HJL -> AS8DHJL)
                    locker_code = getattr(notification, 'locker_code', None)
                    if locker_code:
                        if isinstance(locker_code, str):
                            clean_code = locker_code.replace(
                                '-', '').strip().upper()
                            # Pad to 8 bytes with nulls for C-compatibility
                            locker_code = clean_code.encode(
                                'ascii').ljust(8, b'\x00')
                            log_debug(
                                logger, "Beacon", f"Cleaned/Padded locker: {clean_code} -> {locker_code.hex()}")
                        new_locker_found = True

                        new_locker_found = True
                    else:
                        log_debug(
                            logger, "Beacon", f"Notification {file_guid[:8]} does not contain a locker code.")

                        # 3.5: VALIDATE PAYMENT IF REQUIRED
                    if hasattr(config, 'recipient_payment') and hasattr(config.recipient_payment, 'require_payment') and config.recipient_payment.require_payment:
                        log_info(
                            logger, "Beacon", f"Validating payment for tell {file_guid[:8]}...")

                        # Get recipient user ID from identity config
                        recipient_user_id = config.identity.serial_number if hasattr(
                            config.identity, 'serial_number') else None

                        if recipient_user_id:
                            try:
                                # Call SYNCHRONOUS validation function
                                is_valid, actual_amount, message = validate_tell_payment_sync(
                                    locker_code,
                                    recipient_user_id,
                                    app_context.db_handle,
                                    logger
                                )

                                if not is_valid:
                                    log_warning(
                                        logger, "Beacon", f"Rejected tell {file_guid[:8]}: {message}")

                                    if hasattr(config.recipient_payment, 'auto_reject_unpaid') and config.recipient_payment.auto_reject_unpaid:
                                        failed_count += 1
                                        continue  # Skip storing this tell
                                else:
                                    log_info(
                                        logger, "Beacon", f"Tell {file_guid[:8]} payment validated: {message}")
                            except Exception as e:
                                log_error(logger, "Beacon",
                                          f"Payment validation exception: {e}")
                                # On error, accept tell (fail open)
                        else:
                            log_warning(
                                logger, "Beacon", "Cannot validate payment - no user_id in identity config")

                    # 4. STORE METADATA (received_tells table)
                    # We store the metadata so the download_handler can find it later.
                    err, tell_id = store_received_tell(
                        app_context.db_handle,
                        file_guid=file_guid,
                        locker_code=locker_code,
                        tell_type=getattr(notification, 'tell_type', 0)
                    )

                    if err != DatabaseErrorCode.SUCCESS:
                        log_error(
                            logger, "Beacon", f"Database error ({err}) while storing tell metadata for {file_guid[:8]}")
                        failed_count += 1
                        continue

                    # 5. STORE STRIPE LOCATIONS (received_stripes table)
                    # This maps which RAIDA servers actually have the data.
                    server_list = getattr(notification, 'server_list', [])
                    stripes_stored = 0

                    for server in server_list:
                        # Use the helper defined in the app.py scope to get IP
                        server_ip, server_port = _extract_server_info(server)

                        # Determine indices and parity status
                        stripe_index = getattr(server, 'stripe_index', 0)
                        # In the protocol, stripe_type 1 is usually Parity
                        is_parity = (getattr(server, 'stripe_type', 0) == 1)

                        s_err = store_received_stripe(
                            app_context.db_handle,
                            tell_id=tell_id,
                            server_ip=server_ip,
                            stripe_id=stripe_index,
                            is_parity=is_parity,
                            port=server_port
                        )

                        if s_err != DatabaseErrorCode.SUCCESS:
                            log_error(logger, "Beacon",
                                      f"Failed to store stripe {stripe_index}")
                            continue

                    stripes_stored += 1

                    log_info(
                        logger, "Beacon", f"Successfully cached metadata for {file_guid[:8]} with {stripes_stored} server locations.")
                    successful_count += 1

                except Exception as e:
                    log_error(
                        logger, "Beacon", f"Critical error processing notification GUID {getattr(notification, 'file_guid', 'UNKNOWN')}: {str(e)}")
                    failed_count += 1

            # 6. LOG BATCH SUMMARY
            if len(notifications) > 0:
                log_info(
                    logger, "Beacon", f"Batch Processing Complete: {successful_count} stored, {failed_count} failed.")

            # 7. BATCH HEALING TRIGGER
            # If any payments or staking coins were found, we need to fix them.
            if new_locker_found:
                def run_batch_heal():
                    # Import inside the thread to avoid circular dependencies
                    from heal import heal_wallet

                    # 10-second delay to allow background download tasks to settle
                    # before the healing orchestrator locks the wallet files.
                    time.sleep(10)

                    log_info(
                        logger, "HealTask", "Starting background batch healing pass for 'Default' wallet.")
                    try:
                        # Points to your standard CloudCoin wallet path
                        heal_wallet("Data/Wallets/Default")
                        log_info(
                            logger, "HealTask", "Background batch healing pass completed successfully.")
                    except Exception as he:
                        log_error(logger, "HealTask",
                                  f"Batch healing pass failed: {he}")

                # Daemon thread ensures the healing process doesn't hang the app shutdown
                heal_thread = threading.Thread(
                    target=run_batch_heal, name="BatchHealWorker", daemon=True)
                heal_thread.start()

        if start_beacon_monitor(app_context.beacon_handle, on_mail_received):
            log_info(logger, "App",
                     "Beacon monitor started - watching for new mail")
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
    print(
        f"  GET  {base_url}/api/qmail/ping            - Beacon check for new mail")

    print("\n[ Mail Operations ]")
    print(f"  POST {base_url}/api/mail/send             - Send email")
    print(
        f"  GET  {base_url}/api/mail/download/{{id}}    - Download email by GUID")
    print(
        f"  GET  {base_url}/api/mail/list             - List emails (inbox, sent, etc.)")
    print(
        f"  POST {base_url}/api/mail/create-mailbox   - Create new mailbox (Stake)")
    print(
        f"  GET  {base_url}/api/mail/folders          - List available mail folders")
    print(
        f"  GET  {base_url}/api/mail/count            - Get unread/total counts")

    print("\n[ Individual Email Management ]")
    print(f"  GET  {base_url}/api/mail/{{id}}             - Get email metadata")
    print(
        f"  DELETE {base_url}/api/mail/{{id}}           - Move email to trash")
    print(
        f"  PUT  {base_url}/api/mail/{{id}}/move        - Move email to folder")
    print(
        f"  PUT  {base_url}/api/mail/{{id}}/read        - Mark email read/unread")

    print("\n[ Attachments ]")
    print(
        f"  GET  {base_url}/api/mail/{{id}}/attachments     - List attachments for email")
    print(
        f"  GET  {base_url}/api/mail/{{id}}/attachment/{{n}} - Download specific attachment")

    print("\n[ Contacts & Users ]")
    print(
        f"  GET  {base_url}/api/contacts              - List/Search all contacts")
    print(f"  POST {base_url}/api/contacts              - Add a new contact")
    print(f"  DELETE {base_url}/api/contacts/{{id}}       - Delete a contact")
    print(
        f"  GET  {base_url}/api/data/contacts/popular - Get frequent contacts")
    print(
        f"  GET  {base_url}/api/data/users/search     - Search users for autocomplete")

    print("\n[ Drafts ]")
    print(f"  GET  {base_url}/api/mail/drafts           - List all drafts")
    print(f"  POST {base_url}/api/mail/draft            - Save a new draft")
    print(
        f"  PUT  {base_url}/api/mail/draft/{{id}}       - Update an existing draft")

    print("\n[ System & Data ]")
    print(
        f"  GET  {base_url}/api/data/emails/search    - Full-text search (FTS5)")
    print(
        f"  GET  {base_url}/api/data/servers          - Get QMail/RAIDA server list")
    print(
        f"  GET  {base_url}/api/wallet/balance        - Get full wallet balance")
    print(
        f"  POST {base_url}/api/locker/download       - Manual coin download via code")

    print("\n[ Administration & Sync ]")
    print(
        f"  POST {base_url}/api/admin/sync            - Trigger manual RAIDA data sync")
    print(
        f"  GET  {base_url}/api/admin/servers/parity  - Get current parity server")
    print(
        f"  POST {base_url}/api/admin/servers/parity  - Set parity server configuration")

    print("\n[ Task Management ]")
    print(
        f"  GET  {base_url}/api/task/status/{{id}}      - Check async task status")
    print(
        f"  POST {base_url}/api/task/cancel/{{id}}      - Cancel a pending task")
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
