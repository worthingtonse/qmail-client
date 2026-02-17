"""
payment.py - Payment Calculator Module for QMail Client Core

This module handles payment calculations for email storage and retrieval,
including server fee lookups and locker code generation.

Author: Claude Opus 4.5
Phase: I
Version: 1.0.0

Functions:
    calculate_storage_cost() - Calculate cost for storing data
    get_server_fees() - Get fee structure from database
    request_locker_code() - Generate locker code for payment
    weeks_to_duration_code() - Convert weeks to protocol duration code
"""

import asyncio
import math
import os
import secrets
import string
from typing import Dict, List, Optional, Tuple, Any  # 
from dataclasses import dataclass

from qmail_types import ErrorCode
from logger import log_error, log_info, log_warning, log_debug
from coin_scanner import  parse_denomination_code , get_coins_by_value
from coin_break import break_coin
from locker_put import put_to_locker, CoinForPut, PutResult
from key_manager import get_keys_from_locker_code


try:
    from qmail_types import ErrorCode, StorageDuration
    from logger import log_error, log_info, log_debug, log_warning
    from protocol import weeks_to_duration_code
    from wallet_structure import initialize_wallet_structure
except ImportError:
    # Fallback for standalone testing
    from enum import IntEnum

    class ErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_PARAM = 1
        ERR_NOT_FOUND = 2
        ERR_INTERNAL = 9

    class StorageDuration:
        ONE_DAY = 0
        ONE_WEEK = 1
        ONE_MONTH = 2
        THREE_MONTHS = 3
        SIX_MONTHS = 4
        ONE_YEAR = 5
        PERMANENT = 255

    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")

    def weeks_to_duration_code(weeks: int) -> int:
        if weeks <= 0:
            return 0
        elif weeks == 1:
            return 1
        elif weeks <= 4:
            return 2
        elif weeks <= 12:
            return 3
        elif weeks <= 26:
            return 4
        elif weeks <= 52:
            return 5
        else:
            return 255

    from wallet_structure import initialize_wallet_structure


# ============================================================================
# CONSTANTS
# ============================================================================

PAYMENT_CONTEXT = "PaymentMod"

# Default values
DEFAULT_COST_PER_MB = 0.001      # Default cost per MB if not in database
DEFAULT_COST_PER_WEEK = 0.0001   # Default cost per week if not in database
DEFAULT_STORAGE_WEEKS = 8        # Default storage duration
NUM_SERVERS = 5                  # Number of servers (4 data + 1 parity)


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ServerFees:
    """
    Fee structure for a single server.
    Matches RAIDA11 8-week block model.
    """
    server_id: str
    cost_per_mb: float = 1.0
    cost_per_8_weeks: float = 1.0  
    is_available: bool = True

@dataclass
class PaymentCalculation:
    """Result of a payment calculation."""
    total_cost: float = 0.0
    storage_cost: float = 0.0
    recipient_fees: float = 0.0
    server_breakdown: Dict[str, float] = None
    duration_code: int = StorageDuration.ONE_MONTH
    error_code: ErrorCode = ErrorCode.SUCCESS
    error_message: str = ""

    def __post_init__(self):
        if self.server_breakdown is None:
            self.server_breakdown = {}


@dataclass 
class ServerPayment:
    """Payment prepared for a single QMail server."""
    server_index: int           # Index from database
    server_id: str              # e.g., "RAIDA1" from database  
    ip_address: str             # Server IP for upload
    port: int                   # Server port for upload
    amount: float               # Amount in CC
    locker_code: bytes          # 8-byte locker code
    locker_code_str: str        # String form "XXX-XXXX"
    success: bool = False


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def calculate_storage_cost(
    total_file_size_bytes: int,
    storage_weeks: int,
    server_fees: List[ServerFees] 
) -> float:
    """
    Uses the 8-week block math from the qmail_servers service.
    Formula: (MB * cost_per_mb) + ((weeks / 8) * cost_per_8_weeks)
    """
    size_mb = total_file_size_bytes / (1024 * 1024)
    total_storage_cost = 0.0
    
    # Calculate for the first 5 servers (4 data + 1 parity)
    # We use min() to avoid crashing if fewer than 5 servers exist
    servers_to_pay = server_fees[:5]
    
    for fee in servers_to_pay:
        # MB component
        mb_cost = size_mb * fee.cost_per_mb
        
        # Duration component (normalized to 8-week blocks)
        # e.g., 4 weeks = 0.5 blocks cost
        duration_blocks = storage_weeks / 8.0
        time_cost = duration_blocks * fee.cost_per_8_weeks
        
        total_storage_cost += (mb_cost + time_cost)
        
    return total_storage_cost

def calculate_recipient_fees(db_handle, recipients_list) -> float:
    """
    Calculates the total CC fees for all recipients.
    FIXED: Now supports Pretty Email Addresses by looking up fees in the database.
    """
    from src.database import get_user_by_address, DatabaseErrorCode
    from src.logger import log_debug
    
    total_fee = 0.0
    
    if not recipients_list:
        return 0.0

    for addr in recipients_list:
        # addr can be "Sean.Worthington@CEO#C23.Giga"
        # We use the new database function we just created
        err, user_info = get_user_by_address(db_handle, addr)
        
        if err == DatabaseErrorCode.SUCCESS and user_info:
            fee = user_info.get('inbox_fee', 0.0)
            total_fee += fee
            log_debug(db_handle.logger, "Payment", f"Fee for {addr}: {fee} CC")
        else:
            # Fallback: Agar DB mein nahi mila (rare), toh koi fee assume nahi karenge
            # ya standard fee laga sakte hain.
            continue
            
    return total_fee


def get_server_fees(
    db_handle: object,
    server_ids: Optional[List[str]] = None,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, List[ServerFees]]:
    """
    Get fee structures for servers from the database.
    Updated to read 'cost_per_8_weeks' correctly.
    """
    try:
        # Try to import database module
        try:
            from . import database
        except ImportError:
            import database

        # Get servers from database
        # database.py now returns dicts with 'cost_per_8_weeks'
        err, servers = database.get_all_servers(db_handle, available_only=True)

        if err != 0:
            log_error(logger_handle, PAYMENT_CONTEXT, "get_server_fees failed",
                      "Database query failed")
            return ErrorCode.ERR_INTERNAL, []

        fees = []
        for server in servers:
            server_id = server.get('server_id', '')

            # Filter by server_ids if provided
            if server_ids and server_id not in server_ids:
                continue

            # 1. Parse cost_per_mb
            cost_per_mb = DEFAULT_COST_PER_MB
            if server.get('cost_per_mb') is not None:
                try:
                    cost_per_mb = float(server['cost_per_mb'])
                except (ValueError, TypeError):
                    pass

            # 2. Parse cost_per_8_weeks (The Fix)
            # We default to 1.0 based on your JSON, but fall back safely
            cost_per_8_weeks = 1.0 
            if server.get('cost_per_8_weeks') is not None:
                try:
                    cost_per_8_weeks = float(server['cost_per_8_weeks'])
                except (ValueError, TypeError):
                    pass
            elif server.get('cost_per_week') is not None:
                # Legacy fallback: if DB has old data, convert week -> 8 weeks
                try:
                    cost_per_8_weeks = float(server['cost_per_week']) * 8.0
                except (ValueError, TypeError):
                    pass

            fees.append(ServerFees(
                server_id=server_id,
                cost_per_mb=cost_per_mb,
                cost_per_8_weeks=cost_per_8_weeks, # <--- Correct field assignment
                is_available=server.get('is_available', True)
            ))

        log_debug(logger_handle, PAYMENT_CONTEXT,
                  f"Retrieved fees for {len(fees)} servers")

        return ErrorCode.SUCCESS, fees

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, "get_server_fees failed", str(e))
        return ErrorCode.ERR_INTERNAL, []
# create locker async right now introduces dust threshold , the amount that we overpay (minute amount just to avoid a lot of make change calls )
async def _create_locker_async( 
    amount: float, 
    wallet_path: str, 
    logger_handle: object,
    config: object = None,
    identity_sn: int = 0
) -> Tuple[ErrorCode, bytes, List]:
    """
    Async implementation of locker creation with iterative coin breaking.
    
    NOTE: Pre-flight healing is done BEFORE this function is called.
    This function focuses on coin selection, breaking, and PUT.
    
    Returns:
        Tuple of (error_code, locker_code_bytes, failed_coins)
        - failed_coins: List of coins that failed PUT (for healing by caller)
    """
    import math
    import secrets
    import string
    import asyncio 
    
    MAX_LOOPS = 50
    MIN_PASSES_FOR_SUCCESS = 13 # Matches Go: MIN_PASSED_NUM_TO_BE_AUTHENTIC
    
    try:
        for _ in range(MAX_LOOPS):
            # 1. Get coins (only healthy coins based on file POWN)
            coins = get_coins_by_value(wallet_path, amount, identity_sn=identity_sn)
            
            if not coins:
                 try:
                     all_coins = get_coins_by_value(wallet_path, 0.0, identity_sn=identity_sn)
                     available = sum(parse_denomination_code(c.denomination) for c in all_coins) if all_coins else 0.0
                 except:
                     available = 0.0    
                 log_error(logger_handle, PAYMENT_CONTEXT,
                            f"INSUFFICIENT_FUNDS: Need {amount:.8f} CC, have {available:.8f} CC")
                 return ErrorCode.ERR_NOT_FOUND, b'', []

            
            total_value_selected = sum(parse_denomination_code(c.denomination) for c in coins)
            diff = total_value_selected - amount

            # 2. Check for Match OR Acceptable Overpayment
            acceptable_overpay = max(0.0001, amount * 0.05)
            
            if diff >= -0.00000001 and diff < acceptable_overpay:
                
                log_info(logger_handle, PAYMENT_CONTEXT, 
                         f"Locking {total_value_selected:.8f} for payment of {amount:.8f} (Overpayment: {diff:.8f})")

                # Generate locker code
                random_chars = ''.join(secrets.choice(string.ascii_uppercase + string.digits) 
                                       for _ in range(7))
                locker_code_str = random_chars[:3] + '-' + random_chars[3:]
                log_warning(logger_handle, PAYMENT_CONTEXT, 
                         f"PAYMENT CREATED: Locker Code is {locker_code_str} (Save this in case of crash!)")
                locker_keys = get_keys_from_locker_code(locker_code_str)
                
                coins_for_put = [
                    CoinForPut(c.denomination, c.serial_number, c.ans) 
                    for c in coins
                ]
                
                # Attempt PUT
                put_result, raida_results = await put_to_locker(coins_for_put, locker_keys)
                
                # ============================================================
                # ANALYZE PUT RESULTS
                # ============================================================
                pass_count = sum(1 for s, _ in raida_results.values() if s == 241)
                fail_count = sum(1 for s, _ in raida_results.values() if s == 242)
                timeout_count = sum(1 for s, _ in raida_results.values() if s == -1)
                other_count = 25 - pass_count - fail_count - timeout_count
                
                log_info(logger_handle, PAYMENT_CONTEXT,
                         f"PUT results: {pass_count} pass, {fail_count} fail, "
                         f"{timeout_count} timeout, {other_count} other")
                
                # ============================================================
                # SUCCESS: Need at least 14 passes (matches Go code)
                # ============================================================
                if pass_count >= MIN_PASSES_FOR_SUCCESS:
                    log_info(logger_handle, PAYMENT_CONTEXT,
                             f"PUT SUCCESS with {pass_count}/25 passes (threshold: {MIN_PASSES_FOR_SUCCESS})")
                    
                    # Delete coins from disk
                    for c in coins:
                        try:
                            if os.path.exists(c.file_path):
                                os.remove(c.file_path)
                        except: 
                            pass

                    locker_code_bytes = locker_code_str.encode('ascii').ljust(8, b'\x00')
                    return ErrorCode.SUCCESS, locker_code_bytes, []
                
                # ============================================================
                # FAILURE: Not enough passes - analyze WHY
                # ============================================================
                log_error(logger_handle, PAYMENT_CONTEXT, 
                          f"PUT FAILED: Only {pass_count} passes (need {MIN_PASSES_FOR_SUCCESS})")
                
                # Case A: Too many timeouts - network issue, don't blame coins
                if timeout_count > 11:  # More than 11 timeouts = network problem
                    log_error(logger_handle, PAYMENT_CONTEXT, 
                              "PUT failed due to network issues (too many timeouts). "
                              "Please check internet connection.")
                    return ErrorCode.ERR_INTERNAL, b'', []
                
                # Case B: Too many fails - coins have wrong ANs, need healing
                
                if fail_count > 11:  # More than 11 fails = coins are bad
                    if pass_count >= 13:
                        # Healable - move to Fracked
                        log_warning(logger_handle, PAYMENT_CONTEXT,
                                    f"PUT failed - coins have wrong ANs on {fail_count} RAIDAs. "
                                    f"Moving to Fracked for healing.")
                        return ErrorCode.ERR_INTERNAL, b'', coins  # Return coins for healing
                    else:
                        # <13 passes = Counterfeit (lost forever)
                        log_error(logger_handle, PAYMENT_CONTEXT,
                                  f"PUT failed - coins are COUNTERFEIT ({pass_count} passes < 13). "
                                  f"Moving to Counterfeit folder.")
                        # Move to Counterfeit instead of Fracked
                        counterfeit_path = os.path.join(wallet_path, "Counterfeit")
                        os.makedirs(counterfeit_path, exist_ok=True)
                        for c in coins:
                            try:
                                if os.path.exists(c.file_path):
                                    import shutil
                                    dest = os.path.join(counterfeit_path, os.path.basename(c.file_path))
                                    shutil.move(c.file_path, dest)
                            except:
                                pass
                        return ErrorCode.ERR_INTERNAL, b'', []  # Empty list - don't try to heal
                
                # Case C: Mixed/inconclusive - retry without healing
                # Could be temporary network + a few bad RAIDAs
                log_warning(logger_handle, PAYMENT_CONTEXT,
                            f"PUT inconclusive: {pass_count}p/{fail_count}f/{timeout_count}t. "
                            f"Will retry...")
                return ErrorCode.ERR_INTERNAL, b'', []

            # 3. SIGNIFICANT OVERPAYMENT: Must Break a Coin
            elif diff >= acceptable_overpay:
                coins.sort(key=lambda x: parse_denomination_code(x.denomination), reverse=True)
                coin_to_break = coins[0]
                
                log_info(logger_handle, PAYMENT_CONTEXT,
                         f"Have {total_value_selected:.8f}, need {amount:.8f}. "
                         f"Breaking coin SN={coin_to_break.serial_number}")
                
                break_result = await break_coin(coin_to_break, wallet_path, config, logger_handle)
                
                success = False
                if hasattr(break_result, 'success'): 
                    success = break_result.success
                elif isinstance(break_result, list) and break_result: 
                    success = True
                
                if not success:
                    log_error(logger_handle, PAYMENT_CONTEXT, "Coin break failed")
                    return ErrorCode.ERR_INTERNAL, b'', []
                
                await asyncio.sleep(0.5)
                # Force filesystem sync on Windows
                import gc
                gc.collect()
                continue
                
        log_error(logger_handle, PAYMENT_CONTEXT, "Unable to make exact change after max attempts")
        return ErrorCode.ERR_INTERNAL, b'', []

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, f"Async locker creation crashed: {e}")
        return ErrorCode.ERR_INTERNAL, b'', []
def request_locker_code(
    amount: float,
    db_handle: Optional[object] = None,
    logger_handle: Optional[object] = None,
    config: Optional[object] = None,     # Added for Network
    identity_sn: int = 0                 # Added to protect ID coin
) -> Tuple[ErrorCode, bytes]:
    """
    Request a locker code from cloudcoin for the specified amount.
    STRICT IMPLEMENTATION: Scans, Breaks, and Locks real coins.
    """
    # Hardcoded wallet path matching your logs/project structure
    WALLET_PATH = "Data/Wallets/Default"

    try:
        # Run the async logic synchronously
        result = asyncio.run(_create_locker_async(
            amount, WALLET_PATH, logger_handle, config, identity_sn
        ))
        return result

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, "request_locker_code failed", str(e))
        return ErrorCode.ERR_INTERNAL, b''
    

async def _prepare_server_payments_async(
    db_handle: object,
    total_file_size_bytes: int,
    storage_weeks: int,
    wallet_path: str,
    logger_handle: Optional[object] = None,
    config: Optional[object] = None,
    identity_sn: int = 0
) -> Tuple[ErrorCode, List[ServerPayment]]:
    """
    Prepare payments for ALL available QMail storage servers from database.
    
    ATOMIC GUARANTEE: Either ALL payments succeed or NONE.
    
    Features:
    - PRE-FLIGHT: Verify/heal Bank coins ONCE before payment loop
    - Retry on PUT failure (1 retry before rollback)
    - Automatic rollback if any locker creation fails
    - Move coins to Fracked and heal when PUT fails (AN mismatch)
    
    Flow:
    1. Fetch ALL available servers from DATABASE
    2. Calculate TOTAL amount needed
    3. PRE-FLIGHT: Verify Bank coins, heal if needed
    4. Create locker for each server (with retry)
    5. If ANY fails: ROLLBACK all successful lockers
    """
    CONTEXT = "MultiPayment"
    
    # Retry configuration
    PUT_MAX_ATTEMPTS = 2
    PUT_RETRY_DELAY = 2.0
    ROLLBACK_MAX_ATTEMPTS = 2
    ROLLBACK_RETRY_DELAY = 2.0
    HEAL_WAIT_TIME = 1.0
    
    # Import locker download for rollback capability
    try:
        from locker_download import download_from_locker, LockerDownloadResult
    except ImportError:
        try:
            from .locker_download import download_from_locker, LockerDownloadResult
        except ImportError:
            log_error(logger_handle, CONTEXT, "Cannot import locker_download module")
            return ErrorCode.ERR_INTERNAL, []
    
    # --- 1. Fetch ALL available servers from DATABASE ---
    try:
        from database import get_all_servers, DatabaseErrorCode
    except ImportError:
        try:
            from .database import get_all_servers, DatabaseErrorCode
        except ImportError:
            log_error(logger_handle, CONTEXT, "Cannot import database module")
            return ErrorCode.ERR_INTERNAL, []
    
    err, db_servers = get_all_servers(db_handle, available_only=True)
    
    if err != DatabaseErrorCode.SUCCESS or not db_servers:
        log_error(logger_handle, CONTEXT, "Failed to get servers from database")
        return ErrorCode.ERR_NOT_FOUND, []
    
    num_servers = len(db_servers)
    
    if num_servers == 0:
        log_error(logger_handle, CONTEXT, "No available servers in database")
        return ErrorCode.ERR_NOT_FOUND, []
    
    log_info(logger_handle, CONTEXT,
             f"Preparing payments for {num_servers} servers from database")
    
    # --- 2. Calculate TOTAL amount needed for ALL servers ---
    size_mb = total_file_size_bytes / (1024 * 1024)
    duration_blocks = storage_weeks / 8.0
    
    server_amounts = []  # List of (server_dict, amount)
    total_needed = 0.0
    
    for srv in db_servers:
        cost_per_mb = float(srv.get('cost_per_mb', 1.0) or 1.0)
        cost_per_8_weeks = float(srv.get('cost_per_8_weeks', 1.0) or 1.0)
        
        amount = (size_mb * cost_per_mb) + (duration_blocks * cost_per_8_weeks)
        server_amounts.append((srv, amount))
        total_needed += amount
        
        log_debug(logger_handle, CONTEXT,
                  f"Server {srv.get('server_id')}: {amount:.8f} CC "
                  f"(MB: {cost_per_mb}, 8wk: {cost_per_8_weeks})")
    
    log_info(logger_handle, CONTEXT,
             f"Total payment needed: {total_needed:.8f} CC across {num_servers} servers")
    
    # --- 3. PRE-FLIGHT: Verify Bank coins and heal if needed ---
    log_info(logger_handle, CONTEXT, "PRE-FLIGHT: Verifying Bank coins...")
    
    preflight_success = await _preflight_verify_and_heal(
        wallet_path=wallet_path,
        total_amount_needed=total_needed,
        identity_sn=identity_sn,
        logger_handle=logger_handle
    )
    
    if not preflight_success:
        log_error(logger_handle, CONTEXT, 
                  f"PRE-FLIGHT FAILED: Not enough healthy coins for {total_needed:.8f} CC")
        return ErrorCode.ERR_NOT_FOUND, []
    
    log_info(logger_handle, CONTEXT, "PRE-FLIGHT: Bank coins verified ✓")
    
    # --- 4. Create locker for each server (with retry and rollback on failure) ---
    payments = []
    failed_server_id = None
    failure_error = None
    
    for srv, amount in server_amounts:
        server_id = srv.get('server_id', '')
        server_index = srv.get('server_index', 0)
        ip_address = srv.get('ip_address', '')
        port = srv.get('port', 0)
        
        # --- Handle zero-cost servers ---
        if amount <= 0.00000001:
            code_str = "000-0000"
            
            payments.append(ServerPayment(
                server_index=server_index,
                server_id=server_id,
                ip_address=ip_address,
                port=port,
                amount=0.0,
                locker_code=code_str.encode('ascii'),
                locker_code_str=code_str,
                success=True
            ))
            log_debug(logger_handle, CONTEXT,
                      f"Zero-cost for {server_id}, skipping payment")
            continue
        
        # --- Create locker with retry ---
        locker_code = None
        last_error = None
        
        for attempt in range(PUT_MAX_ATTEMPTS):
            if attempt > 0:
                log_warning(logger_handle, CONTEXT,
                            f"Retrying locker creation for {server_id} "
                            f"(attempt {attempt + 1}/{PUT_MAX_ATTEMPTS})...")
                await asyncio.sleep(PUT_RETRY_DELAY)
            
            log_info(logger_handle, CONTEXT,
                     f"Creating locker for {server_id}: {amount:.8f} CC")
            
            err, locker_code, failed_coins = await _create_locker_async(
                amount=amount,
                wallet_path=wallet_path,
                logger_handle=logger_handle,
                config=config,
                identity_sn=identity_sn
            )
            
            if err == ErrorCode.SUCCESS and locker_code:
                # Success - break out of retry loop
                break
            
            # --- Handle PUT failure due to AN mismatch ---
            if failed_coins and len(failed_coins) > 0:
                log_warning(logger_handle, CONTEXT,
                            f"PUT failed - coins have wrong ANs. Moving to Fracked and healing...")
                
                # Move coins to Fracked
                await _move_coins_to_fracked(failed_coins, wallet_path, logger_handle)
                
                # Heal
                await _attempt_heal_wallet(wallet_path, logger_handle)
                
                # Wait for filesystem sync
                await asyncio.sleep(HEAL_WAIT_TIME)
            
            last_error = err
            locker_code = None
            log_warning(logger_handle, CONTEXT,
                        f"Locker creation failed for {server_id}: {err} "
                        f"(attempt {attempt + 1}/{PUT_MAX_ATTEMPTS})")
        
        # --- Check if all attempts failed ---
        if locker_code is None:
            log_error(logger_handle, CONTEXT,
                      f"Failed to create locker for {server_id} after {PUT_MAX_ATTEMPTS} attempts")
            failed_server_id = server_id
            failure_error = last_error
            break  # Exit loop to trigger rollback
        
        # --- Success - add to payments list ---
        locker_str = locker_code[:8].decode('ascii', errors='ignore').strip('\x00')
        
        payments.append(ServerPayment(
            server_index=server_index,
            server_id=server_id,
            ip_address=ip_address,
            port=port,
            amount=amount,
            locker_code=locker_code,
            locker_code_str=locker_str,
            success=True
        ))
        
        log_info(logger_handle, CONTEXT,
                 f"Locker created for {server_id}: {locker_str}")
    
    # --- 5. Check if we need to rollback ---
    if failed_server_id is not None:
        payments_to_rollback = [p for p in payments if p.amount > 0]
        
        if payments_to_rollback:
            log_warning(logger_handle, CONTEXT,
                        f"Payment failed at {failed_server_id}. "
                        f"Rolling back {len(payments_to_rollback)} successful lockers...")
            
            # --- ROLLBACK with retry ---
            rollback_success_count = 0
            rollback_fail_count = 0
            failed_lockers = []
            
            for p in payments_to_rollback:
                rollback_succeeded = False
                
                for attempt in range(ROLLBACK_MAX_ATTEMPTS):
                    if attempt > 0:
                        log_warning(logger_handle, CONTEXT,
                                    f"Retrying rollback for {p.server_id} "
                                    f"(attempt {attempt + 1}/{ROLLBACK_MAX_ATTEMPTS})...")
                        await asyncio.sleep(ROLLBACK_RETRY_DELAY)
                    
                    try:
                        log_info(logger_handle, CONTEXT,
                                 f"Rollback: Recovering coins from {p.server_id} ({p.locker_code_str})")
                        
                        result, recovered_coins = await download_from_locker(
                            locker_code=p.locker_code,
                            wallet_path=wallet_path,
                            db_handle=db_handle,
                            logger_handle=logger_handle
                        )
                        
                        if result == LockerDownloadResult.SUCCESS:
                            coin_count = len(recovered_coins) if recovered_coins else 0
                            log_info(logger_handle, CONTEXT,
                                     f"Rollback SUCCESS for {p.server_id}: {coin_count} coins recovered")
                            rollback_succeeded = True
                            break
                            
                        elif result == LockerDownloadResult.ERR_LOCKER_EMPTY:
                            log_warning(logger_handle, CONTEXT,
                                        f"Rollback: Locker {p.locker_code_str} is empty")
                            rollback_succeeded = True
                            break
                            
                        else:
                            log_warning(logger_handle, CONTEXT,
                                        f"Rollback attempt {attempt + 1} failed: {result}")
                            
                    except Exception as e:
                        log_warning(logger_handle, CONTEXT,
                                    f"Rollback attempt {attempt + 1} exception: {e}")
                
                if rollback_succeeded:
                    rollback_success_count += 1
                else:
                    rollback_fail_count += 1
                    failed_lockers.append(p)
            
            # Log rollback summary
            if rollback_fail_count > 0:
                log_error(logger_handle, CONTEXT,
                          f"ROLLBACK INCOMPLETE: {rollback_success_count} recovered, "
                          f"{rollback_fail_count} failed. Manual recovery required!")
                log_error(logger_handle, CONTEXT, "=" * 50)
                log_error(logger_handle, CONTEXT, "MANUAL RECOVERY - SAVE THESE LOCKER CODES:")
                for p in failed_lockers:
                    log_error(logger_handle, CONTEXT,
                              f"  Locker: {p.locker_code_str} | Server: {p.server_id} | Amount: {p.amount:.8f} CC")
                log_error(logger_handle, CONTEXT, "=" * 50)
            else:
                log_info(logger_handle, CONTEXT,
                         f"ROLLBACK COMPLETE: All {rollback_success_count} lockers recovered")
        else:
            log_info(logger_handle, CONTEXT,
                     f"Payment failed at {failed_server_id}, but no paid lockers to rollback")
        
        return failure_error or ErrorCode.ERR_INTERNAL, []
    
    # --- 6. All payments created successfully ---
    log_info(logger_handle, CONTEXT,
             f"All {len(payments)} storage lockers created")
    
    return ErrorCode.SUCCESS, payments


async def _preflight_verify_and_heal(
    wallet_path: str,
    total_amount_needed: float,
    identity_sn: int,
    logger_handle: object
) -> bool:
    """
    PRE-FLIGHT CHECK: Verify Bank coins are healthy and heal if needed.
    
    This runs ONCE before the payment loop to ensure all coins are ready.
    
    Returns:
        True if enough healthy coins are available (after healing if needed)
        False if insufficient funds even after healing
    """
    CONTEXT = "PreFlight"
    
    try:
        from heal import verify_bank_coins, heal_wallet
    except ImportError:
        try:
            from .heal import verify_bank_coins, heal_wallet
        except ImportError:
            log_warning(logger_handle, CONTEXT, "Cannot import heal module - skipping pre-flight")
            return True  # Continue without pre-flight
    
    try:
        # Step 1: Verify Bank coins and move fracked ones to Fracked folder
        log_info(logger_handle, CONTEXT, "Verifying Bank coins...")
        err, checked, moved = verify_bank_coins(wallet_path)
        
        log_info(logger_handle, CONTEXT, 
                 f"Verified: {checked} coins checked, {moved} moved to Fracked")
        
        # Step 2: If fracked coins found, heal them
        if moved > 0:
            log_info(logger_handle, CONTEXT, 
                     f"Found {moved} fracked coins. Healing...")
            
            result = heal_wallet(wallet_path, max_iterations=2)
            
            log_info(logger_handle, CONTEXT,
                     f"Healed: {result.total_fixed}/{result.total_fracked} coins fixed")
            
            # Wait for filesystem to sync
            await asyncio.sleep(1.0)
        
        # Step 3: Check if we have enough healthy coins now
        coins = get_coins_by_value(wallet_path, total_amount_needed, identity_sn=identity_sn)
        
        if not coins:
            log_error(logger_handle, CONTEXT,
                      f"Insufficient healthy coins for {total_amount_needed:.8f} CC")
            return False
        
        total_available = sum(parse_denomination_code(c.denomination) for c in coins)
        log_info(logger_handle, CONTEXT,
                 f"Available: {total_available:.8f} CC (need {total_amount_needed:.8f} CC) ✓")
        
        return True
        
    except Exception as e:
        log_error(logger_handle, CONTEXT, f"Pre-flight check failed: {e}")
        return False


async def _move_coins_to_fracked( # this is only working as a helper to the prepare payment function otherwise a different function is mostly used for this purpose this is kind of redundant but serves the purpose
    coins: List, 
    wallet_path: str, 
    logger_handle: object
) -> int:
    """Move coins from Bank to Fracked folder."""
    import shutil
    
    CONTEXT = "CoinMove"
    fracked_path = os.path.join(wallet_path, "Fracked")
    os.makedirs(fracked_path, exist_ok=True)
    
    moved_count = 0
    for c in coins:
        try:
            if os.path.exists(c.file_path):
                dest = os.path.join(fracked_path, os.path.basename(c.file_path))
                shutil.move(c.file_path, dest)
                moved_count += 1
                log_debug(logger_handle, CONTEXT, f"Moved SN={c.serial_number} to Fracked")
        except Exception as e:
            log_warning(logger_handle, CONTEXT, f"Failed to move SN={c.serial_number}: {e}")
    
    log_info(logger_handle, CONTEXT, f"Moved {moved_count}/{len(coins)} coins to Fracked")
    return moved_count


async def _attempt_heal_wallet(
    wallet_path: str, 
    logger_handle: object
) -> bool:
    """Attempt to heal fracked coins in wallet."""
    CONTEXT = "Heal"
    
    try:
        from heal import heal_wallet
    except ImportError:
        try:
            from .heal import heal_wallet
        except ImportError:
            log_warning(logger_handle, CONTEXT, "Cannot import heal module")
            return False
    
    try:
        log_info(logger_handle, CONTEXT, "Starting heal process...")
        result = heal_wallet(wallet_path, max_iterations=2)
        
        if result.total_fixed > 0:
            log_info(logger_handle, CONTEXT,
                     f"Healed {result.total_fixed}/{result.total_fracked} coins")
            return True
        elif result.total_fracked == 0:
            log_info(logger_handle, CONTEXT, "No fracked coins to heal")
            return True
        else:
            log_warning(logger_handle, CONTEXT,
                        f"Healing incomplete: 0/{result.total_fracked} fixed")
            return True
            
    except Exception as e:
        log_error(logger_handle, CONTEXT, f"Healing failed: {e}")
        return False



def prepare_server_payments(
    db_handle: object,
    total_file_size_bytes: int,
    storage_weeks: int,
    wallet_path: str = "Data/Wallets/Default",
    logger_handle: Optional[object] = None,
    config: Optional[object] = None,
    identity_sn: int = 0
) -> Tuple[ErrorCode, List[ServerPayment]]:
    """
    Synchronous wrapper for _prepare_server_payments_async.
    
    Handles event loop detection to avoid nested asyncio.run() errors.
    """
    try:
        # Check if we're already in an async context
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context - use ThreadPoolExecutor
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run,
                    _prepare_server_payments_async(
                        db_handle, total_file_size_bytes, storage_weeks,
                        wallet_path, logger_handle, config, identity_sn
                    )
                )
                return future.result(timeout=120)
        except RuntimeError:
            # No running loop - safe to use asyncio.run()
            return asyncio.run(_prepare_server_payments_async(
                db_handle, total_file_size_bytes, storage_weeks,
                wallet_path, logger_handle, config, identity_sn
            ))
    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, f"prepare_server_payments failed: {e}")
        return ErrorCode.ERR_INTERNAL, []

def calculate_total_payment(
    file_sizes: List[int],
    storage_weeks: int,
    recipients: List[str],  # <--- Correct: Accepts list of addresses
    db_handle: object,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, PaymentCalculation]:
    """
    Calculate total payment, including per-user Inbox Fees from the database.
    """
    result = PaymentCalculation()

    # --- 1. Get Server Fees ---
    err, server_fees = get_server_fees(db_handle, logger_handle=logger_handle)
    if err != ErrorCode.SUCCESS or not server_fees:
        if logger_handle:
            log_warning(logger_handle, PAYMENT_CONTEXT, "Using default server fees")
        server_fees = [ServerFees(server_id=f"default_{i}") for i in range(NUM_SERVERS)]

    while len(server_fees) < NUM_SERVERS:
        server_fees.append(ServerFees(server_id=f"default_{len(server_fees)}"))

    # --- 2. Calculate Storage Cost ---
    total_size = sum(file_sizes) if file_sizes else 0
    try:
        # FIX: calculate_storage_cost returns a float, not a tuple.
        storage_cost_float = calculate_storage_cost(total_size, storage_weeks, server_fees)
        
        result.storage_cost = storage_cost_float
        result.duration_code = weeks_to_duration_code(storage_weeks)
    except Exception as e:
        if logger_handle:
            log_error(logger_handle, PAYMENT_CONTEXT, f"Storage calc failed: {e}")
        return ErrorCode.ERR_INTERNAL, result

    # --- 3. Calculate Recipient Fees (Robust Logic) ---
    total_recipient_fee = 0.0
    
    # Robust Import: Handle both package and local execution contexts
    get_user_by_address = None
    DatabaseErrorCode = None
    try:
        from .database import get_user_by_address, DatabaseErrorCode
    except ImportError:
        try:
            from database import get_user_by_address, DatabaseErrorCode
        except ImportError:
            pass # Fallback: db functions not available

    if get_user_by_address and recipients:
        for addr in recipients:
            # Type Safety: Ensure address is a string before DB lookup
            addr_str = str(addr).strip()
            
            # Look up user in DB to find their specific InboxFee
            err, user = get_user_by_address(db_handle, addr_str)
            
            if err == DatabaseErrorCode.SUCCESS and user:
                # Default to 0.0 if 'inbox_fee' is missing or None
                fee = float(user.get('inbox_fee', 0.0))
                total_recipient_fee += fee
            else:
                # User not in local DB (unknown contact). 
                # Phase 1 Policy: Charge 0.0 for unknown users.
                pass
    
    result.recipient_fees = total_recipient_fee

    # --- 4. Final Totals ---
    result.total_cost = result.storage_cost + result.recipient_fees
    result.error_code = ErrorCode.SUCCESS

    if logger_handle:
        log_info(logger_handle, PAYMENT_CONTEXT,
             f"Total: {result.total_cost:.4f} (Storage: {result.storage_cost:.4f}, Recip: {result.recipient_fees:.4f})")

    return ErrorCode.SUCCESS, result
# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("=" * 60)
    print("payment.py - Test Suite")
    print("=" * 60)

    # Test 1: Calculate storage cost
    print("\n1. Testing calculate_storage_cost()...")
    fees = [ServerFees(server_id=f"RAIDA{i}", cost_per_mb=0.001) for i in range(5)]
    err, calc = calculate_storage_cost(1024 * 1024, 5, 8, fees)  # 1 MB, 5 servers, 8 weeks
    assert err == ErrorCode.SUCCESS
    print(f"   Total cost for 1 MB / 8 weeks: {calc.total_cost:.6f}")
    print(f"   Duration code: {calc.duration_code}")
    print("   SUCCESS")

    # Test 2: Empty data
    print("\n2. Testing with zero size...")
    err, calc = calculate_storage_cost(0, 5, 8, fees)
    assert err == ErrorCode.SUCCESS
    assert calc.total_cost == sum(8 * f.cost_per_week for f in fees)  # Only weekly cost
    print(f"   Cost for 0 bytes: {calc.total_cost:.6f}")
    print("   SUCCESS")

    # Test 3: weeks_to_duration_code
    print("\n3. Testing weeks_to_duration_code()...")
    assert weeks_to_duration_code(0) == StorageDuration.ONE_DAY
    assert weeks_to_duration_code(1) == StorageDuration.ONE_WEEK
    assert weeks_to_duration_code(4) == StorageDuration.ONE_MONTH
    assert weeks_to_duration_code(8) == StorageDuration.THREE_MONTHS
    assert weeks_to_duration_code(20) == StorageDuration.SIX_MONTHS
    assert weeks_to_duration_code(52) == StorageDuration.ONE_YEAR
    assert weeks_to_duration_code(100) == StorageDuration.PERMANENT
    print("   All duration codes correct")
    print("   SUCCESS")

    # Test 4: Recipient fees (stub)
    print("\n4. Testing calculate_recipient_fees()...")
    err, fees_amount = calculate_recipient_fees(5)
    assert err == ErrorCode.SUCCESS
    assert fees_amount == 0.0
    print(f"   Recipient fees for 5 recipients: {fees_amount}")
    print("   SUCCESS (stub returns 0)")

    # Test 5: Request locker code
    print("\n5. Testing request_locker_code()...")
    err, locker = request_locker_code(0.01)
    assert err == ErrorCode.SUCCESS
    assert len(locker) == 8
    print(f"   Locker code: {locker.hex()}")
    print("   SUCCESS")

    # Test 6: Invalid inputs
    print("\n6. Testing invalid inputs...")
    err, _ = calculate_storage_cost(-100, 5, 8, fees)
    assert err == ErrorCode.ERR_INVALID_PARAM
    err, _ = calculate_storage_cost(100, 1, 8, fees)  # Need at least 2 servers
    assert err == ErrorCode.ERR_INVALID_PARAM
    print("   Invalid inputs correctly rejected")
    print("   SUCCESS")

    print("\n" + "=" * 60)
    print("All payment tests passed!")
    print("=" * 60)
