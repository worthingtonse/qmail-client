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
) -> Tuple[ErrorCode, bytes]:
    """
    Async implementation of locker creation with iterative coin breaking.
    FIXED: 
      1. Uses top-level imports for CoinForPut/PutResult (from locker_put).
      2. Corrected put_to_locker call (2 args only) to avoid type errors.
      3. Includes Dust Threshold and Loop limits for stability.
    """
    import math
    import secrets
    import string
    import asyncio 
    
    # Increased loops to handle deep recursive breaks (1.0 -> 0.0001)
    MAX_LOOPS = 20
    
    # Threshold for "Close Enough". 
    # If we are overpaying by less than 0.0001 (DN -4), just pay it.
    DUST_THRESHOLD = 0.0001
    
    try:
        for _ in range(MAX_LOOPS):
            # 1. Get coins
            coins = get_coins_by_value(wallet_path, amount, identity_sn=identity_sn)
            
            if not coins:
                log_error(logger_handle, PAYMENT_CONTEXT, 
                          f"Insufficient funds for amount {amount}")
                return ErrorCode.ERR_NOT_FOUND, b''
            
            total_value_selected = sum(parse_denomination_code(c.denomination) for c in coins)
            diff = total_value_selected - amount

            # 2. Check for Match OR Acceptable Overpayment
            # We accept if we have enough AND the excess is just dust.
            if diff >= -0.00000001 and diff < DUST_THRESHOLD:
                
                log_info(logger_handle, PAYMENT_CONTEXT, 
                         f"Locking {total_value_selected:.8f} for payment of {amount:.8f} (Overpayment: {diff:.8f})")

                # --- MATCH FOUND: LOCK IT ---
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
                
                # --- FIX IS HERE ---
                # 1. No invalid inner imports.
                # 2. Pass ONLY coins and keys. 
                #    The previous error "LoggerHandle... not integer" implies the 3rd arg 
                #    is a timeout integer, not a logger or config object.
                put_result, _ = await put_to_locker(coins_for_put, locker_keys)
                
                if put_result != PutResult.SUCCESS:
                    log_error(logger_handle, PAYMENT_CONTEXT, f"Locker PUT failed: {put_result}")
                    return ErrorCode.ERR_INTERNAL, b''

                # Cleanup
                for c in coins:
                    try:
                        if os.path.exists(c.file_path):
                            os.remove(c.file_path)
                    except: pass

                locker_code_bytes = locker_code_str.encode('ascii').ljust(8, b'\x00')
                return ErrorCode.SUCCESS, locker_code_bytes

            # 3. SIGNIFICANT OVERPAYMENT: Must Break a Coin
            elif diff >= DUST_THRESHOLD:
                # Sort ASCENDING (Smallest first)
                coins.sort(key=lambda x: parse_denomination_code(x.denomination), reverse=False)
                
                coin_to_break = coins[0]
                
                log_info(logger_handle, PAYMENT_CONTEXT,
                         f"Have {total_value_selected:.8f}, need {amount:.8f}. "
                         f"Breaking smallest available coin: SN {coin_to_break.serial_number} (Val: {parse_denomination_code(coin_to_break.denomination)})")
                
                # Execute Break (Command 90)
                break_result = await break_coin(coin_to_break, wallet_path, config, logger_handle)
                
                # Check success (Handle object vs list result)
                success = False
                if hasattr(break_result, 'success'): success = break_result.success
                elif isinstance(break_result, list) and break_result: success = True
                
                if not success:
                    log_error(logger_handle, PAYMENT_CONTEXT, "Coin break failed during payment")
                    return ErrorCode.ERR_INTERNAL, b''
                
                # Wait for FS to sync
                await asyncio.sleep(0.5)
                
                # LOOP RESTARTS -> get_coins_by_value will be called again
                continue
                
        # If loop finishes without returning
        log_error(logger_handle, PAYMENT_CONTEXT, "Unable to make exact change after max attempts")
        return ErrorCode.ERR_INTERNAL, b''

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, f"Async locker creation crashed: {e}")
        return ErrorCode.ERR_INTERNAL, b''
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
    
    REUSES _create_locker_async() for each server's payment.
    
    Flow:
    1. Fetch ALL available servers from DATABASE
    2. Calculate amount per server based on its fees
    3. Call _create_locker_async() for each server sequentially
    4. Return list of ServerPayment with locker codes
    """
    CONTEXT = "MultiPayment"
    
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
    
    # --- 2. Calculate amount for each server based on ITS fees ---
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
    
    # --- 3. Create locker for each server using existing _create_locker_async ---
    payments = []
    
    for srv, amount in server_amounts:
        server_id = srv.get('server_id', '')
        server_index = srv.get('server_index', 0)
        ip_address = srv.get('ip_address', '')
        port = srv.get('port', 0)
        
        if amount <= 0.00000001:
            # Zero cost - generate placeholder locker code
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
        
        # Use existing _create_locker_async for this server's payment
        log_info(logger_handle, CONTEXT,
                 f"Creating locker for {server_id}: {amount:.8f} CC")
        
        err, locker_code = await _create_locker_async(
            amount=amount,
            wallet_path=wallet_path,
            logger_handle=logger_handle,
            config=config,
            identity_sn=identity_sn
        )
        
        if err != ErrorCode.SUCCESS or not locker_code:
            log_error(logger_handle, CONTEXT,
                      f"Failed to create locker for {server_id}: {err}")
            # Return partial list - caller can decide to refund
            return err, payments
        
        # Extract string form from bytes
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
    
    log_info(logger_handle, CONTEXT,
             f"All {len(payments)} server payments prepared successfully")
    
    return ErrorCode.SUCCESS, payments


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
