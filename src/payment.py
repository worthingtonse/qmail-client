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

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

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
    """Fee structure for a single server."""
    server_id: str
    cost_per_mb: float = DEFAULT_COST_PER_MB
    cost_per_week: float = DEFAULT_COST_PER_WEEK
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


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def calculate_storage_cost(
    total_file_size: int,
    num_servers: int,
    storage_weeks: int,
    server_fees: List[ServerFees],
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, PaymentCalculation]:
    """
    Calculate the total storage cost for uploading data.

    The cost is calculated per server based on:
    - Data size stored on each server (total / num_data_servers)
    - Storage duration
    - Server-specific fees

    Args:
        total_file_size: Total size of data in bytes (before striping)
        num_servers: Number of servers to distribute data across (default 5)
        storage_weeks: Number of weeks to store data
        server_fees: List of ServerFees for each server
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, PaymentCalculation)

    Example:
        fees = [ServerFees(server_id=f"RAIDA{i}") for i in range(5)]
        err, calc = calculate_storage_cost(1024 * 1024, 5, 8, fees)
        print(f"Total cost: {calc.total_cost}")
    """
    result = PaymentCalculation()

    # Validate inputs
    if total_file_size < 0:
        log_error(logger_handle, PAYMENT_CONTEXT, "calculate_storage_cost failed",
                  "total_file_size cannot be negative")
        result.error_code = ErrorCode.ERR_INVALID_PARAM
        result.error_message = "File size cannot be negative"
        return ErrorCode.ERR_INVALID_PARAM, result

    if num_servers < 2:
        log_error(logger_handle, PAYMENT_CONTEXT, "calculate_storage_cost failed",
                  f"num_servers must be at least 2, got {num_servers}")
        result.error_code = ErrorCode.ERR_INVALID_PARAM
        result.error_message = "Must have at least 2 servers"
        return ErrorCode.ERR_INVALID_PARAM, result

    if not server_fees:
        log_warning(logger_handle, PAYMENT_CONTEXT,
                    "No server fees provided, using defaults")
        server_fees = [ServerFees(server_id=f"default_{i}") for i in range(num_servers)]

    # Convert weeks to duration code
    result.duration_code = weeks_to_duration_code(storage_weeks)

    # Calculate size per server (data is distributed across all servers)
    # Each server stores total_size / num_data_servers bytes
    # Plus parity server stores same amount
    num_data_servers = num_servers - 1
    size_per_server_bytes = (total_file_size + num_data_servers - 1) // num_data_servers
    size_per_server_mb = size_per_server_bytes / (1024 * 1024)

    # Calculate cost for each server
    total_cost = 0.0
    breakdown = {}

    for i, fee in enumerate(server_fees[:num_servers]):
        # Cost = size_mb * cost_per_mb + weeks * cost_per_week
        server_cost = (size_per_server_mb * fee.cost_per_mb) + \
                     (storage_weeks * fee.cost_per_week)

        breakdown[fee.server_id] = server_cost
        total_cost += server_cost

        log_debug(logger_handle, PAYMENT_CONTEXT,
                  f"Server {fee.server_id}: {size_per_server_mb:.3f} MB * "
                  f"{fee.cost_per_mb} + {storage_weeks} weeks * {fee.cost_per_week} = "
                  f"{server_cost:.6f}")

    result.storage_cost = total_cost
    result.total_cost = total_cost
    result.server_breakdown = breakdown
    result.error_code = ErrorCode.SUCCESS

    log_info(logger_handle, PAYMENT_CONTEXT,
             f"Calculated storage cost: {total_cost:.6f} for {total_file_size} bytes "
             f"across {num_servers} servers for {storage_weeks} weeks")

    return ErrorCode.SUCCESS, result


def calculate_recipient_fees(
    recipient_count: int,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, float]:
    """
    Calculate fees for recipients (stub - returns 0).

    In the future, recipients may charge fees to receive emails.
    Currently this is not implemented and returns 0.

    Args:
        recipient_count: Number of recipients
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, total recipient fees)
    """
    # Stub: No recipient fees currently
    log_debug(logger_handle, PAYMENT_CONTEXT,
              f"Recipient fees for {recipient_count} recipients: 0.0 (not implemented)")
    return ErrorCode.SUCCESS, 0.0


def get_server_fees(
    db_handle: object,
    server_ids: Optional[List[str]] = None,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, List[ServerFees]]:
    """
    Get fee structures for servers from the database.

    Args:
        db_handle: Database handle
        server_ids: Optional list of specific server IDs to query
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, list of ServerFees)
    """
    try:
        # Try to import database module
        try:
            from . import database
        except ImportError:
            import database

        # Get servers from database
        err, servers = database.get_all_servers(db_handle, available_only=True)

        if err != 0:  # Database error
            log_error(logger_handle, PAYMENT_CONTEXT, "get_server_fees failed",
                      "Database query failed")
            return ErrorCode.ERR_INTERNAL, []

        # Convert to ServerFees objects
        fees = []
        for server in servers:
            server_id = server.get('server_id', '')

            # Filter by server_ids if provided
            if server_ids and server_id not in server_ids:
                continue

            # Parse cost_per_mb (stored as string in database)
            cost_per_mb = DEFAULT_COST_PER_MB
            if server.get('cost_per_mb'):
                try:
                    cost_per_mb = float(server['cost_per_mb'])
                except (ValueError, TypeError):
                    pass

            # Parse cost_per_week (if available)
            cost_per_week = DEFAULT_COST_PER_WEEK
            if server.get('cost_per_week'):
                try:
                    cost_per_week = float(server['cost_per_week'])
                except (ValueError, TypeError):
                    pass

            fees.append(ServerFees(
                server_id=server_id,
                cost_per_mb=cost_per_mb,
                cost_per_week=cost_per_week,
                is_available=server.get('is_available', True)
            ))

        log_debug(logger_handle, PAYMENT_CONTEXT,
                  f"Retrieved fees for {len(fees)} servers")

        return ErrorCode.SUCCESS, fees

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, "get_server_fees failed", str(e))
        return ErrorCode.ERR_INTERNAL, []


def request_locker_code(
    amount: float,
    db_handle: Optional[object] = None,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, bytes]:
    """
    Request a locker code from cloudcoin for the specified amount.

    The locker code is used to pay for storage on QMail servers.
    The servers validate the locker code and deduct the appropriate amount.

    Args:
        amount: Amount in CloudCoin units
        db_handle: Optional database handle for cloudcoin integration
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, 8-byte locker code)
        - SUCCESS and locker code on success
        - ERR_NOT_FOUND if insufficient funds
        - ERR_INTERNAL on other errors
    """
    try:
        # Try to import cloudcoin module
        try:
            from . import cloudcoin
            has_cloudcoin = True
        except ImportError:
            try:
                import cloudcoin
                has_cloudcoin = True
            except ImportError:
                has_cloudcoin = False

        if has_cloudcoin and hasattr(cloudcoin, 'generate_locker_code'):
            # Use real cloudcoin module
            err, locker_code = cloudcoin.generate_locker_code(amount, db_handle)
            if err != 0:
                log_error(logger_handle, PAYMENT_CONTEXT, "request_locker_code failed",
                          "CloudCoin locker code generation failed")
                return ErrorCode.ERR_NOT_FOUND, b''
            return ErrorCode.SUCCESS, locker_code
        else:
            # Fallback: generate a dummy locker code for testing
            log_warning(logger_handle, PAYMENT_CONTEXT,
                        "CloudCoin module not available, generating test locker code")
            import os
            test_locker = os.urandom(8)
            return ErrorCode.SUCCESS, test_locker

    except Exception as e:
        log_error(logger_handle, PAYMENT_CONTEXT, "request_locker_code failed", str(e))
        return ErrorCode.ERR_INTERNAL, b''


def calculate_total_payment(
    file_sizes: List[int],
    storage_weeks: int,
    recipient_count: int,
    db_handle: object,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, PaymentCalculation]:
    """
    Calculate total payment for sending an email with attachments.

    This is a convenience function that:
    1. Gets server fees from database
    2. Calculates storage cost for all files
    3. Adds recipient fees (currently 0)

    Args:
        file_sizes: List of file sizes in bytes (email body + attachments)
        storage_weeks: Number of weeks to store
        recipient_count: Number of recipients
        db_handle: Database handle
        logger_handle: Optional logger handle

    Returns:
        Tuple of (ErrorCode, PaymentCalculation)

    Example:
        err, calc = calculate_total_payment([1024, 2048, 5000], 8, 3, db)
        if err == ErrorCode.SUCCESS:
            print(f"Total: {calc.total_cost}")
    """
    result = PaymentCalculation()

    # Get server fees
    err, server_fees = get_server_fees(db_handle, logger_handle=logger_handle)
    if err != ErrorCode.SUCCESS:
        log_warning(logger_handle, PAYMENT_CONTEXT,
                    "Could not get server fees, using defaults")
        server_fees = [ServerFees(server_id=f"default_{i}") for i in range(NUM_SERVERS)]

    # Ensure we have enough servers
    while len(server_fees) < NUM_SERVERS:
        server_fees.append(ServerFees(server_id=f"default_{len(server_fees)}"))

    # Calculate total size of all files
    total_size = sum(file_sizes) if file_sizes else 0

    # Calculate storage cost
    err, storage_calc = calculate_storage_cost(
        total_size, NUM_SERVERS, storage_weeks, server_fees, logger_handle
    )
    if err != ErrorCode.SUCCESS:
        return err, storage_calc

    # Calculate recipient fees (stub)
    err, recipient_fees = calculate_recipient_fees(recipient_count, logger_handle)
    if err != ErrorCode.SUCCESS:
        result.error_code = err
        result.error_message = "Failed to calculate recipient fees"
        return err, result

    # Combine costs
    result.storage_cost = storage_calc.storage_cost
    result.recipient_fees = recipient_fees
    result.total_cost = storage_calc.storage_cost + recipient_fees
    result.server_breakdown = storage_calc.server_breakdown
    result.duration_code = storage_calc.duration_code
    result.error_code = ErrorCode.SUCCESS

    log_info(logger_handle, PAYMENT_CONTEXT,
             f"Total payment: {result.total_cost:.6f} "
             f"(storage={result.storage_cost:.6f}, recipients={result.recipient_fees:.6f})")

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
