"""
coin_break.py - CloudCoin Break (Make Change) Module

This module implements the functionality to break CloudCoins into smaller
denominations using RAIDA Command 90 (Make Change).

Breaking one coin produces 10 coins of the next lower denomination:
  1000 -> 100 x 10
  100  -> 10 x 10
  10   -> 1 x 10
  1    -> 0.1 x 10

Author: Claude Opus 4.5
Date: 2025-12-22
Version: 1.0.0

Usage:
    from coin_break import break_coin, BreakResult

    # Break a 100cc coin into ten 10cc coins
    result = await break_coin(coin, wallet_path)
    if result.success:
        print(f"Created {len(result.new_coins)} new coins")
"""

import asyncio
import os
import secrets
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Optional, Dict

# Import project modules
try:
    from .protocol import (
        build_complete_make_change_request,
        ProtocolErrorCode,
        CMD_GROUP_CHANGE,
        CMD_MAKE_CHANGE,
    )
    from .network_async import (
        create_async_connection,
        close_async_connection,
        send_raw_request_async,
        NetworkConfig,
        NetworkErrorCode,
    )
    from .cloudcoin import (
        LockerCoin,
        write_coin_file,
        generate_coin_filename,
        CloudCoinErrorCode,
        CC_RAIDA_COUNT,
        CC_AN_LENGTH,
    )
    from .logger import log_error, log_debug, log_info, log_warning
except ImportError:
    # Fallback for standalone testing
    from protocol import (
        build_complete_make_change_request,
        ProtocolErrorCode,
        CMD_GROUP_CHANGE,
        CMD_MAKE_CHANGE,
    )
    from network_async import (
        create_async_connection,
        close_async_connection,
        send_raw_request_async,
        NetworkConfig,
        NetworkErrorCode,
    )
    from cloudcoin import (
        LockerCoin,
        write_coin_file,
        generate_coin_filename,
        CloudCoinErrorCode,
        CC_RAIDA_COUNT,
        CC_AN_LENGTH,
    )
    def log_error(handle, ctx, msg, reason=None):
        print(f"[ERROR] [{ctx}] {msg}" + (f" | {reason}" if reason else ""))
    def log_debug(handle, ctx, msg): print(f"[DEBUG] [{ctx}] {msg}")
    def log_info(handle, ctx, msg): print(f"[INFO] [{ctx}] {msg}")
    def log_warning(handle, ctx, msg): print(f"[WARNING] [{ctx}] {msg}")


# ============================================================================
# CONSTANTS
# ============================================================================

BREAK_CONTEXT = "CoinBreak"

# Consensus requirement
MIN_CONSENSUS = 13  # Minimum RAIDAs needed for success

# Serial number range for new coins
MIN_STARTING_SN = 100_000
MAX_STARTING_SN = 16_777_215

# Denomination encoding (value -> code)
DENOM_TO_CODE = {
    0.1: -1,
    1: 0,
    10: 1,
    100: 2,
    1000: 3,
}

# Denomination decoding (code -> value)
CODE_TO_DENOM = {
    -1: 0.1,
    0: 1,
    1: 10,
    2: 100,
    3: 1000,
}

# Response status codes
STATUS_SUCCESS = 250
ERROR_SN_NOT_AVAILABLE = 215

# Network timeout (ms)
DEFAULT_TIMEOUT_MS = 10000


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CoinToBreak:
    """
    Represents a CloudCoin to be broken into smaller denominations.
    """
    serial_number: int
    denomination: int  # Signed int8 code (-1, 0, 1, 2, 3)
    ans: List[bytes] = field(default_factory=lambda: [bytes(16)] * CC_RAIDA_COUNT)
    file_path: str = ""  # Original file path

    def get_value(self) -> float:
        """Get the coin value from denomination code."""
        return CODE_TO_DENOM.get(self.denomination, 0)


@dataclass
class BreakResult:
    """Result of a break operation."""
    success: bool                        # True if >= 13/25 consensus
    original_coin: Optional[CoinToBreak] # The coin that was broken
    new_coins: List[LockerCoin]          # 10 new coins (empty if failed)
    raida_statuses: List[int]            # Status from each RAIDA (25 elements)
    pass_count: int                      # Number of RAIDAs that passed
    error_message: str                   # Error description if failed


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _generate_starting_sn() -> int:
    """
    Generate a random starting serial number for new coins.

    Returns:
        Random integer between 100,000 and 16,777,215
    """
    return secrets.randbelow(MAX_STARTING_SN - MIN_STARTING_SN + 1) + MIN_STARTING_SN


def _generate_pans() -> List[List[bytes]]:
    """
    Generate unique PANs for all new coins across all RAIDAs.

    Returns:
        2D list: pans[raida_id][coin_index] = 16-byte PAN
        Total: 25 RAIDAs × 10 coins = 250 unique PANs
    """
    return [[secrets.token_bytes(16) for _ in range(10)] for _ in range(CC_RAIDA_COUNT)]


def _read_coin_file(file_path: str, logger_handle=None) -> Tuple[CloudCoinErrorCode, Optional[CoinToBreak]]:
    """
    Read a CloudCoin .bin file and extract all data needed for breaking.

    Args:
        file_path: Path to .bin file
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, CoinToBreak or None)
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 439:  # Minimum size: 32 header + 7 coin header + 400 ANs
            log_error(logger_handle, BREAK_CONTEXT,
                      f"File too small: {len(data)} bytes", file_path)
            return CloudCoinErrorCode.ERR_IO_ERROR, None

        # Read denomination at byte 33 (32 header + 1 split + 1 denom)
        denomination = struct.unpack('b', data[33:34])[0]

        # Read serial number at bytes 34-37 (big-endian)
        serial_number = struct.unpack('>I', data[34:38])[0]

        # Read 25 ANs starting at byte 39 (32 header + 7 coin header)
        ans = []
        offset = 39
        for i in range(CC_RAIDA_COUNT):
            an = data[offset:offset + CC_AN_LENGTH]
            ans.append(an)
            offset += CC_AN_LENGTH

        coin = CoinToBreak(
            serial_number=serial_number,
            denomination=denomination,
            ans=ans,
            file_path=file_path
        )

        log_debug(logger_handle, BREAK_CONTEXT,
                  f"Read coin: SN={serial_number}, DN={denomination}")

        return CloudCoinErrorCode.SUCCESS, coin

    except IOError as e:
        log_error(logger_handle, BREAK_CONTEXT,
                  f"Failed to read coin file", str(e))
        return CloudCoinErrorCode.ERR_IO_ERROR, None
    except Exception as e:
        log_error(logger_handle, BREAK_CONTEXT,
                  f"Unexpected error reading coin", str(e))
        return CloudCoinErrorCode.ERR_IO_ERROR, None


def _find_coin_to_break(
    wallet_path: str,
    target_denomination: int,
    logger_handle=None
) -> Tuple[CloudCoinErrorCode, Optional[CoinToBreak]]:
    """
    Find a coin to break from Bank or Fracked folder.

    Args:
        wallet_path: Path to wallet (e.g., "Data/Wallets/Default")
        target_denomination: The denomination code to find (-1, 0, 1, 2, 3)
        logger_handle: Optional logger

    Returns:
        Tuple of (error_code, CoinToBreak or None)

    Search order:
        1. Bank folder (prefer authentic coins)
        2. Fracked folder (if Bank has none)
    """
    search_folders = ["Bank", "Fracked"]

    for folder_name in search_folders:
        folder_path = os.path.join(wallet_path, folder_name)
        if not os.path.isdir(folder_path):
            continue

        try:
            for entry in os.scandir(folder_path):
                if not entry.is_file() or not entry.name.endswith('.bin'):
                    continue

                # Quick check: read denomination from file
                try:
                    with open(entry.path, 'rb') as f:
                        f.seek(33)
                        denom_byte = f.read(1)
                        if not denom_byte:
                            continue
                        file_denom = struct.unpack('b', denom_byte)[0]

                    if file_denom == target_denomination:
                        # Found matching coin, read full data
                        err, coin = _read_coin_file(entry.path, logger_handle)
                        if err == CloudCoinErrorCode.SUCCESS and coin:
                            log_info(logger_handle, BREAK_CONTEXT,
                                     f"Found coin in {folder_name}: SN={coin.serial_number}")
                            return CloudCoinErrorCode.SUCCESS, coin

                except IOError:
                    continue

        except OSError as e:
            log_warning(logger_handle, BREAK_CONTEXT,
                        f"Error scanning {folder_name}: {e}")
            continue

    log_warning(logger_handle, BREAK_CONTEXT,
                f"No coin found with denomination code {target_denomination}")
    return CloudCoinErrorCode.ERR_FILE_NOT_FOUND, None


# ============================================================================
# RAIDA COMMUNICATION
# ============================================================================

async def _make_change_single_raida(
    raida_id: int,
    coin: CoinToBreak,
    starting_sn: int,
    pans: List[bytes],
    config: Optional[NetworkConfig] = None,
    logger_handle=None
) -> Tuple[int, int, str]:
    """
    Execute Make Change command on one RAIDA.

    Args:
        raida_id: RAIDA server ID (0-24)
        coin: The coin being broken
        starting_sn: Starting serial number for new coins
        pans: List of 10 PANs (16 bytes each) for this RAIDA
        config: Network configuration
        logger_handle: Optional logger

    Returns:
        Tuple of (raida_id, status_code, error_message)
        - status_code 250 = success
        - status_code 215 = SN not available
        - status_code 0 = network/other error
    """
    conn = None
    try:
        # Build complete request
        err, request, challenge, nonce = build_complete_make_change_request(
            raida_id=raida_id,
            original_dn=coin.denomination,
            original_sn=coin.serial_number,
            original_an=coin.ans[raida_id],
            starting_sn=starting_sn,
            pans=pans,
            logger_handle=logger_handle
        )

        if err != ProtocolErrorCode.SUCCESS:
            return (raida_id, 0, f"Failed to build request: {err}")

        # Create connection
        conn = await create_async_connection(raida_id, config, logger_handle)
        if conn is None:
            return (raida_id, 0, "Failed to connect")

        # Send request
        err_code, response_header, response_body = await send_raw_request_async(
            conn, request, DEFAULT_TIMEOUT_MS, config, logger_handle
        )

        if err_code != NetworkErrorCode.SUCCESS:
            return (raida_id, 0, f"Network error: {err_code}")

        if response_header is None:
            return (raida_id, 0, "No response header")

        # Check status code from response header
        status = response_header.status if hasattr(response_header, 'status') else 0

        if status == STATUS_SUCCESS:
            log_debug(logger_handle, BREAK_CONTEXT,
                      f"RAIDA {raida_id}: SUCCESS")
            return (raida_id, STATUS_SUCCESS, "")
        elif status == ERROR_SN_NOT_AVAILABLE:
            log_warning(logger_handle, BREAK_CONTEXT,
                        f"RAIDA {raida_id}: SN not available")
            return (raida_id, ERROR_SN_NOT_AVAILABLE, "SN not available")
        else:
            log_warning(logger_handle, BREAK_CONTEXT,
                        f"RAIDA {raida_id}: Status {status}")
            return (raida_id, status, f"Status {status}")

    except asyncio.TimeoutError:
        log_warning(logger_handle, BREAK_CONTEXT,
                    f"RAIDA {raida_id}: Timeout")
        return (raida_id, 0, "Timeout")
    except Exception as e:
        log_error(logger_handle, BREAK_CONTEXT,
                  f"RAIDA {raida_id}: Exception", str(e))
        return (raida_id, 0, str(e))
    finally:
        if conn is not None:
            try:
                await close_async_connection(conn)
            except Exception:
                pass


async def _make_change_all_raidas(
    coin: CoinToBreak,
    starting_sn: int,
    pans: List[List[bytes]],
    config: Optional[NetworkConfig] = None,
    logger_handle=None
) -> List[Tuple[int, int, str]]:
    """
    Execute Make Change on all 25 RAIDAs in parallel.

    Args:
        coin: The coin being broken
        starting_sn: Starting serial number for new coins
        pans: 2D list pans[raida_id][coin_index] = 16-byte PAN
        config: Network configuration
        logger_handle: Optional logger

    Returns:
        List of (raida_id, status_code, error_message) for all 25 RAIDAs
    """
    tasks = []
    for raida_id in range(CC_RAIDA_COUNT):
        task = _make_change_single_raida(
            raida_id, coin, starting_sn, pans[raida_id], config, logger_handle
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Convert exceptions to error results
    final_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            final_results.append((i, 0, str(result)))
        else:
            final_results.append(result)

    return final_results


# ============================================================================
# COIN CREATION AND FILE OPERATIONS
# ============================================================================

def _create_new_coins(
    starting_sn: int,
    pans: List[List[bytes]],
    raida_results: List[Tuple[int, int, str]],
    new_denomination: int,
    logger_handle=None
) -> List[LockerCoin]:
    """
    Create LockerCoin objects for the 10 new coins after successful break.

    Args:
        starting_sn: The starting serial number (coins are SSN to SSN+9)
        pans: The PANs sent to each RAIDA (become ANs for successful RAIDAs)
        raida_results: Results from each RAIDA (raida_id, status, error)
        new_denomination: Denomination code of new coins (original - 1)
        logger_handle: Optional logger

    Returns:
        List of 10 LockerCoin objects with proper ANs and POWN strings
    """
    # Build status lookup
    status_map = {r[0]: r[1] for r in raida_results}

    new_coins = []
    for coin_idx in range(10):
        sn = starting_sn + coin_idx

        # Build ANs and POWN string for this coin
        ans = []
        pown_chars = []

        for raida_id in range(CC_RAIDA_COUNT):
            status = status_map.get(raida_id, 0)

            if status == STATUS_SUCCESS:
                # Use the PAN we sent as the AN
                ans.append(pans[raida_id][coin_idx])
                pown_chars.append('p')
            else:
                # Failed - use zeros for AN
                ans.append(bytes(16))
                if status == 0:
                    pown_chars.append('n')  # No response
                else:
                    pown_chars.append('f')  # Failed

        pown_string = ''.join(pown_chars)

        coin = LockerCoin(
            serial_number=sn,
            denomination=new_denomination,
            ans=ans,
            pown_string=pown_string
        )
        new_coins.append(coin)

        log_debug(logger_handle, BREAK_CONTEXT,
                  f"Created new coin: SN={sn}, DN={new_denomination}, POWN={pown_string[:10]}...")

    return new_coins


def _save_new_coins_to_fracked(
    coins: List[LockerCoin],
    wallet_path: str,
    logger_handle=None
) -> CloudCoinErrorCode:
    """
    Save the new coins to the Fracked folder for grading.

    Args:
        coins: List of LockerCoin objects to save
        wallet_path: Path to wallet

    Returns:
        CloudCoinErrorCode
    """
    fracked_path = os.path.join(wallet_path, "Fracked")

    # Ensure Fracked folder exists
    Path(fracked_path).mkdir(parents=True, exist_ok=True)

    saved_count = 0
    for coin in coins:
        filename = generate_coin_filename(
            coin.denomination,
            coin.serial_number,
            coin.pown_string
        )
        filepath = os.path.join(fracked_path, filename)

        err = write_coin_file(filepath, coin, logger_handle)
        if err == CloudCoinErrorCode.SUCCESS:
            saved_count += 1
        else:
            log_error(logger_handle, BREAK_CONTEXT,
                      f"Failed to save coin SN={coin.serial_number}")

    log_info(logger_handle, BREAK_CONTEXT,
             f"Saved {saved_count}/{len(coins)} new coins to Fracked/")

    return CloudCoinErrorCode.SUCCESS if saved_count == len(coins) else CloudCoinErrorCode.ERR_IO_ERROR


def _move_original_to_change(
    coin: CoinToBreak,
    wallet_path: str,
    logger_handle=None
) -> CloudCoinErrorCode:
    """
    Move the original coin file to Change folder after successful break.

    Args:
        coin: The original coin that was broken
        wallet_path: Path to wallet

    Returns:
        CloudCoinErrorCode
    """
    if not coin.file_path or not os.path.exists(coin.file_path):
        log_warning(logger_handle, BREAK_CONTEXT,
                    "Original coin file path not found")
        return CloudCoinErrorCode.ERR_FILE_NOT_FOUND

    # Ensure Change folder exists
    change_path = os.path.join(wallet_path, "Change")
    Path(change_path).mkdir(parents=True, exist_ok=True)

    # Move file
    dest_path = os.path.join(change_path, os.path.basename(coin.file_path))

    try:
        shutil.move(coin.file_path, dest_path)
        log_info(logger_handle, BREAK_CONTEXT,
                 f"Moved original coin to Change/: SN={coin.serial_number}")
        return CloudCoinErrorCode.SUCCESS
    except IOError as e:
        log_error(logger_handle, BREAK_CONTEXT,
                  f"Failed to move coin to Change/", str(e))
        return CloudCoinErrorCode.ERR_IO_ERROR


# ============================================================================
# MAIN FUNCTION
# ============================================================================

async def break_coin(
    coin: CoinToBreak,
    wallet_path: str,
    config: Optional[NetworkConfig] = None,
    logger_handle=None
) -> BreakResult:
    """
    Break a single coin into 10 smaller denomination coins.

    Uses Command 90 (Make Change) - a single-step process where the client
    generates sequential serial numbers for the new coins.

    Args:
        coin: The CoinToBreak to break (must have denomination >= 0, i.e. value >= 1)
        wallet_path: Path to wallet (e.g., "Data/Wallets/Default")
        config: Optional network configuration
        logger_handle: Optional logger

    Returns:
        BreakResult with success status and new coins

    Example:
        coin = CoinToBreak(serial_number=12345, denomination=2, ans=[...])
        result = await break_coin(coin, "Data/Wallets/Default")
        if result.success:
            print(f"Created {len(result.new_coins)} coins worth {result.new_coins[0].get_value()} each")
    """
    log_info(logger_handle, BREAK_CONTEXT,
             f"Breaking coin: SN={coin.serial_number}, DN={coin.denomination}")

    # Validate coin can be broken
    if coin.denomination < 0:  # -1 = 0.1, can't break further
        return BreakResult(
            success=False,
            original_coin=coin,
            new_coins=[],
            raida_statuses=[0] * CC_RAIDA_COUNT,
            pass_count=0,
            error_message="Cannot break fractional coins (denomination < 1)"
        )

    # Validate ANs
    if not coin.ans or len(coin.ans) != CC_RAIDA_COUNT:
        return BreakResult(
            success=False,
            original_coin=coin,
            new_coins=[],
            raida_statuses=[0] * CC_RAIDA_COUNT,
            pass_count=0,
            error_message="Coin has invalid ANs"
        )

    # Generate starting serial number
    starting_sn = _generate_starting_sn()
    log_debug(logger_handle, BREAK_CONTEXT,
              f"Generated starting SN: {starting_sn}")

    # Generate PANs for all new coins across all RAIDAs
    pans = _generate_pans()
    log_debug(logger_handle, BREAK_CONTEXT,
              f"Generated {len(pans)}x{len(pans[0])} PANs")

    # Execute Make Change on all RAIDAs
    results = await _make_change_all_raidas(coin, starting_sn, pans, config, logger_handle)

    # Count successful responses
    raida_statuses = [0] * CC_RAIDA_COUNT
    pass_count = 0
    for raida_id, status, error in results:
        raida_statuses[raida_id] = status
        if status == STATUS_SUCCESS:
            pass_count += 1

    log_info(logger_handle, BREAK_CONTEXT,
             f"Make Change results: {pass_count}/{CC_RAIDA_COUNT} passed")

    # Check consensus
    if pass_count < MIN_CONSENSUS:
        return BreakResult(
            success=False,
            original_coin=coin,
            new_coins=[],
            raida_statuses=raida_statuses,
            pass_count=pass_count,
            error_message=f"Break failed - only {pass_count}/{MIN_CONSENSUS} RAIDAs passed"
        )

    # Create new coins
    new_denomination = coin.denomination - 1  # One step smaller
    new_coins = _create_new_coins(starting_sn, pans, results, new_denomination, logger_handle)

    # Save new coins to Fracked folder
    err = _save_new_coins_to_fracked(new_coins, wallet_path, logger_handle)
    if err != CloudCoinErrorCode.SUCCESS:
        log_warning(logger_handle, BREAK_CONTEXT,
                    "Some coins may not have been saved")

    # Move original coin to Change folder
    err = _move_original_to_change(coin, wallet_path, logger_handle)
    if err != CloudCoinErrorCode.SUCCESS:
        log_warning(logger_handle, BREAK_CONTEXT,
                    "Original coin may not have been moved")

    log_info(logger_handle, BREAK_CONTEXT,
             f"Break successful: Created {len(new_coins)} coins")

    return BreakResult(
        success=True,
        original_coin=coin,
        new_coins=new_coins,
        raida_statuses=raida_statuses,
        pass_count=pass_count,
        error_message=""
    )


async def break_coin_by_denomination(
    wallet_path: str,
    target_denomination: int,
    config: Optional[NetworkConfig] = None,
    logger_handle=None
) -> BreakResult:
    """
    Find and break a coin of the specified denomination.

    This is a convenience function that finds a suitable coin in the wallet
    and breaks it.

    Args:
        wallet_path: Path to wallet
        target_denomination: Denomination code to break (0=1cc, 1=10cc, 2=100cc, 3=1000cc)
        config: Network configuration
        logger_handle: Optional logger

    Returns:
        BreakResult

    Example:
        # Break a 100cc coin into ten 10cc coins
        result = await break_coin_by_denomination("Data/Wallets/Default", 2)
    """
    # Find coin to break
    err, coin = _find_coin_to_break(wallet_path, target_denomination, logger_handle)
    if err != CloudCoinErrorCode.SUCCESS or coin is None:
        return BreakResult(
            success=False,
            original_coin=None,
            new_coins=[],
            raida_statuses=[0] * CC_RAIDA_COUNT,
            pass_count=0,
            error_message=f"No coin found with denomination code {target_denomination}"
        )

    return await break_coin(coin, wallet_path, config, logger_handle)


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("coin_break.py - CloudCoin Break Module")
    print("=" * 60)

    # Test helper functions
    print("\n1. Testing _generate_starting_sn()...")
    for _ in range(5):
        sn = _generate_starting_sn()
        assert MIN_STARTING_SN <= sn <= MAX_STARTING_SN, f"SN {sn} out of range"
    print(f"   Generated SN sample: {sn}")
    print("   SUCCESS: SN generation works")

    print("\n2. Testing _generate_pans()...")
    pans = _generate_pans()
    assert len(pans) == CC_RAIDA_COUNT, f"Expected {CC_RAIDA_COUNT} RAIDA entries"
    assert len(pans[0]) == 10, "Expected 10 PANs per RAIDA"
    assert len(pans[0][0]) == 16, "Expected 16-byte PANs"
    # Check uniqueness
    all_pans = [pan for raida_pans in pans for pan in raida_pans]
    assert len(all_pans) == len(set([p.hex() for p in all_pans])), "PANs not unique"
    print(f"   Generated {len(all_pans)} unique PANs")
    print("   SUCCESS: PAN generation works")

    print("\n3. Testing denomination codes...")
    assert DENOM_TO_CODE[1] == 0
    assert DENOM_TO_CODE[10] == 1
    assert DENOM_TO_CODE[100] == 2
    assert CODE_TO_DENOM[0] == 1
    assert CODE_TO_DENOM[1] == 10
    assert CODE_TO_DENOM[-1] == 0.1
    print("   SUCCESS: Denomination encoding works")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
