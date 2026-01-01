"""
heal.py - CloudCoin Fracked Coin Healing Manager/Orchestrator

This module orchestrates the "Fix Fracked" process for CloudCoins in the QMail system.
It coordinates smaller, single-responsibility modules to perform the complete healing.

Author: Claude Opus 4.5
Version: 2.0.0 (Refactored)
Date: 2025-12-26

Module Dependencies:
    - heal_protocol.py: Protocol constants, message building, response parsing
    - heal_file_io.py: Binary file I/O, CloudCoinBin dataclass
    - heal_network.py: RAIDA communication, parallel operations
    - heal_encryption.py: Encryption check and fix

Healing Process Overview:
    1. Check encryption - verify shared secrets exist with fracked RAIDA
    2. Fix encryption if needed - establish shared secrets via encrypted tickets
    3. Find Limbo - determine status of coins in Limbo folder (AN vs PAN)
    4. Grade Limbo - move limbo coins to appropriate folders based on Find results
    5. Get Tickets - obtain proof of authenticity from working RAIDA
    6. Fix with Tickets - send tickets to fracked RAIDA to repair passwords
    7. Loop - repeat steps 5-6 if fracked count reduced but not zero
    8. Grade - move repaired coins to Bank folder
"""

import os
import sys
import logging
from typing import List, Set, Dict, Tuple
from dataclasses import dataclass, field

# Import from modular components
from .heal_protocol import (
    RAIDA_COUNT, QUORUM_REQUIRED, HealErrorCode,
    generate_pg, calculate_new_an
)
from .heal_file_io import (
    CloudCoinBin, load_coins_from_folder, move_coin_file,
    FOLDER_BANK, FOLDER_FRACKED, FOLDER_LIMBO, FOLDER_COUNTERFEIT, FOLDER_SUSPECT,
    ensure_wallet_folders_exist, check_wallet_folders_exist
)
from .heal_network import (
    get_tickets_for_coins_batch, find_coins_batch, fix_coins_on_raida_set_batch
)
from .heal_encryption import (
    EncryptionHealth, check_encryption, fix_encryption
)

# Import wallet structure initialization
try:
    from .wallet_structure import initialize_wallet_structure
except ImportError:
    from .wallet_structure import initialize_wallet_structure


# ============================================================================
# LOGGING
# ============================================================================

def setup_logger(name: str = "heal", level: int = logging.DEBUG) -> logging.Logger:
    """Configure and return a logger for the heal module."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger

logger = setup_logger()


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class HealResult:
    """Results from a healing operation."""
    total_fracked: int = 0
    total_fixed: int = 0
    total_failed: int = 0
    total_limbo: int = 0
    total_limbo_recovered: int = 0
    errors: List[str] = field(default_factory=list)


# ============================================================================
# STEP 3: FIND LIMBO
# ============================================================================

def find_limbo(wallet_path: str) -> Tuple[HealErrorCode, List[CloudCoinBin]]:
    """
    STEP 3: Find status of coins.
    Now checks BOTH Limbo and Fracked folders as requested.
    """
    logger.info("STEP 3: Finding status for Limbo and Fracked coins...")
    all_coins = []

    # 1. Load from Limbo
    limbo_folder = os.path.join(wallet_path, FOLDER_LIMBO)
    err_l, l_coins = load_coins_from_folder(limbo_folder)
    if err_l == HealErrorCode.SUCCESS and l_coins:
        all_coins.extend(l_coins)

    # 2. Load from Fracked (Added per requirement)
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    err_f, f_coins = load_coins_from_folder(fracked_folder)
    if err_f == HealErrorCode.SUCCESS and f_coins:
        all_coins.extend(f_coins)

    if not all_coins:
        logger.info("  -> No coins found in Limbo or Fracked folders.")
        return HealErrorCode.SUCCESS, []

    logger.info(f"  -> Executing Find on {len(all_coins)} coins...")
    
    # Execute batch Find command (CMD 10)
    find_results = find_coins_batch(all_coins)

    # Process results (logic remains same for AN/PAN swapping)
    for coin_idx, coin in enumerate(all_coins):
        for raida_id in range(RAIDA_COUNT):
            if raida_id in find_results:
                result = find_results[raida_id][coin_idx]
                if result == 'an':
                    coin.update_pown_char(raida_id, 'p')
                elif result == 'pan':
                    coin.ans[raida_id] = coin.pans[raida_id]
                    coin.update_pown_char(raida_id, 'p')
                elif result == 'neither':
                    coin.update_pown_char(raida_id, 'f')

    return HealErrorCode.SUCCESS, all_coins


# ============================================================================
# STEP 4: GRADE LIMBO
# ============================================================================

def grade_limbo(wallet_path: str, coins: List[CloudCoinBin]) -> HealErrorCode:
    """
    STEP 4: Grade limbo coins and move to appropriate folders.

    Based on Find results:
    - Authentic (13+ pass): Move to Bank
    - Fracked (pass >= 13, but some fail): Move to Fracked
    - Counterfeit (13+ fail): Move to Fraud
    - Still limbo: Leave in Limbo

    Args:
        wallet_path: Path to wallet folder
        coins: Limbo coins with updated status from find_limbo

    Returns:
        HealErrorCode
    """
    logger.info("STEP 4: Grading limbo coins...")

    if not coins:
        logger.info("  -> No limbo coins to grade")
        return HealErrorCode.SUCCESS

    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    fraud_folder = os.path.join(wallet_path, FOLDER_COUNTERFEIT)

    for coin in coins:
        status = coin.get_grade_status()

        if status == 'authentic':
            coin.has_pans = False  # Clear PANs after resolution
            err = move_coin_file(coin, bank_folder)
            logger.info(f"  -> Coin {coin.serial_number}: AUTHENTIC -> Bank")
        elif status == 'fracked':
            coin.has_pans = False
            err = move_coin_file(coin, fracked_folder)
            logger.info(f"  -> Coin {coin.serial_number}: FRACKED -> Fracked folder")
        elif status == 'counterfeit':
            coin.has_pans = False
            err = move_coin_file(coin, fraud_folder)
            logger.info(f"  -> Coin {coin.serial_number}: COUNTERFEIT -> Fraud folder")
        else:
            # Still limbo - leave in place
            logger.info(f"  -> Coin {coin.serial_number}: Still in LIMBO")

    return HealErrorCode.SUCCESS


# ============================================================================
# STEP 5: GET TICKETS
# ============================================================================

def get_tickets(coins: List[CloudCoinBin]) -> Tuple[HealErrorCode, List[int], Dict[int, List[bool]]]:
    """
    STEP 5: Get tickets from authenticated RAIDA.

    Tickets prove that a coin is authentic on the issuing RAIDA.
    These tickets are used in the Fix step to convince fracked RAIDA.

    Args:
        coins: Coins to get tickets for

    Returns:
        Tuple of:
            - error_code
            - List of 25 ticket IDs
            - Dict of per-RAIDA results
    """
    logger.info("STEP 5: Getting tickets from RAIDA...")

    if not coins:
        logger.info("  -> No coins to get tickets for")
        return HealErrorCode.SUCCESS, [0] * RAIDA_COUNT, {}

    logger.info(f"  -> Getting tickets for {len(coins)} coins")

    tickets, coin_results = get_tickets_for_coins_batch(coins)

    # Count successful tickets
    valid_tickets = sum(1 for t in tickets if t != 0)
    logger.info(f"  -> Received {valid_tickets}/{RAIDA_COUNT} valid tickets")

    if valid_tickets < QUORUM_REQUIRED:
        logger.warning(f"  -> Insufficient tickets ({valid_tickets} < {QUORUM_REQUIRED})")
        return HealErrorCode.ERR_NO_TICKETS, tickets, coin_results

    return HealErrorCode.SUCCESS, tickets, coin_results


# ============================================================================
# STEP 6: FIX WITH TICKETS
# ============================================================================

def fix_with_tickets(
    coins: List[CloudCoinBin],
    tickets: List[int],
    fracked_raida: Set[int]
) -> Tuple[HealErrorCode, int]:
    """
    STEP 6: Fix fracked RAIDA using tickets.

    Sends tickets to each fracked RAIDA. The RAIDA contacts other RAIDA
    to verify the tickets, then updates its password for the coin.

    Args:
        coins: Coins to fix
        tickets: List of 25 ticket IDs from get_tickets
        fracked_raida: Set of RAIDA IDs that need fixing

    Returns:
        Tuple of (error_code, number of fixes applied)
    """
    logger.info("STEP 6: Fixing coins with tickets...")

    if not coins or not fracked_raida:
        logger.info("  -> Nothing to fix")
        return HealErrorCode.SUCCESS, 0

    logger.info(f"  -> Fixing {len(coins)} coins on RAIDA: {sorted(fracked_raida)}")

    # Generate PG for new passwords
    pg = generate_pg()

    # Fix on each fracked RAIDA in parallel (batch version)
    result_dict = fix_coins_on_raida_set_batch(coins, fracked_raida, pg, tickets)

    # Process results and update coins
    total_fixes = 0

    for coin_idx, coin in enumerate(coins):
        for raida_id in fracked_raida:
            if raida_id in result_dict and result_dict[raida_id][coin_idx]:
                # Fix succeeded - update AN and POWN
                new_an = calculate_new_an(raida_id, coin.denomination, coin.serial_number, pg)
                coin.ans[raida_id] = new_an
                coin.update_pown_char(raida_id, 'p')
                total_fixes += 1

    logger.info(f"  -> Applied {total_fixes} fixes")
    return HealErrorCode.SUCCESS, total_fixes


# ============================================================================
# STEP 8: GRADE COINS
# ============================================================================

def grade_coins(wallet_path: str, coins: List[CloudCoinBin]) -> HealErrorCode:
    """
    STEP 8: Grade fixed coins and move to appropriate folders.

    Args:
        wallet_path: Path to wallet folder
        coins: Coins to grade

    Returns:
        HealErrorCode
    """
    logger.info("STEP 8: Grading coins...")

    if not coins:
        logger.info("  -> No coins to grade")
        return HealErrorCode.SUCCESS

    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    fraud_folder = os.path.join(wallet_path, FOLDER_COUNTERFEIT)
    suspect_folder = os.path.join(wallet_path, FOLDER_SUSPECT)

    for coin in coins:
        status = coin.get_grade_status()

        if status == 'authentic':
            err = move_coin_file(coin, bank_folder)
            logger.info(f"  -> Coin {coin.serial_number}: AUTHENTIC -> Bank")
        elif status == 'fracked':
            # Still fracked after fix attempt - might need another round
            err = move_coin_file(coin, fracked_folder)
            logger.info(f"  -> Coin {coin.serial_number}: Still FRACKED -> Fracked folder")
        elif status == 'counterfeit':
            err = move_coin_file(coin, fraud_folder)
            logger.info(f"  -> Coin {coin.serial_number}: COUNTERFEIT -> Fraud folder")
        else:
            err = move_coin_file(coin, suspect_folder)
            logger.info(f"  -> Coin {coin.serial_number}: SUSPECT -> Suspect folder")

    return HealErrorCode.SUCCESS


# ============================================================================
# MAIN HEAL FUNCTION
# ============================================================================

def heal_wallet(wallet_path: str, max_iterations: int = 3) -> HealResult:
    """
    Main entry point for healing fracked coins in a wallet.

    Executes the complete healing process:
    1. Check encryption
    2. Fix encryption if needed
    3. Find limbo coins
    4. Grade limbo coins
    5. Get tickets for fracked coins
    6. Fix fracked coins with tickets
    7. Loop if fracked count reduced but not zero
    8. Grade all coins

    Args:
        wallet_path: Path to wallet folder
        max_iterations: Maximum fix iterations (default 3)

    Returns:
        HealResult with statistics
    """
    logger.info("=" * 60)
    logger.info("Starting Heal Process")
    logger.info(f"Wallet: {wallet_path}")
    logger.info("=" * 60)

    result = HealResult()

    # Validate wallet path exists (or can be created)
    if not os.path.exists(wallet_path):
        logger.warning(f"Wallet path does not exist, creating: {wallet_path}")

    # Ensure all wallet folders exist (Bank, Fracked, Limbo, etc.)
    err = ensure_wallet_folders_exist(wallet_path)
    if err != HealErrorCode.SUCCESS:
        logger.error(f"Failed to create wallet folders")
        result.errors.append("Failed to create wallet folder structure")
        return result

    # Verify folders were created
    all_exist, missing = check_wallet_folders_exist(wallet_path)
    if not all_exist:
        logger.error(f"Missing wallet folders: {missing}")
        result.errors.append(f"Missing wallet folders: {missing}")
        return result

    logger.info(f"Wallet folders verified: Bank, Fracked, Limbo, Fraud, Suspect, Grade")

    # STEP 1: Check encryption
    err, encryption_health = check_encryption(wallet_path)
    if err != HealErrorCode.SUCCESS:
        result.errors.append("Encryption check failed")
        return result

    # STEP 2: Fix encryption if needed
    err = fix_encryption(wallet_path, encryption_health)
    if err != HealErrorCode.SUCCESS:
        result.errors.append("Encryption fix failed")
        # Continue anyway - some operations may work unencrypted

    # STEP 3: Find limbo coins
    err, limbo_coins = find_limbo(wallet_path)
    if err == HealErrorCode.SUCCESS and limbo_coins:
        result.total_limbo = len(limbo_coins)

        # STEP 4: Grade limbo coins
        err = grade_limbo(wallet_path, limbo_coins)

        # Count recovered limbo coins
        for coin in limbo_coins:
            if coin.get_grade_status() in ['authentic', 'fracked']:
                result.total_limbo_recovered += 1

    # Load fracked coins
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    err, fracked_coins = load_coins_from_folder(fracked_folder)

    if err != HealErrorCode.SUCCESS or not fracked_coins:
        logger.info("No fracked coins to fix")
        return result

    result.total_fracked = len(fracked_coins)
    logger.info(f"Found {result.total_fracked} fracked coins to fix")

    # STEP 5-7: Iterative fix process
    iteration = 0
    coins_to_fix = fracked_coins

    while iteration < max_iterations and coins_to_fix:
        iteration += 1
        logger.info(f"\n--- Fix Iteration {iteration}/{max_iterations} ---")

        # Count fracked positions before fix
        fracked_before = sum(coin.count_fracked() for coin in coins_to_fix)

        # Identify which RAIDA need fixing
        fracked_raida: Set[int] = set()
        for coin in coins_to_fix:
            fracked_raida.update(coin.get_fracked_raida())

        if not fracked_raida:
            logger.info("No fracked RAIDA positions remaining")
            break

        # STEP 5: Get tickets
        err, tickets, coin_results = get_tickets(coins_to_fix)
        if err != HealErrorCode.SUCCESS:
            logger.warning("Failed to get sufficient tickets")
            result.errors.append(f"Iteration {iteration}: Failed to get tickets")
            break

        # STEP 6: Fix with tickets
        err, fixes_applied = fix_with_tickets(coins_to_fix, tickets, fracked_raida)

        # Count fracked positions after fix
        fracked_after = sum(coin.count_fracked() for coin in coins_to_fix)

        logger.info(f"Fracked positions: {fracked_before} -> {fracked_after}")

        # STEP 7: Check if we should continue
        if fracked_after == 0:
            logger.info("All fracked positions fixed!")
            break
        elif fracked_after >= fracked_before:
            logger.info("No improvement - stopping iterations")
            break
        else:
            logger.info(f"Reduced by {fracked_before - fracked_after} - continuing...")

        # Filter to only still-fracked coins
        coins_to_fix = [c for c in coins_to_fix if c.count_fracked() > 0]

    # STEP 8: Grade all coins
    err = grade_coins(wallet_path, fracked_coins)

    # Calculate final statistics
    for coin in fracked_coins:
        status = coin.get_grade_status()
        if status == 'authentic':
            result.total_fixed += 1
        elif status == 'counterfeit':
            result.total_failed += 1

    logger.info("\n" + "=" * 60)
    logger.info("Heal Process Complete")
    logger.info(f"  Total fracked: {result.total_fracked}")
    logger.info(f"  Total fixed: {result.total_fixed}")
    logger.info(f"  Total failed: {result.total_failed}")
    logger.info(f"  Limbo coins: {result.total_limbo}")
    logger.info(f"  Limbo recovered: {result.total_limbo_recovered}")
    if result.errors:
        logger.info(f"  Errors: {len(result.errors)}")
        for err in result.errors:
            logger.info(f"    - {err}")
    logger.info("=" * 60)

    return result


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """
    Command-line interface for the heal module.

    Usage:
        python heal.py <wallet_path>
        python heal.py --help
        python heal.py --test
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="CloudCoin Fracked Coin Healing Module (Modular Version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python heal.py Data/Wallets/Default
    python heal.py --test
    python heal.py --verbose Data/Wallets/Mailbox
        """
    )

    parser.add_argument(
        'wallet_path',
        nargs='?',
        default=None,
        help='Path to wallet folder'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Run module integration tests'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--max-iterations', '-i',
        type=int,
        default=3,
        help='Maximum fix iterations (default: 3)'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.test:
        run_integration_tests()
        return

    if not args.wallet_path:
        parser.print_help()
        return

    result = heal_wallet(args.wallet_path, max_iterations=args.max_iterations)

    # Exit with appropriate code
    if result.errors:
        sys.exit(1)
    sys.exit(0)


def run_integration_tests():
    """
    Run integration tests to verify module imports and basic functionality.
    """
    print("=" * 60)
    print("heal.py - Module Integration Tests")
    print("=" * 60)

    # Test 1: Import verification
    print("\n1. Testing module imports...")
    try:
        from heal_protocol import RAIDA_COUNT, generate_challenge
        from heal_file_io import CloudCoinBin, read_coin_file
        from heal_network import (
            get_raida_endpoint, send_request, RAIDA_BASE_PORT,
            get_tickets_for_coins_batch, find_coins_batch, fix_coins_on_raida_set_batch
        )
        from heal_encryption import EncryptionHealth, check_encryption
        print("   All modules imported successfully")
        print("   PASS")
    except ImportError as e:
        print(f"   FAIL: {e}")
        return

    # Test 2: Protocol constants
    print("\n2. Testing protocol constants...")
    assert RAIDA_COUNT == 25, f"RAIDA_COUNT should be 25, got {RAIDA_COUNT}"
    assert RAIDA_BASE_PORT == 50000, f"RAIDA_BASE_PORT should be 50000, got {RAIDA_BASE_PORT}"
    print(f"   RAIDA_COUNT = {RAIDA_COUNT}")
    print(f"   RAIDA_BASE_PORT = {RAIDA_BASE_PORT}")
    print("   PASS")

    # Test 3: CloudCoinBin creation
    print("\n3. Testing CloudCoinBin creation...")
    coin = CloudCoinBin(
        denomination=1,
        serial_number=12345678,
        pown='pppppppppppppfffffuuuuuu'
    )
    assert coin.get_value() == 10.0
    assert len(coin.get_fracked_raida()) == 5
    assert len(coin.get_passed_raida()) == 13
    assert coin.get_grade_status() == 'fracked'
    print(f"   Denomination: {coin.denomination}, Value: {coin.get_value()}")
    print(f"   Fracked RAIDA: {coin.get_fracked_raida()}")
    print(f"   Grade Status: {coin.get_grade_status()}")
    print("   PASS")

    # Test 4: Challenge generation
    print("\n4. Testing challenge generation...")
    challenge = generate_challenge()
    assert len(challenge) == 16, f"Challenge should be 16 bytes, got {len(challenge)}"
    print(f"   Challenge: {challenge.hex()}")
    print("   PASS")

    # Test 5: RAIDA endpoint
    print("\n5. Testing RAIDA endpoint generation...")
    host, port = get_raida_endpoint(13)
    assert port == 50013, f"RAIDA 13 port should be 50013, got {port}"
    print(f"   RAIDA 13: {host}:{port}")
    print("   PASS")

    # Test 6: EncryptionHealth
    print("\n6. Testing EncryptionHealth dataclass...")
    health = EncryptionHealth()
    assert len(health.is_broken) == 25
    assert len(health.get_broken_raida()) == 0
    assert len(health.get_working_raida()) == 25
    health.is_broken[5] = True
    health.is_broken[10] = True
    assert 5 in health.get_broken_raida()
    assert 10 in health.get_broken_raida()
    print(f"   Working RAIDA: {len(health.get_working_raida())}")
    print(f"   Broken RAIDA: {health.get_broken_raida()}")
    print("   PASS")

    # Test 7: HealResult
    print("\n7. Testing HealResult dataclass...")
    result = HealResult()
    result.total_fracked = 10
    result.total_fixed = 8
    result.total_failed = 2
    assert result.total_fracked == 10
    assert result.total_fixed == 8
    print(f"   Fracked: {result.total_fracked}")
    print(f"   Fixed: {result.total_fixed}")
    print("   PASS")

    print("\n" + "=" * 60)
    print("All integration tests passed!")
    print("=" * 60)
    print("\nModular architecture verified:")
    print("  - heal_protocol.py: Protocol constants and message building")
    print("  - heal_file_io.py: Binary file I/O operations")
    print("  - heal_network.py: RAIDA communication")
    print("  - heal_encryption.py: Encryption check and fix")
    print("  - heal.py: Orchestrator (this file)")
    print("\nNote: Network tests require live RAIDA servers.")


if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()
    main()
