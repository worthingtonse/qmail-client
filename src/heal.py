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
from heal_protocol import (
    RAIDA_COUNT, QUORUM_REQUIRED, HealErrorCode,
    generate_pg, calculate_new_an
)
from heal_file_io import (
    CloudCoinBin, load_coins_from_folder, move_coin_file,
    FOLDER_BANK, FOLDER_FRACKED, FOLDER_LIMBO, FOLDER_COUNTERFEIT, FOLDER_SUSPECT,
    ensure_wallet_folders_exist, check_wallet_folders_exist
)
from heal_network import (
    get_tickets_for_coins_batch, find_coins_batch, fix_coins_on_raida_set_batch
)
from heal_encryption import (
    EncryptionHealth, check_encryption, fix_encryption
)

# Import wallet structure initialization
try:
    from wallet_structure import initialize_wallet_structure
except ImportError:
    from wallet_structure import initialize_wallet_structure


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
            logger.info(
                f"  -> Coin {coin.serial_number}: FRACKED -> Fracked folder")
        elif status == 'counterfeit':
            coin.has_pans = False
            err = move_coin_file(coin, fraud_folder)
            logger.info(
                f"  -> Coin {coin.serial_number}: COUNTERFEIT -> Fraud folder")
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
        logger.warning(
            f"  -> Insufficient tickets ({valid_tickets} < {QUORUM_REQUIRED})")
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

    logger.info(
        f"  -> Fixing {len(coins)} coins on RAIDA: {sorted(fracked_raida)}")

    # Generate PG for new passwords
    pg = generate_pg()

    # Fix on each fracked RAIDA in parallel (batch version)
    result_dict = fix_coins_on_raida_set_batch(
        coins, fracked_raida, pg, tickets)

    # Process results and update coins
    total_fixes = 0

    for coin_idx, coin in enumerate(coins):
        for raida_id in fracked_raida:
            if raida_id in result_dict and result_dict[raida_id][coin_idx]:
                # Fix succeeded - update AN and POWN
                new_an = calculate_new_an(
                    raida_id, coin.denomination, coin.serial_number, pg)
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
            logger.info(
                f"  -> Coin {coin.serial_number}: Still FRACKED -> Fracked folder")
        elif status == 'counterfeit':
            err = move_coin_file(coin, fraud_folder)
            logger.info(
                f"  -> Coin {coin.serial_number}: COUNTERFEIT -> Fraud folder")
        else:
            err = move_coin_file(coin, suspect_folder)
            logger.info(
                f"  -> Coin {coin.serial_number}: SUSPECT -> Suspect folder")

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

    logger.info(
        f"Wallet folders verified: Bank, Fracked, Limbo, Fraud, Suspect, Grade")

   # STEP 0: MOVE FRACKED BANK COINS TO FRACKED FOLDER
    # Check all Bank coins for 'f', 'n', or 'u' status and move them for healing
    err, checked, moved = verify_bank_coins(wallet_path)
    if moved > 0:
        logger.info(f"Moved {moved} fracked Bank coins to Fracked folder for healing")
    
    # STEP 0.5: DISCOVER BANK COIN STATUS (for remaining unknown via network check)
    err, checked2, moved2 = discover_bank_coin_status(wallet_path)
    if moved2 > 0:
        logger.info(f"Discovered {moved2} additional coins that need attention")

    # STEP 1-2: CHECK ENCRYPTION (DON'T FAIL IF ALL BROKEN - FIX AFTER HEALING)
    err, encryption_health = check_encryption(wallet_path)
    if err != HealErrorCode.SUCCESS:
        result.errors.append("Encryption check failed")
        return result

    working_raida_count = len(encryption_health.get_working_raida())
    broken_raida_count = len(encryption_health.get_broken_raida())

    # Only attempt encryption fix if we have enough helpers (need 2+ working RAIDA)
    if broken_raida_count > 0 and working_raida_count >= 2:
        logger.info(
            f"Attempting to fix encryption on {broken_raida_count} RAIDA...")
        fix_result = fix_encryption(wallet_path, encryption_health)

        if not fix_result.success:
            logger.warning(
                f"Encryption fix incomplete - fixed {fix_result.total_fixed}/{broken_raida_count}")
            logger.warning(
                "Will continue healing in UNENCRYPTED mode for broken RAIDA")
            # DON'T FAIL HERE - healing can work without encryption
    elif broken_raida_count > 0:
        logger.warning(
            f"[!] Cannot fix encryption - only {working_raida_count} working RAIDA (need 2+)")
        logger.warning("[!] Will attempt healing in UNENCRYPTED mode")
        logger.warning("[!] RAIDA requests will be sent WITHOUT encryption!")
    else:
        logger.info("[OK] All RAIDA have working encryption")

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

        # Count positions needing healing before fix (includes both 'f' and 'u')
        fracked_before = sum(coin.count_needs_healing() for coin in coins_to_fix)

        # Identify which RAIDA need fixing (include both failed AND unknown)
        fracked_raida: Set[int] = set()
        for coin in coins_to_fix:
            fracked_raida.update(coin.get_needs_healing_raida())

        if not fracked_raida:
            logger.info("No fracked RAIDA positions remaining")
            break

        # STEP 5: Get tickets
        err, tickets, coin_results = get_tickets(coins_to_fix)
        if err != HealErrorCode.SUCCESS:
            logger.warning("Failed to get sufficient tickets")
            result.errors.append(
                f"Iteration {iteration}: Failed to get tickets")
            break

        # STEP 6: Fix with tickets
        err, fixes_applied = fix_with_tickets(
            coins_to_fix, tickets, fracked_raida)

        # Count positions needing healing after fix
        fracked_after = sum(coin.count_needs_healing() for coin in coins_to_fix)

        logger.info(f"Fracked positions: {fracked_before} -> {fracked_after}")

        # STEP 7: Check if we should continue
        if fracked_after == 0:
            logger.info("All fracked positions fixed!")
            break
        elif fracked_after >= fracked_before:
            logger.info("No improvement - stopping iterations")
            break
        else:
            logger.info(
                f"Reduced by {fracked_before - fracked_after} - continuing...")

        # Filter to only still-fracked coins (those with 'f' or 'u' positions)
        coins_to_fix = [c for c in coins_to_fix if c.count_needs_healing() > 0]

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
# STEP 9: DISCOVER BANK COIN STATUS
# ============================================================================

def discover_bank_coin_status(wallet_path: str) -> Tuple[HealErrorCode, int, int]:
    """
    STEP 9: Discover true status of Bank coins with unknown ('u') RAIDA.

    Bank coins may have 'u' (unknown) status on some RAIDA if they were
    never properly authenticated. This step sends Get Ticket requests
    to discover their true status and update POWN strings.

    Coins that turn out to be fracked will be moved to Fracked folder.
    Coins that turn out to be counterfeit will be moved to Counterfeit folder.

    Args:
        wallet_path: Path to wallet folder

    Returns:
        Tuple of (error_code, coins_checked, coins_moved)
    """
    logger.info("STEP 9: Discovering Bank coin status...")

    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    err, bank_coins = load_coins_from_folder(bank_folder)

    if err != HealErrorCode.SUCCESS or not bank_coins:
        logger.info("  -> No coins in Bank folder")
        return HealErrorCode.SUCCESS, 0, 0

    # Find coins with unknown status
    coins_with_unknown = [c for c in bank_coins if 'u' in c.pown]

    if not coins_with_unknown:
        logger.info("  -> All Bank coins have known status")
        return HealErrorCode.SUCCESS, 0, 0

    logger.info(f"  -> Found {len(coins_with_unknown)} coins with unknown status")

    # Get tickets to discover true status (this updates POWN strings)
    from heal_network import get_tickets_for_coins_batch
    tickets, results = get_tickets_for_coins_batch(coins_with_unknown)

    # Now grade the coins based on discovered status
    coins_moved = 0
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    fraud_folder = os.path.join(wallet_path, FOLDER_COUNTERFEIT)

    for coin in coins_with_unknown:
        status = coin.get_grade_status()
        logger.info(f"  -> Coin {coin.serial_number}: {coin.pown} -> {status}")

        if status == 'authentic':
            # Coin is good, update file in place
            from heal_file_io import write_coin_file
            write_coin_file(coin.file_path, coin)
            logger.info(f"     Updated in Bank (all 25 pass)")
        elif status == 'fracked':
            # Move to Fracked folder for healing
            err = move_coin_file(coin, fracked_folder)
            logger.info(f"     Moved to Fracked folder for healing")
            coins_moved += 1
        elif status == 'counterfeit':
            # Move to Counterfeit folder
            err = move_coin_file(coin, fraud_folder)
            logger.info(f"     Moved to Counterfeit folder")
            coins_moved += 1

    return HealErrorCode.SUCCESS, len(coins_with_unknown), coins_moved


# ============================================================================
# MULTI-WALLET HEALING
# ============================================================================

def verify_bank_coins(wallet_path: str) -> Tuple[HealErrorCode, int, int]:
    """
    STEP 0.5: Move Bank coins with FRACKED status to Fracked folder for healing.
    
    Uses the same grading logic as Go code:
    - Need 14+ passes (MIN_PASSED_NUM_TO_BE_AUTHENTIC)
    - 0 fails
    - 0 errors
    - 'n' (no-response) and 'u' (untried) are NEUTRAL (ignored)
    
    Args:
        wallet_path: Path to wallet folder
        
    Returns:
        Tuple of (error_code, coins_checked, coins_moved_to_fracked)
    """
    logger.info("STEP 0.5: Checking Bank coins for fracked status...")
    
    bank_folder = os.path.join(wallet_path, FOLDER_BANK)
    err, bank_coins = load_coins_from_folder(bank_folder)
    
    if err != HealErrorCode.SUCCESS or not bank_coins:
        logger.info("  -> No coins in Bank folder")
        return HealErrorCode.SUCCESS, 0, 0
    
    # Find coins that are FRACKED (using Go grading logic)
    needs_healing = []
    for coin in bank_coins:
        pown = coin.pown or ''
        pass_count = pown.count('p')
        fail_count = pown.count('f')
        error_count = pown.count('e')
        
        # Coin is FRACKED if:
        # - Less than 14 passes, OR
        # - Has any fails, OR
        # - Has any errors
        is_fracked = (pass_count < 14) or (fail_count > 0) or (error_count > 0)
        
        if is_fracked:
            needs_healing.append(coin)
    
    if not needs_healing:
        logger.info(f"  -> All {len(bank_coins)} Bank coins are healthy (14+ passes, 0 fails)")
        return HealErrorCode.SUCCESS, len(bank_coins), 0
    
    logger.info(f"  -> Found {len(needs_healing)} fracked coins needing healing")
    
    # Move to Fracked folder
    fracked_folder = os.path.join(wallet_path, FOLDER_FRACKED)
    coins_moved = 0
    
    for coin in needs_healing:
        pown = coin.pown or ''
        pass_count = pown.count('p')
        fail_count = pown.count('f')
        error_count = pown.count('e')
        no_resp = pown.count('n')
        unknown = pown.count('u')
        
        reason = []
        if pass_count < 14:
            reason.append(f"only {pass_count} passes")
        if fail_count > 0:
            reason.append(f"{fail_count} fails")
        if error_count > 0:
            reason.append(f"{error_count} errors")
        
        logger.info(f"  -> Coin {coin.serial_number}: {pass_count}p/{fail_count}f/{no_resp}n/{unknown}u -> FRACKED ({', '.join(reason)})")
        err = move_coin_file(coin, fracked_folder)
        if err == HealErrorCode.SUCCESS:
            coins_moved += 1
    
    logger.info(f"  -> Moved {coins_moved} coins to Fracked folder for healing")
    return HealErrorCode.SUCCESS, len(bank_coins), coins_moved


def get_wallets_base_path() -> str:
    """
    Get the base path for wallets, relative to the project root.

    Handles both running from src/ directory and project root.
    """
    # Try relative to current directory first
    if os.path.exists("Data/Wallets"):
        return "Data/Wallets"

    # Try parent directory (if running from src/)
    if os.path.exists("../Data/Wallets"):
        return "../Data/Wallets"

    # Try absolute path based on this file's location
    this_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(this_dir)
    wallets_path = os.path.join(project_root, "Data", "Wallets")
    if os.path.exists(wallets_path):
        return wallets_path

    # Default fallback
    return "Data/Wallets"


def discover_all_wallets(base_path: str = None) -> List[str]:
    """
    Discover all wallet folders in the base path.

    A valid wallet folder is any directory that contains a Bank subfolder
    or is a direct child of the wallets base path.

    Args:
        base_path: Base path to search for wallets (auto-detected if None)

    Returns:
        List of wallet paths
    """
    if base_path is None:
        base_path = get_wallets_base_path()

    wallets = []

    if not os.path.exists(base_path):
        logger.warning(f"Wallets base path does not exist: {base_path}")
        return wallets

    for name in os.listdir(base_path):
        wallet_path = os.path.join(base_path, name)
        if os.path.isdir(wallet_path):
            # Check if it looks like a wallet (has Bank folder or other wallet folders)
            bank_path = os.path.join(wallet_path, FOLDER_BANK)
            fracked_path = os.path.join(wallet_path, FOLDER_FRACKED)
            if os.path.exists(bank_path) or os.path.exists(fracked_path):
                wallets.append(wallet_path)
            else:
                # Still include it - heal_wallet will create the folders
                wallets.append(wallet_path)

    # Sort for consistent ordering
    wallets.sort()
    return wallets


def heal_all_wallets(max_iterations: int = 3, base_path: str = None) -> Dict[str, HealResult]:
    """
    Heal ALL wallets found in the wallets folder.

    Automatically discovers all wallet folders (Default, Mailbox, Sender, etc.)
    and processes each one.

    Args:
        max_iterations: Maximum fix iterations per wallet
        base_path: Base path to search for wallets (auto-detected if None)

    Returns:
        Dict mapping wallet_path -> HealResult
    """
    if base_path is None:
        base_path = get_wallets_base_path()

    logger.info("=" * 60)
    logger.info("HEALING ALL WALLETS")
    logger.info("=" * 60)

    # Discover all wallets
    wallet_paths = discover_all_wallets(base_path)

    if not wallet_paths:
        logger.warning(f"No wallets found in {base_path}")
        return {}

    logger.info(f"Found {len(wallet_paths)} wallets: {[os.path.basename(w) for w in wallet_paths]}")

    results = {}

    for wallet_path in wallet_paths:
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing wallet: {wallet_path}")
        logger.info(f"{'='*60}")
        results[wallet_path] = heal_wallet(wallet_path, max_iterations)

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("ALL WALLETS HEAL SUMMARY")
    logger.info("=" * 60)

    total_fracked = 0
    total_fixed = 0
    total_failed = 0

    for wallet_path, result in results.items():
        logger.info(f"\n{wallet_path}:")
        logger.info(f"  Fracked: {result.total_fracked}")
        logger.info(f"  Fixed: {result.total_fixed}")
        logger.info(f"  Failed: {result.total_failed}")
        total_fracked += result.total_fracked
        total_fixed += result.total_fixed
        total_failed += result.total_failed

    logger.info(f"\nTOTAL: {total_fixed}/{total_fracked} fixed, {total_failed} failed")
    logger.info("=" * 60)

    return results


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """
    Command-line interface for the heal module.

    Usage:
        python heal.py <wallet_path>
        python heal.py --all              # Heal both Default and Mailbox
        python heal.py --help
        python heal.py --test
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="CloudCoin Fracked Coin Healing Module (Modular Version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python heal.py --all                    # Heal both Default and Mailbox wallets
    python heal.py Data/Wallets/Default     # Heal specific wallet
    python heal.py --test                   # Run module tests
    python heal.py --verbose --all          # Verbose heal of all wallets
        """
    )

    parser.add_argument(
        'wallet_path',
        nargs='?',
        default=None,
        help='Path to wallet folder (or use --all for Default + Mailbox)'
    )

    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Heal both Default and Mailbox wallets'
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

    parser.add_argument(
        '--discover-only',
        action='store_true',
        help='Only discover Bank coin status without full healing'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.test:
        run_integration_tests()
        return

    # Handle --discover-only mode
    if args.discover_only:
        if args.all:
            wallet_paths = discover_all_wallets()
            for wallet_path in wallet_paths:
                logger.info(f"\nDiscovering: {wallet_path}")
                discover_bank_coin_status(wallet_path)
        elif args.wallet_path:
            discover_bank_coin_status(args.wallet_path)
        else:
            parser.print_help()
        return

    # Handle --all flag
    if args.all:
        results = heal_all_wallets(max_iterations=args.max_iterations)
        # Exit with error if any wallet had errors
        has_errors = any(r.errors for r in results.values())
        sys.exit(1 if has_errors else 0)

    # Handle specific wallet path
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
    assert len(
        challenge) == 16, f"Challenge should be 16 bytes, got {len(challenge)}"
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