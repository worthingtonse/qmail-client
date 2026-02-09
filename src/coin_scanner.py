"""
coin_scanner.py - CloudCoin Binary File Scanner

This module scans CloudCoin .bin files and calculates wallet balances by reading
denomination codes from binary files.

Binary File Format:
- Denomination code: Byte offset 34 (0-indexed)
- Type: Signed int8 (signed byte)
- Value calculation: 10^(denomination_code)
- Special case: code=11 represents "Key" coins (treated as value 0)

Author: Claude Sonnet 4.5
Date: 2025-12-22
"""

import os
import struct
import math
from typing import Tuple, Dict, Optional , List , Any
from enum import IntEnum

# Import error codes from cloudcoin module
try:
    from cloudcoin import CloudCoinErrorCode
    from logger import log_error, log_warning, log_debug, log_info
    from wallet_structure import initialize_wallet_structure
except ImportError:
    # Fallback definitions for standalone usage
    class CloudCoinErrorCode(IntEnum):
        SUCCESS = 0
        ERR_IO_ERROR = 4
        ERR_INVALID_KEY = 3

    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")

    def log_warning(handle, context, msg):
        print(f"[WARNING] [{context}] {msg}")

    def log_debug(handle, context, msg):
        print(f"[DEBUG] [{context}] {msg}")

    def log_info(handle, context, msg):
        print(f"[INFO] [{context}] {msg}")

    from wallet_structure import initialize_wallet_structure


# ============================================================================
# CONSTANTS
# ============================================================================

DENOMINATION_BYTE_OFFSET = 34  # 0-based byte offset for denomination code
MIN_FILE_SIZE = 35             # Minimum bytes required to read denomination
KEY_COIN_CODE = 11             # Special code for Key/NFT coins


# ============================================================================
# DENOMINATION PARSING
# ============================================================================

def parse_denomination_code(denom_code: int) -> float:
    """
    Convert denomination code to actual CloudCoin value.

    Based on C implementation in utils.c:360-391 (cc_denomination_to_string)

    Args:
        denom_code: Signed 8-bit integer from byte 34

    Returns:
        Float value of the coin

    Examples:
        -1 => 0.1
         0 => 1
         1 => 10
         2 => 100
         3 => 1000
        11 => 0 (Key coin - special case)
    """
    # Special case: Key coins (NFTs)
    if denom_code == KEY_COIN_CODE:
        return 0.0

    # Standard calculation: value = 10^code
    # Handles both positive and negative codes
    try:
        value = 10 ** denom_code
        return float(value)
    except (OverflowError, ValueError):
        # Handle extreme values
        return 0.0


def parse_coin_file(file_path: str, logger_handle=None) -> Tuple[CloudCoinErrorCode, Optional[float]]:
    """
    Parse a single CloudCoin .bin file and extract its denomination value.

    Args:
        file_path: Absolute path to .bin file
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (error_code, value)
        - On success: (SUCCESS, denomination_value)
        - On error: (error_code, None)
    """
    try:
        # Check file size first
        file_size = os.path.getsize(file_path)
        if file_size < MIN_FILE_SIZE:
            log_warning(logger_handle, "CoinScanner",
                       f"File too small ({file_size} bytes): {file_path}")
            return CloudCoinErrorCode.ERR_INVALID_KEY, None

        # Read denomination byte
        with open(file_path, 'rb') as f:
            f.seek(DENOMINATION_BYTE_OFFSET)
            denom_byte = f.read(1)

            if not denom_byte:
                log_warning(logger_handle, "CoinScanner",
                           f"Cannot read denomination byte: {file_path}")
                return CloudCoinErrorCode.ERR_IO_ERROR, None

            # Unpack as signed int8 (signed byte)
            denom_code = struct.unpack('b', denom_byte)[0]

            # Convert to value
            value = parse_denomination_code(denom_code)

            return CloudCoinErrorCode.SUCCESS, value

    except IOError as e:
        log_error(logger_handle, "CoinScanner",
                 f"IO error reading {file_path}", str(e))
        return CloudCoinErrorCode.ERR_IO_ERROR, None
    except Exception as e:
        log_error(logger_handle, "CoinScanner",
                 f"Unexpected error parsing {file_path}", str(e))
        return CloudCoinErrorCode.ERR_IO_ERROR, None


# ============================================================================
# DIRECTORY SCANNING
# ============================================================================

def scan_coins_in_directory(dir_path: str, logger_handle=None) -> Tuple[float, int, Dict[float, int]]:
    """
    Scan all .bin files in a directory and calculate total balance.

    Uses os.scandir() for performance with large directories.
    Continues scanning even if individual files are corrupted.

    Args:
        dir_path: Absolute path to directory containing .bin files
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (total_value, coin_count, denomination_counts)
        - total_value: Sum of all coin values
        - coin_count: Number of valid coins found
        - denomination_counts: Dict mapping value to count
          Example: {1.0: 50, 100.0: 10, 0.1: 5}
    """
    total_value = 0.0
    coin_count = 0
    denomination_counts: Dict[float, int] = {}

    # Check if directory exists
    if not os.path.isdir(dir_path):
        log_warning(logger_handle, "CoinScanner",
                   f"Directory does not exist: {dir_path}")
        return 0.0, 0, {}

    try:
        # Use scandir for better performance
        with os.scandir(dir_path) as entries:
            for entry in entries:
                # Filter to .bin files only
                if not entry.is_file() or not entry.name.endswith('.bin'):
                    continue

                # Parse the coin file
                err, value = parse_coin_file(entry.path, logger_handle)

                if err == CloudCoinErrorCode.SUCCESS and value is not None:
                    # Update totals
                    total_value += value
                    coin_count += 1

                    # Update denomination histogram
                    denomination_counts[value] = denomination_counts.get(value, 0) + 1
                else:
                    # Log but continue scanning
                    log_debug(logger_handle, "CoinScanner",
                             f"Skipping corrupted file: {entry.name}")

    except OSError as e:
        log_error(logger_handle, "CoinScanner",
                 f"Error scanning directory {dir_path}", str(e))
        # Return partial results
        return total_value, coin_count, denomination_counts

    return total_value, coin_count, denomination_counts


def get_denomination_breakdown(denomination_counts: Dict[float, int]) -> Dict[str, int]:
    """
    Convert denomination histogram to denomination breakdown.

    All valid CloudCoin denominations are powers of 10 (based on utils.c encoding).
    This includes: 0.0000001, 0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1,
                   1, 10, 100, 1000, 10000, 100000, etc.

    Args:
        denomination_counts: Dict mapping float values to counts

    Returns:
        Dict with string keys for all denominations found
        Example: {"1": 50, "10": 10, "100": 5, "0.1": 5, "other": 2}

    Note:
        "other" category includes Key coins (value=0) and any non-power-of-10 values
    """
    breakdown = {}
    other_count = 0

    for value, count in denomination_counts.items():
        # Check if value is a power of 10 (valid CloudCoin denomination)
        if value > 0:
            log_value = math.log10(value)
            # Check if log10 is approximately an integer (within floating point tolerance)
            is_power_of_10 = abs(log_value - round(log_value)) < 1e-9

            if is_power_of_10:
                # Valid CloudCoin denomination - use appropriate string representation
                if value < 1:
                    # Fractional value - use decimal notation
                    key = str(value)
                elif value == int(value):
                    # Whole number - use integer notation
                    key = str(int(value))
                else:
                    # Edge case - use float notation
                    key = str(value)

                breakdown[key] = count
            else:
                # Non-power-of-10 value
                other_count += count
        else:
            # Key coins (value=0) or negative values
            other_count += count

    # Add "other" category if needed
    if other_count > 0:
        breakdown["other"] = other_count

    return breakdown


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def scan_wallet_folders(bank_path: str, fracked_path: str, limbo_path: Optional[str] = None,
                       logger_handle=None) -> Dict:
    """
    Scan multiple wallet folders and return comprehensive balance information.

    Args:
        bank_path: Path to Bank folder (authenticated coins)
        fracked_path: Path to Fracked folder (coins needing fix)
        limbo_path: Optional path to Limbo folder (uncertain state coins)
        logger_handle: Optional logger handle

    Returns:
        Dict with balance information:
        {
            "total_coins": int,
            "total_value": float,
            "folders": {
                "bank_coins": int,
                "bank_value": float,
                "fracked_coins": int,
                "fracked_value": float,
                "limbo_coins": int,       # if limbo_path provided
                "limbo_value": float      # if limbo_path provided
            },
            "denominations": {
                "bank": {"1": count, "100": count, ...},
                "fracked": {"1": count, "100": count, ...},
                "limbo": {"1": count, "100": count, ...}  # if limbo_path provided
            }
        }
    """
    # Scan Bank folder
    bank_value, bank_count, bank_denoms = scan_coins_in_directory(bank_path, logger_handle)

    # Scan Fracked folder
    fracked_value, fracked_count, fracked_denoms = scan_coins_in_directory(fracked_path, logger_handle)

    # Scan Limbo folder if provided
    limbo_value, limbo_count, limbo_denoms = 0.0, 0, {}
    if limbo_path:
        limbo_value, limbo_count, limbo_denoms = scan_coins_in_directory(limbo_path, logger_handle)

    # Calculate totals
    total_value = bank_value + fracked_value + limbo_value
    total_coins = bank_count + fracked_count + limbo_count

    # Build result
    result = {
        "total_coins": total_coins,
        "total_value": total_value,
        "folders": {
            "bank_coins": bank_count,
            "bank_value": bank_value,
            "fracked_coins": fracked_count,
            "fracked_value": fracked_value
        },
        "denominations": {
            "bank": get_denomination_breakdown(bank_denoms),
            "fracked": get_denomination_breakdown(fracked_denoms)
        }
    }

    # Add Limbo if scanned
    if limbo_path:
        result["folders"]["limbo_coins"] = limbo_count
        result["folders"]["limbo_value"] = limbo_value
        result["denominations"]["limbo"] = get_denomination_breakdown(limbo_denoms)

    return result

def load_coin_metadata(filepath: str) -> Optional[Dict]:
    """
    Look inside at Byte 16 for POWN status (25 nibbles) and Byte 32 for SN/DN.
    Matches the supervisor's stable naming requirement (DN.SN.bin).
    
    Returns:
        Dictionary with denomination, serial_number, pown_string, value, and file_path
    """
    import os
    import struct
    
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # Format 9 coins are exactly 439 bytes
        if len(data) < 439:
            return None

        # 1. PARSE POWN STATUS (Starts at Byte 16)
        # 13 bytes contain 26 nibbles. The first 25 represent RAIDA 0-24.
        pown_bytes = data[16:29]
        pown_string = ""
        for i in range(25):
            # Extract high nibble for even indices, low nibble for odd indices
            byte_val = pown_bytes[i // 2]
            nibble = (byte_val >> 4) if (i % 2 == 0) else (byte_val & 0x0F)
            
            # RAIDA Status Mapping: 1=pass (p), 0=fail (f), 2=unknown (u)
            if nibble == 1: 
                pown_string += 'p'
            elif nibble == 0: 
                pown_string += 'f'
            else: 
                pown_string += 'u'

        # 2. PARSE BODY (Starts at Byte 32)
        # Offset 34: Denomination (1 byte signed int)
        # Offset 35: Serial Number (4 bytes big-endian)
        denomination_code = struct.unpack('b', data[34:35])[0]
        serial_number = struct.unpack('>I', data[35:39])[0]

        return {
            'denomination': denomination_code,
            'serial_number': serial_number,
            'pown_string': pown_string,
            'value': parse_denomination_code(denomination_code),
            'file_path': filepath
        }
    except Exception:
        return None
    



def load_coin_from_file(file_path: str) -> Optional[Any]:
    """
    Loads full coin data including ANs and internal POWN status.
    Required for payment orchestrations (Cmd 82).
    """
    import struct
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 439:
            return None

        # Parse internal POWN from Byte 16

        pown_bytes = data[16:29]
        pown_str = ""
        for i in range(25):
            byte_val = pown_bytes[i // 2]
            nibble = (byte_val >> 4) if (i % 2 == 0) else (byte_val & 0x0F)
            
            # Correct nibble decoding (matches cloudcoin.py _char_to_pown_nibble)
            if nibble == 0xA:      # 10 = POWN_PASS
                pown_str += 'p'
            elif nibble == 0xF:    # 15 = POWN_FAIL
                pown_str += 'f'
            elif nibble == 0xC:    # 12 = POWN_NO_RESPONSE
                pown_str += 'n'
            elif nibble == 0x0:    # 0 = POWN_UNTRIED
                pown_str += 'u'
            else:
                pown_str += 'u'    # Unknown status

        # Parse SN/DN from Byte 32 preamble
        denomination = struct.unpack('b', data[34:35])[0]
        serial_number = struct.unpack('>I', data[35:39])[0]

        # Parse 25 Authenticity Numbers (ANs)
        # ANs start at Offset 39 (Byte 32 + 7 bytes of header)
        ans = []
        for i in range(25):
            start = 39 + (i * 16)
            ans.append(data[start : start + 16])

        # Create a simple object to match the expected coin interface
        # FIXED: Added 'serial_number' alias to match 'sn' for compatibility
        return type('Coin', (), {
            'denomination': denomination,
            'sn': serial_number,             # Used by some modules
            'serial_number': serial_number,  # <--- FIXED: Added for coin_break compatibility
            'ans': ans,
            'pown_string': pown_str,
            'file_path': file_path
        })()
    except Exception:
        return None


def get_coins_by_value(wallet_path: str, target_value: float, identity_sn: int = None) -> List:
    """
    Get coins from wallet that total the target value.
    
    STRATEGY: 
    1. Only select coins with 25/25 pass status (no 'f', 'u', or 'n' in POWN)
    2. Greedy fit - largest coins that FIT first
    3. Minimizes overpayment and avoids breaking coins
    """
    import os
    from coin_scanner import parse_denomination_code, load_coin_from_file
    
    bank_path = os.path.join(wallet_path, "Bank")
    
    if not os.path.exists(bank_path):
        return []
    
    all_coins = []
    
    # for filename in os.listdir(bank_path):
    #     if not filename.endswith('.bin'):
    #         continue
            
    #     file_path = os.path.join(bank_path, filename)

    # Use scandir for fresh directory reading (avoids Windows caching)
    try:
        entries = list(os.scandir(bank_path))
    except OSError:
        return []
    
    for entry in entries:
        if not entry.name.endswith('.bin'):
            continue
            
        file_path = entry.path
        coin = load_coin_from_file(file_path)
        
        if coin is None:
            continue
        
        # Skip identity coin
        if identity_sn and coin.serial_number == int(identity_sn):
            continue
        
        # Check coin health - this has the same grading implementation as the go code 
        pown = getattr(coin, 'pown_string', '') or ''
        pass_count = pown.count('p')
        fail_count = pown.count('f')
        error_count = pown.count('e')
        
        # Need at least 14 passes (MIN_PASSED_NUM_TO_BE_AUTHENTIC) this variable is same as used in the go code
        if pass_count < 14:
            continue
        
        # # If has fails or errors, it's fracked (not authentic)
        # if fail_count > 0 or error_count > 0:
        #     continue
        
        # 'n' (no response) and 'u' (untried) are IGNORED - coin is still authentic
        # This matches Go behavior where only 'f' and 'e' disqualify a coin
        
        coin_value = parse_denomination_code(coin.denomination)
        all_coins.append((coin, coin_value))

        print(f"[DEBUG] Found coin: SN={coin.serial_number}, DN={coin.denomination}, value={coin_value}, pown={pown[:10]}...") # just printing the coins and their pown status for debugging

    # Sort DESCENDING (Largest First)
    all_coins.sort(key=lambda x: x[1], reverse=True)
    
    selected_coins = []
    remaining = target_value
    
    # GREEDY SELECTION: Only take coins that FIT within remaining
    for coin, val in all_coins:
        if val <= remaining + 0.00000001:  # Coin fits
            selected_coins.append(coin)
            remaining -= val
            
            if remaining <= 0.00000001:  # Target reached exactly
                return selected_coins
    
    # If we still have remaining > 0, we need ONE larger coin
    if remaining > 0.00000001:
        for coin, val in reversed(all_coins):  # Smallest to largest
            if coin not in selected_coins and val >= remaining:
                selected_coins.append(coin)
                return selected_coins
    
    # Check if we have enough total
    total = sum(parse_denomination_code(c.denomination) for c in selected_coins)
    if total >= target_value - 0.00000001:
        return selected_coins

    # Insufficient funds (no healthy coins available)
    return []

def find_identity_coin(wallet_path: str, target_sn: Optional[int] = None) -> Optional[dict]:
    """
    Scans wallet for an identity coin. 
    FIX: Uses load_coin_from_file to ensure ANs are loaded.
    """
    import os
    # Use the FULL loader, not the metadata loader
    from src.coin_scanner import load_coin_from_file 
    
    if not os.path.exists(wallet_path): return None
    
    for filename in os.listdir(wallet_path):
        if not filename.endswith('.bin'): continue
        
        # Load the FULL coin (including ANs)
        coin_obj = load_coin_from_file(os.path.join(wallet_path, filename))
        
        if coin_obj:
            # If target_sn is None, take the first coin, else match SN
            if target_sn is None or coin_obj.serial_number == int(target_sn):
                # Convert the Object back to a Dict to match existing API expectations
                # or return the object if your handlers support it.
                return {
                    'serial_number': coin_obj.serial_number,
                    'denomination': coin_obj.denomination,
                    'ans': coin_obj.ans,  # <--- This is what was missing!
                    'pown_string': coin_obj.pown_string,
                    'file_path': coin_obj.file_path
                }
    return None

# ============================================================================
# TESTING / MAIN
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("=" * 60)
    print("CloudCoin Scanner Test")
    print("=" * 60)

    # Test denomination code conversion
    print("\nDenomination Code Tests:")
    test_codes = [-1, 0, 1, 2, 3, 11]
    for code in test_codes:
        value = parse_denomination_code(code)
        print(f"  Code {code:2d} => Value {value}")

    # Test directory scanning if path provided
    import sys
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
        print(f"\nScanning directory: {test_path}")
        total_val, count, denoms = scan_coins_in_directory(test_path)
        print(f"  Total coins: {count}")
        print(f"  Total value: {total_val}")
        print(f"  Denominations: {denoms}")
        print(f"  Breakdown: {get_denomination_breakdown(denoms)}")
