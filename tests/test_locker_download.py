"""
Test script for the new Locker DOWNLOAD command (85).

This tests the updated locker_download.py with the new single-command
workflow that replaces PEEK + REMOVE.

Usage:
    python test_locker_download.py <locker_key>
    python test_locker_download.py 57D-P4R4
"""

import sys
import os
import asyncio

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from locker_download import (
    download_from_locker,
    LockerDownloadResult,
    compute_coin_an,
    RAIDA_COUNT
)
from key_manager import get_keys_from_locker_code
import hashlib


def test_key_derivation(locker_key: str):
    """Test that key derivation works with the string locker key."""
    print("\n" + "=" * 60)
    print("TEST 1: Key Derivation")
    print("=" * 60)

    try:
        keys = get_keys_from_locker_code(locker_key)
        print(f"  Input locker key: {locker_key}")
        print(f"  Generated {len(keys)} keys")

        # Check 0xFF padding
        for i, key in enumerate(keys):
            if key[12:16] != b'\xff\xff\xff\xff':
                print(f"  ERROR: Key {i} missing 0xFF padding!")
                return False

        print(f"  Sample key 0: {keys[0].hex()}")
        print(f"  Sample key 12: {keys[12].hex()}")
        print("  All keys have proper 0xFF padding")
        print("  PASSED")
        return True

    except Exception as e:
        print(f"  FAILED: {e}")
        return False


def test_an_computation():
    """Test that AN computation matches expected formula."""
    print("\n" + "=" * 60)
    print("TEST 2: AN Computation")
    print("=" * 60)

    # Test with known values
    test_seed = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    test_sn = 12345678
    test_raida = 5

    # Expected: MD5("{raida_id}{serial_number}{seed_hex}")
    expected_input = f"{test_raida}{test_sn}{test_seed.hex()}"
    expected_an = hashlib.md5(expected_input.encode('ascii')).digest()
    actual_an = compute_coin_an(test_raida, test_sn, test_seed)

    print(f"  RAIDA ID: {test_raida}")
    print(f"  Serial Number: {test_sn}")
    print(f"  Seed: {test_seed.hex()}")
    print(f"  Input string: {expected_input[:50]}...")
    print(f"  Expected AN: {expected_an.hex()}")
    print(f"  Actual AN:   {actual_an.hex()}")

    if actual_an == expected_an:
        print("  PASSED")
        return True
    else:
        print("  FAILED: AN mismatch!")
        return False


async def test_locker_download(locker_key: str, wallet_path: str):
    """Test the actual locker download."""
    print("\n" + "=" * 60)
    print("TEST 3: Locker Download")
    print("=" * 60)

    print(f"  Locker key: {locker_key}")
    print(f"  Wallet path: {wallet_path}")
    print(f"  Connecting to {RAIDA_COUNT} RAIDA servers...")
    print()

    # The locker key string is used directly by get_keys_from_locker_code
    # We need to convert it for download_from_locker which expects bytes
    # But looking at the code, it actually accepts the string directly
    # through get_keys_from_locker_code

    # Actually, download_from_locker expects bytes (8 bytes locker code)
    # But the key_manager can accept string. Let me check what format is needed.

    # Looking at the code, download_from_locker uses locker_code[:8] as bytes
    # But get_keys_from_locker_code accepts string or bytes
    # The locker key "57D-P4R4" is a string representation

    # Let me convert it to bytes by encoding as UTF-8 (taking first 8 bytes)
    locker_code_bytes = locker_key.encode('utf-8')[:8]

    print(f"  Locker code as bytes: {locker_code_bytes.hex()}")

    result, coins = await download_from_locker(
        locker_code=locker_code_bytes,
        wallet_path=wallet_path,
        db_handle=None,
        logger_handle=None
    )

    print()
    print(f"  Result: {result.name} ({result.value})")
    print(f"  Coins downloaded: {len(coins)}")

    if coins:
        total_value = 0
        for coin in coins:
            denom_value = 10.0 ** coin.denomination if coin.denomination != 11 else 0
            total_value += denom_value
            print(f"    - SN={coin.serial_number}, Denom={coin.denomination}, "
                  f"POWN={coin.pown_string[:10]}...")
        print(f"  Total value: {total_value}")

    if result == LockerDownloadResult.SUCCESS:
        print("  PASSED")
        return True
    elif result == LockerDownloadResult.ERR_LOCKER_EMPTY:
        print("  Locker was empty (might be already used)")
        return False
    elif result == LockerDownloadResult.ERR_INSUFFICIENT_RESPONSES:
        print("  Not enough RAIDA responses (network issue)")
        return False
    else:
        print(f"  FAILED: {result.name}")
        return False


def remove_used_key(locker_key: str, keys_file: str):
    """Remove the used locker key from the file."""
    print("\n" + "=" * 60)
    print("Removing used locker key from file")
    print("=" * 60)

    try:
        with open(keys_file, 'r') as f:
            lines = f.readlines()

        # Remove the key
        new_lines = [line for line in lines if line.strip() != locker_key]

        if len(new_lines) < len(lines):
            with open(keys_file, 'w') as f:
                f.writelines(new_lines)
            print(f"  Removed '{locker_key}' from {keys_file}")
            print(f"  Remaining keys: {len(new_lines)}")
        else:
            print(f"  Key '{locker_key}' not found in file")

    except Exception as e:
        print(f"  Error removing key: {e}")


async def main():
    # Get locker key from command line or use default
    if len(sys.argv) > 1:
        locker_key = sys.argv[1]
    else:
        locker_key = "57D-P4R4"

    print("=" * 60)
    print("Locker Download Test - Command 85")
    print("=" * 60)
    print(f"Testing with locker key: {locker_key}")

    # Test 1: Key derivation
    if not test_key_derivation(locker_key):
        print("\nKey derivation failed, aborting.")
        return 1

    # Test 2: AN computation
    if not test_an_computation():
        print("\nAN computation failed, aborting.")
        return 1

    # Test 3: Actual download
    wallet_path = os.path.join(os.path.dirname(__file__), "Data", "Wallets", "Default")
    os.makedirs(os.path.join(wallet_path, "Fracked"), exist_ok=True)

    download_success = await test_locker_download(locker_key, wallet_path)

    # If download was successful, remove the key from the file
    if download_success:
        keys_file = os.path.join(
            os.path.dirname(__file__),
            "Data", "LockerKeys", "1.locker_keys.txt"
        )
        remove_used_key(locker_key, keys_file)

    print("\n" + "=" * 60)
    if download_success:
        print("ALL TESTS PASSED!")
    else:
        print("Download test failed or locker was empty")
    print("=" * 60)

    return 0 if download_success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
