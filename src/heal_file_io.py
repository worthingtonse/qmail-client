"""
heal_file_io.py - CloudCoin Binary File I/O for Healing Operations

This module handles reading and writing CloudCoin .bin files,
including the CloudCoinBin dataclass and file operations.

Author: Claude Opus 4.5
Version: 1.0.0
Date: 2025-12-26

Binary File Format (439 bytes for single coin without PANs):
    - File Header: 32 bytes
        - Byte 0: File Format (0x09)
        - Byte 1: Reserved (0x01)
        - Bytes 2-3: Coin ID (0x0006, big-endian)
        - Byte 4: Experimental (0x00)
        - Byte 5: Encryption Type (0x00 = none)
        - Bytes 6-7: Token Count (big-endian, 0x0001 for single coin)
        - Bytes 8-14: Password Hash (zeros)
        - Byte 15: State flag (0x01 if PANs included)
        - Bytes 16-28: POWN bytes (13 bytes, 25 nibbles)
        - Bytes 29-31: Padding (0x99)
    - Coin Header: 7 bytes
        - Byte 0: Split (0x00)
        - Byte 1: Shard (0x00)
        - Byte 2: Denomination (signed int8)
        - Bytes 3-6: Serial number (uint32, big-endian)
    - Coin Body: 400 bytes
        - 25 ANs, 16 bytes each
    - Optional: 400 more bytes for PANs (limbo coins)
"""

import os
import struct
import threading
import logging
from typing import List, Tuple, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger("heal_file_io")

# Import from heal_protocol
try:
    from heal_protocol import (
        RAIDA_COUNT, AN_SIZE, COIN_ID, HealErrorCode,
        QUORUM_REQUIRED, ENC_NONE,
        encode_pown_bytes, decode_pown_bytes
    )
except ImportError:
    from heal_protocol import (
        RAIDA_COUNT, AN_SIZE, COIN_ID, HealErrorCode,
        QUORUM_REQUIRED, ENC_NONE,
        encode_pown_bytes, decode_pown_bytes
    )

# Import wallet structure initialization
try:
    from wallet_structure import initialize_wallet_structure
except ImportError:
    from wallet_structure import initialize_wallet_structure


# ============================================================================
# FILE FORMAT CONSTANTS
# ============================================================================

FILE_HEADER_SIZE = 32
COIN_HEADER_SIZE = 7  # Split(1) + Shard(1) + Denomination(1) + SerialNumber(4) = 7 bytes
COIN_BODY_SIZE = AN_SIZE * RAIDA_COUNT  # 400 bytes
SINGLE_COIN_FILE_SIZE = FILE_HEADER_SIZE + COIN_HEADER_SIZE + COIN_BODY_SIZE  # 439 bytes

# Wallet Folder Names
FOLDER_BANK = "Bank"
FOLDER_FRACKED = "Fracked"
FOLDER_LIMBO = "Limbo"
FOLDER_COUNTERFEIT = "Counterfiet"
FOLDER_SUSPECT = "Suspect"
FOLDER_GRADE = "Grade"


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CloudCoinBin:
    """
    Represents a CloudCoin loaded from a .bin file.

    This is the primary data structure for coin operations in the heal module.
    Designed for easy conversion to C struct.

    Attributes:
        denomination: Signed int8 (-7 to 11), where 10^denom = value
        serial_number: Unique coin identifier (uint32)
        ans: List of 25 Authenticity Numbers (16 bytes each)
        pans: List of 25 Proposed ANs (for limbo coins)
        pown: 25-character status string
        file_path: Source file path
        has_pans: Whether this coin has PANs (limbo state)
    """
    denomination: int = 0
    serial_number: int = 0
    ans: List[bytes] = field(default_factory=lambda: [bytes(AN_SIZE)] * RAIDA_COUNT)
    pans: List[bytes] = field(default_factory=lambda: [bytes(AN_SIZE)] * RAIDA_COUNT)
    pown: str = 'u' * RAIDA_COUNT
    file_path: str = ""
    has_pans: bool = False

    def get_value(self) -> float:
        """Calculate coin value from denomination code."""
        if self.denomination == 11:  # Key/NFT coin
            return 0.0
        return 10.0 ** self.denomination

    def get_fracked_raida(self) -> List[int]:
        """Return list of RAIDA indices where coin is fracked (failed)."""
        return [i for i, char in enumerate(self.pown) if char == 'f']

    def get_passed_raida(self) -> List[int]:
        """Return list of RAIDA indices where coin is authenticated."""
        return [i for i, char in enumerate(self.pown) if char == 'p']

    def get_grade_status(self) -> str:
        """
        Determine coin status based on POWN string.

        Returns:
            'authentic' - 13+ pass, 0 fail, 0 unknown (perfect coin)
            'fracked' - 13+ pass, but some fail or unknown (needs healing)
            'counterfeit' - < 13 pass (cannot be healed)
            'limbo' - too many unknowns to determine
        """
        pass_count = self.pown.count('p')
        fail_count = self.pown.count('f')
        unknown_count = self.pown.count('u')

        if pass_count >= QUORUM_REQUIRED:
            # Has quorum (13+)
            if fail_count > 0 or unknown_count > 0:
                # Has fails or unknowns → fracked
                return 'fracked'
            else:
                # All 25 are 'p' → authentic
                return 'authentic'
        elif fail_count >= QUORUM_REQUIRED:
            # More than 13 fails → counterfeit
            return 'counterfeit'
        else:
            # Not enough passes or fails → limbo
            return 'limbo'

    def update_pown_char(self, raida_id: int, status: str) -> None:
        """Update POWN string at specified RAIDA position."""
        if 0 <= raida_id < RAIDA_COUNT:
            pown_list = list(self.pown)
            pown_list[raida_id] = status
            self.pown = ''.join(pown_list)

    def count_fracked(self) -> int:
        """Return count of fracked (failed) RAIDA positions."""
        return self.pown.count('f')

    def count_passed(self) -> int:
        """Return count of passed RAIDA positions."""
        return self.pown.count('p')


# ============================================================================
# FILE READ OPERATIONS
# ============================================================================

def read_coin_file(file_path: str) -> Tuple[HealErrorCode, Optional[CloudCoinBin]]:
    """
    Read a CloudCoin from a .bin file.

    File format:
        - Bytes 0-31: File header (32 bytes)
        - Bytes 32-38: Coin header (7 bytes)
        - Bytes 39-438: Coin body - 25 ANs (400 bytes)
        - Optional: 400 more bytes for PANs if limbo coin

    Args:
        file_path: Path to .bin file

    Returns:
        Tuple of (error_code, CloudCoinBin or None)
    """
    try:
        if not os.path.exists(file_path):
            return HealErrorCode.ERR_FILE_NOT_FOUND, None

        file_size = os.path.getsize(file_path)
        if file_size < SINGLE_COIN_FILE_SIZE:
            return HealErrorCode.ERR_INVALID_FILE, None

        with open(file_path, 'rb') as f:
            # Read file header (32 bytes)
            file_header = f.read(FILE_HEADER_SIZE)
            if len(file_header) < FILE_HEADER_SIZE:
                return HealErrorCode.ERR_INVALID_FILE, None

            # Parse POWN from file header (bytes 16-28)
            pown_bytes = file_header[16:29]
            pown_string = decode_pown_bytes(pown_bytes)

            # Check if PANs are included (byte 15, state flag)
            has_pans = (file_header[15] & 0x01) == 1

            # Read coin header (7 bytes: split + shard + denomination + serial_number)
            coin_header = f.read(COIN_HEADER_SIZE)
            if len(coin_header) < COIN_HEADER_SIZE:
                return HealErrorCode.ERR_INVALID_FILE, None

            # Parse coin header
            # Byte 0: Split, Byte 1: Shard, Byte 2: Denomination, Bytes 3-6: Serial Number
            denomination = struct.unpack('b', bytes([coin_header[2]]))[0]  # Signed int8
            serial_number = struct.unpack('>I', coin_header[3:7])[0]

            # Read 25 ANs (400 bytes)
            ans = []
            for i in range(RAIDA_COUNT):
                an = f.read(AN_SIZE)
                if len(an) < AN_SIZE:
                    return HealErrorCode.ERR_INVALID_FILE, None
                ans.append(an)

            # Read PANs if present
            pans = [bytes(AN_SIZE)] * RAIDA_COUNT
            if has_pans and file_size >= SINGLE_COIN_FILE_SIZE + COIN_BODY_SIZE:
                for i in range(RAIDA_COUNT):
                    pan = f.read(AN_SIZE)
                    if len(pan) >= AN_SIZE:
                        pans[i] = pan

            coin = CloudCoinBin(
                denomination=denomination,
                serial_number=serial_number,
                ans=ans,
                pans=pans,
                pown=pown_string,
                file_path=file_path,
                has_pans=has_pans
            )

            return HealErrorCode.SUCCESS, coin

    except IOError as e:
        return HealErrorCode.ERR_IO_ERROR, None


# ============================================================================
# FILE WRITE OPERATIONS
# ============================================================================

def write_coin_file(
    file_path: str,
    coin: CloudCoinBin,
    include_pans: bool = False
) -> HealErrorCode:
    """
    Write a CloudCoin to a .bin file.

    Args:
        file_path: Path to write .bin file
        coin: CloudCoinBin object to write
        include_pans: Whether to include PANs (for limbo coins)

    Returns:
        HealErrorCode
    """
    try:
        # Build file header (32 bytes)
        file_header = bytearray(FILE_HEADER_SIZE)
        file_header[0] = 0x09  # File Format version
        file_header[1] = 0x01  # Reserved
        file_header[2] = (COIN_ID >> 8) & 0xFF  # Coin ID high
        file_header[3] = COIN_ID & 0xFF  # Coin ID low
        file_header[4] = 0x00  # Experimental
        file_header[5] = ENC_NONE  # Encryption type
        file_header[6] = 0x00  # Token count high
        file_header[7] = 0x01  # Token count low (1 coin)
        # Bytes 8-14: Password hash (zeros)
        file_header[15] = 0x01 if include_pans else 0x00  # State flag

        # POWN bytes (bytes 16-28)
        pown_bytes = encode_pown_bytes(coin.pown)
        file_header[16:29] = pown_bytes

        # Padding
        file_header[29] = 0x99
        file_header[30] = 0x99
        file_header[31] = 0x99

        # Build coin header (7 bytes): Split(1) + Shard(1) + Denomination(1) + SerialNumber(4)
        coin_header = bytearray(COIN_HEADER_SIZE)
        coin_header[0] = 0x00  # Split
        coin_header[1] = 0x00  # Shard
        coin_header[2] = coin.denomination & 0xFF  # Denomination (signed int8)
        struct.pack_into('>I', coin_header, 3, coin.serial_number)

        # Ensure parent directory exists
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        # Write to file
        with open(file_path, 'wb') as f:
            f.write(file_header)
            f.write(coin_header)

            # Write 25 ANs
            for i in range(RAIDA_COUNT):
                if i < len(coin.ans) and coin.ans[i]:
                    an = coin.ans[i]
                    if len(an) >= AN_SIZE:
                        f.write(an[:AN_SIZE])
                    else:
                        f.write(an + bytes(AN_SIZE - len(an)))
                else:
                    f.write(bytes(AN_SIZE))

            # Write PANs if needed
            if include_pans:
                for i in range(RAIDA_COUNT):
                    if i < len(coin.pans) and coin.pans[i]:
                        pan = coin.pans[i]
                        if len(pan) >= AN_SIZE:
                            f.write(pan[:AN_SIZE])
                        else:
                            f.write(pan + bytes(AN_SIZE - len(pan)))
                    else:
                        f.write(bytes(AN_SIZE))

        return HealErrorCode.SUCCESS

    except IOError as e:
        return HealErrorCode.ERR_IO_ERROR


# ============================================================================
# FILE MANAGEMENT OPERATIONS
# ============================================================================

def generate_coin_filename(coin: CloudCoinBin) -> str:
    """
    Generate filename for a coin.

    Format: {denomination}.{serial_number}.bin

    Args:
        coin: CloudCoinBin object

    Returns:
        Filename string
    """
    return f"{coin.denomination}.{coin.serial_number}.bin"


def move_coin_file(coin: CloudCoinBin, dest_folder: str) -> HealErrorCode:
    """
    Move a coin file to a new folder while PRESERVING its original filename.
    FIXED: Uses the original filename instead of generating a new one based on SN.
    """
    if not coin.file_path or not os.path.exists(coin.file_path):
        return HealErrorCode.ERR_FILE_NOT_FOUND
 
    try:
        # FIXED: Capture the original filename from the existing path
        # Taaki Tabeen.bin heal hone ke baad bhi Tabeen.bin hi rahe
        original_filename = os.path.basename(coin.file_path)
        new_path = os.path.join(dest_folder, original_filename)
 
        # Ensure destination folder exists
        if not os.path.exists(dest_folder):
            os.makedirs(dest_folder, exist_ok=True)
 
        # Write coin to new location (to update the internal POWN bytes)
        err = write_coin_file(new_path, coin, include_pans=coin.has_pans)
        if err != HealErrorCode.SUCCESS:
            return err
 
        # Remove the old file only if the path has actually changed
        if os.path.exists(coin.file_path) and coin.file_path != new_path:
            os.remove(coin.file_path)
 
        # Update the object's path reference
        coin.file_path = new_path
        return HealErrorCode.SUCCESS
 
    except IOError as e:
        logger.error(f"IO Error moving coin file {coin.serial_number}: {e}")
        return HealErrorCode.ERR_IO_ERROR

def load_coins_from_folder(folder_path: str) -> Tuple[HealErrorCode, List[CloudCoinBin]]:
    """
    Load all .bin coin files from a folder.

    Args:
        folder_path: Path to folder containing .bin files

    Returns:
        Tuple of (error_code, list of CloudCoinBin)
    """
    coins = []

    if not os.path.exists(folder_path):
        return HealErrorCode.ERR_FILE_NOT_FOUND, coins

    try:
        for filename in os.listdir(folder_path):
            if filename.endswith('.bin'):
                file_path = os.path.join(folder_path, filename)
                err, coin = read_coin_file(file_path)
                if err == HealErrorCode.SUCCESS and coin:
                    coins.append(coin)

        return HealErrorCode.SUCCESS, coins

    except OSError as e:
        return HealErrorCode.ERR_IO_ERROR, coins


def get_wallet_folder(wallet_path: str, folder_name: str) -> str:
    """
    Get full path to a wallet subfolder.

    Args:
        wallet_path: Base wallet path
        folder_name: Subfolder name (e.g., FOLDER_BANK, FOLDER_FRACKED)

    Returns:
        Full path to subfolder
    """
    return os.path.join(wallet_path, folder_name)


# All required wallet subfolders
WALLET_FOLDERS = [
    FOLDER_BANK,
    FOLDER_FRACKED,
    FOLDER_LIMBO,
    FOLDER_COUNTERFEIT,
    FOLDER_SUSPECT,
    FOLDER_GRADE,
]


def ensure_wallet_folders_exist(wallet_path: str) -> HealErrorCode:
    """
    Ensure all required wallet folders exist, creating them if necessary.

    This should be called when the program starts or before any heal operation.

    Required folders:
        - Bank: Authenticated coins
        - Fracked: Coins with some failed RAIDA
        - Limbo: Coins with unknown status
        - Fraud: Counterfeit coins
        - Suspect: Suspicious coins
        - Grade: Coins pending grading

    Args:
        wallet_path: Path to wallet (e.g., Data/Wallets/Default)

    Returns:
        HealErrorCode.SUCCESS if all folders exist/created
        HealErrorCode.ERR_IO_ERROR if creation failed
    """
    try:
        # Create wallet path itself if it doesn't exist
        if not os.path.exists(wallet_path):
            os.makedirs(wallet_path, exist_ok=True)
            logger.info(f"Created wallet directory: {wallet_path}")

        # Create each subfolder
        for folder_name in WALLET_FOLDERS:
            folder_path = os.path.join(wallet_path, folder_name)
            if not os.path.exists(folder_path):
                os.makedirs(folder_path, exist_ok=True)
                logger.info(f"Created folder: {folder_path}")

        return HealErrorCode.SUCCESS

    except OSError as e:
        logger.error(f"Failed to create wallet folders: {e}")
        return HealErrorCode.ERR_IO_ERROR


def check_wallet_folders_exist(wallet_path: str) -> Tuple[bool, List[str]]:
    """
    Check if all required wallet folders exist.

    Args:
        wallet_path: Path to wallet

    Returns:
        Tuple of (all_exist: bool, missing_folders: List[str])
    """
    missing = []
    for folder_name in WALLET_FOLDERS:
        folder_path = os.path.join(wallet_path, folder_name)
        if not os.path.exists(folder_path):
            missing.append(folder_name)

    return len(missing) == 0, missing


def move_coin_to_fracked(coin: CloudCoinBin, wallet_path: str = "Data/Wallets/Default") -> bool:
    """
    Move a coin from Bank to Fracked folder within specified wallet.
    Works for both Default (payment) and Mailbox (identity) wallets.
    
    Args:
        coin: CloudCoinBin object
        wallet_path: Path to wallet (e.g., "Data/Wallets/Default" or "Data/Wallets/Mailbox")
    
    Returns:
        bool: True if moved successfully
    """
    import shutil
    import os
    
    bank_folder = os.path.join(wallet_path, "Bank")
    fracked_folder = os.path.join(wallet_path, "Fracked")
    
    source_file = os.path.join(bank_folder, coin.filename)
    dest_file = os.path.join(fracked_folder, coin.filename)
    
    if not os.path.exists(source_file):
        print(f"[WARN] Coin not found in Bank: {source_file}")
        return False
    
    try:
        os.makedirs(fracked_folder, exist_ok=True)
        shutil.move(source_file, dest_file)
        print(f"[INFO] Moved coin to Fracked: {coin.filename}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to move coin to Fracked: {e}")
        return False


def move_coin_to_bank(coin: CloudCoinBin, wallet_path: str = "Data/Wallets/Default") -> bool:
    """
    Move a healed coin from Fracked back to Bank folder within specified wallet.
    Works for both Default (payment) and Mailbox (identity) wallets.
    
    Args:
        coin: CloudCoinBin object
        wallet_path: Path to wallet
    
    Returns:
        bool: True if moved successfully
    """
    import shutil
    import os
    
    fracked_folder = os.path.join(wallet_path, "Fracked")
    bank_folder = os.path.join(wallet_path, "Bank")
    
    source_file = os.path.join(fracked_folder, coin.filename)
    dest_file = os.path.join(bank_folder, coin.filename)
    
    if not os.path.exists(source_file):
        print(f"[WARN] Coin not found in Fracked: {source_file}")
        return False
    
    try:
        os.makedirs(bank_folder, exist_ok=True)
        shutil.move(source_file, dest_file)
        print(f"[INFO] Moved healed coin to Bank: {coin.filename}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to move coin to Bank: {e}")
        return False


# ============================================================================
# SELF-TEST
# ============================================================================

if __name__ == "__main__":
    # Ensure wallet folders exist
    initialize_wallet_structure()

    import tempfile
    import shutil

    print("=" * 60)
    print("heal_file_io.py - Self Tests")
    print("=" * 60)

    # Create temp directory
    test_dir = tempfile.mkdtemp(prefix="heal_file_io_test_")
    print(f"\nUsing temp directory: {test_dir}")

    try:
        # Test 1: CloudCoinBin structure
        print("\n1. Testing CloudCoinBin structure...")
        coin = CloudCoinBin(
            denomination=1,
            serial_number=12345678,
            pown='pppppppppppppfffffuuuuuu'
        )
        assert coin.get_value() == 10.0
        assert len(coin.get_fracked_raida()) == 5
        assert len(coin.get_passed_raida()) == 13
        assert coin.get_grade_status() == 'fracked'
        print(f"   PASS: Value={coin.get_value()}, Fracked={coin.get_fracked_raida()}")

        # Test 2: Write and read coin file
        print("\n2. Testing file write/read cycle...")
        test_coin = CloudCoinBin(
            denomination=1,
            serial_number=99999999,
            pown='ppppppppppppppppppppppppp',
            ans=[os.urandom(16) for _ in range(25)]
        )
        test_file = os.path.join(test_dir, "test_coin.bin")

        err = write_coin_file(test_file, test_coin)
        assert err == HealErrorCode.SUCCESS, f"Write failed: {err}"

        err, read_coin = read_coin_file(test_file)
        assert err == HealErrorCode.SUCCESS, f"Read failed: {err}"
        assert read_coin.denomination == test_coin.denomination
        assert read_coin.serial_number == test_coin.serial_number
        assert read_coin.pown == test_coin.pown

        for i in range(25):
            assert read_coin.ans[i] == test_coin.ans[i], f"AN mismatch at {i}"

        print(f"   PASS: File size = {os.path.getsize(test_file)} bytes")

        # Test 3: Generate filename
        print("\n3. Testing filename generation...")
        filename = generate_coin_filename(test_coin)
        expected = f"1.99999999.bin"
        assert filename == expected, f"Filename mismatch: {filename}"
        print(f"   PASS: {filename}")

        # Test 4: Move coin file
        print("\n4. Testing move coin file...")
        dest_folder = os.path.join(test_dir, "Bank")
        err = move_coin_file(read_coin, dest_folder)
        assert err == HealErrorCode.SUCCESS
        assert os.path.exists(read_coin.file_path)
        assert "Bank" in read_coin.file_path
        print(f"   PASS: Moved to {read_coin.file_path}")

        # Test 5: Load coins from folder
        print("\n5. Testing load coins from folder...")
        err, coins = load_coins_from_folder(dest_folder)
        assert err == HealErrorCode.SUCCESS
        assert len(coins) == 1
        print(f"   PASS: Loaded {len(coins)} coins")

        print("\n" + "=" * 60)
        print("All tests passed!")
        print("=" * 60)

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\nCleaned up: {test_dir}")
