#!/usr/bin/env python3
"""
bin_to_key_converter.py - CloudCoin Binary to Key File Converter

Converts CloudCoin .bin files to .key files containing Authenticity Numbers.

File naming format: <CoinID><Denomination><SerialNumber>.key
Example: 00060300273645.key

Key file content: 25 lines, each containing one AN as a hex string (32 chars)
Line 0: AN[0]
Line 1: AN[1]
...
Line 24: AN[24]

Author: Claude Sonnet 4.5
Date: 2025-12-12
"""

import os
import sys
import struct
from pathlib import Path


def list_bin_files(directory='.'):
    """
    Scan directory for .bin files and return list.

    Args:
        directory: Directory to scan (default: current directory)

    Returns:
        List of .bin file paths
    """
    bin_files = []
    for file in Path(directory).iterdir():
        if file.is_file() and file.suffix.lower() == '.bin':
            bin_files.append(file)

    return sorted(bin_files)


def extract_coin_data(bin_file_path):
    """
    Extract coin data from binary file.

    File structure (based on user's indices):
    - Coin ID: bytes 2-3 (should be 0x0006)
    - Denomination: byte 34 (coin header byte 2)
    - Serial Number: bytes 35-38 (coin header bytes 3-6)
    - AN 0: bytes 39-54 (16 bytes)
    - AN 1: bytes 55-70 (16 bytes)
    - ...
    - AN 24: bytes 439-454 (16 bytes)

    Args:
        bin_file_path: Path to .bin file

    Returns:
        Tuple of (coin_id, denomination, serial_number, ans_list)
        or None on error
    """
    try:
        with open(bin_file_path, 'rb') as f:
            data = f.read()

        # Validate minimum file size
        # File header (32) + Coin header (7) + ANs (25*16=400) = 439 bytes minimum
        if len(data) < 439:
            print(f"Error: File too small ({len(data)} bytes, need at least 439)")
            return None

        # Extract Coin ID (bytes 2-3, big-endian)
        coin_id = struct.unpack('>H', data[2:4])[0]

        # Verify Coin ID is 0x0006 (CloudCoin)
        if coin_id != 0x0006:
            print(f"Warning: Coin ID is 0x{coin_id:04X}, expected 0x0006 (CloudCoin)")

        # File header is 32 bytes, coin header starts at byte 32
        # Coin header structure:
        #   Byte 0 (file byte 32): Split
        #   Byte 1 (file byte 33): Shard
        #   Byte 2 (file byte 34): Denomination
        #   Bytes 3-6 (file bytes 35-38): Serial Number

        # Extract Denomination (byte 34 - coin header byte 2)
        denomination = data[34]

        # Extract Serial Number (bytes 35-38 - coin header bytes 3-6)
        # Serial number is 4 bytes, big-endian unsigned int
        serial_number = struct.unpack('>I', data[35:39])[0]

        # Extract 25 Authenticity Numbers (each 16 bytes)
        # ANs start at byte 39 (after 32-byte file header + 7-byte coin header)
        ans = []
        an_start = 39

        for i in range(25):
            an_offset = an_start + (i * 16)
            an_bytes = data[an_offset:an_offset + 16]

            if len(an_bytes) < 16:
                print(f"Error: Incomplete AN at index {i}")
                return None

            # Convert to hex string (32 characters)
            an_hex = an_bytes.hex().upper()
            ans.append(an_hex)

        return (coin_id, denomination, serial_number, ans)

    except Exception as e:
        print(f"Error reading file: {e}")
        return None


def convert_to_key_file(bin_file_path, output_dir='.'):
    """
    Convert .bin file to .key file.

    Args:
        bin_file_path: Path to input .bin file
        output_dir: Directory for output .key file

    Returns:
        Path to created .key file, or None on error
    """
    # Extract coin data
    result = extract_coin_data(bin_file_path)
    if result is None:
        return None

    coin_id, denomination, serial_number, ans = result

    # Build key filename: <CoinID><Denomination><SerialNumber>.key
    # CoinID: 4 hex chars (2 bytes)
    # Denomination: 2 hex chars (1 byte)
    # SerialNumber: 8 hex chars (4 bytes)
    key_filename = f"{coin_id:04X}{denomination:02X}{serial_number:08X}.key"
    key_file_path = Path(output_dir) / key_filename

    # Write ANs to file (one per line)
    try:
        with open(key_file_path, 'w') as f:
            for an in ans:
                f.write(an + '\n')

        print(f"✓ Created: {key_file_path}")
        print(f"  Coin ID: 0x{coin_id:04X}")
        print(f"  Denomination: {denomination}")
        print(f"  Serial Number: {serial_number}")
        print(f"  ANs: {len(ans)} lines")

        return key_file_path

    except Exception as e:
        print(f"Error writing key file: {e}")
        return None


def main():
    """Main program loop."""
    print("=" * 70)
    print("CloudCoin Binary to Key File Converter")
    print("=" * 70)
    print()

    # Get current directory
    current_dir = os.getcwd()
    print(f"Scanning directory: {current_dir}")
    print()

    # List all .bin files
    bin_files = list_bin_files(current_dir)

    if not bin_files:
        print("No .bin files found in current directory.")
        print()
        input("Press Enter to exit...")
        return

    # Display enumerated list
    print(f"Found {len(bin_files)} .bin file(s):")
    print()
    for idx, file_path in enumerate(bin_files):
        file_size = file_path.stat().st_size
        print(f"  [{idx}] {file_path.name} ({file_size:,} bytes)")

    print()
    print("-" * 70)

    # Get user input
    while True:
        try:
            user_input = input("\nEnter file index to convert (or 'q' to quit): ").strip()

            if user_input.lower() in ('q', 'quit', 'exit'):
                print("Exiting...")
                return

            # Parse index
            index = int(user_input)

            if index < 0 or index >= len(bin_files):
                print(f"Error: Index must be between 0 and {len(bin_files) - 1}")
                continue

            # Convert selected file
            selected_file = bin_files[index]
            print()
            print(f"Converting: {selected_file.name}")
            print("-" * 70)

            result = convert_to_key_file(selected_file, current_dir)

            if result:
                print()
                print("Conversion successful!")
            else:
                print()
                print("Conversion failed.")

            print()
            print("-" * 70)

            # Ask if user wants to convert another
            another = input("\nConvert another file? (y/n): ").strip().lower()
            if another not in ('y', 'yes'):
                print("Exiting...")
                return

        except ValueError:
            print("Error: Please enter a valid number or 'q' to quit")
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting...")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
