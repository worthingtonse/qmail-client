"""
test_peek.py - PEEK Command Test

Tests the PEEK command to check for mail in a mailbox.
Uses real key files for authentication.

Key file format:
  - Filename: {coin_id:4}{denomination:2}{serial_number:6}.key
  - Example: 00060300001AEB.key -> coin_id=6, denom=3, sn=6891
  - Contents: 25 lines of 32-char hex strings (16-byte ANs, one per RAIDA)

Author: Claude Opus 4.5
Version: 1.0.0

Run with: python tests/test_peek.py
"""

import sys
import os
import socket
import time
import struct
import json
import urllib.request
import ssl
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
DATA_DIR = os.path.join(BASE_DIR, 'Data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')

# Key file paths
SENDER_KEY_PATH = os.path.join(DATA_DIR, 'Wallets', 'Sender', 'Bank', '00060300001AEA.key')
RECEIVER_KEY_PATH = os.path.join(DATA_DIR, 'Wallets', 'Receiver', 'Bank', '00060300001AEB.key')

# QMail server directory URL
QMAIL_SERVERS_URL = "https://raida11.cloudcoin.global/service/qmail_servers"

# Timeouts
CONNECT_TIMEOUT_MS = 10000
READ_TIMEOUT_MS = 30000


# ============================================================================
# KEY FILE PARSING
# ============================================================================

@dataclass
class WalletKey:
    """Parsed wallet key file."""
    coin_id: int
    denomination: int
    serial_number: int
    ans: List[bytes]  # 25 ANs, one per RAIDA server
    file_path: str


def parse_key_filename(filename: str) -> Tuple[int, int, int]:
    """
    Parse key filename to extract coin_id, denomination, serial_number.

    Format: {coin_id:4}{denomination:2}{serial_number:6}.key
    Example: 00060300001AEB.key -> (6, 3, 6891)
    """
    basename = os.path.basename(filename)
    name = basename.replace('.key', '')

    if len(name) != 14:
        raise ValueError(f"Invalid key filename format: {basename} (expected 14 hex chars)")

    coin_id = int(name[0:4], 16)
    denomination = int(name[4:6], 16)
    serial_number = int(name[6:14], 16)

    return coin_id, denomination, serial_number


def load_key_file(path: str) -> WalletKey:
    """
    Load and parse a wallet key file.

    Returns:
        WalletKey with parsed credentials and ANs
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")

    # Parse filename
    coin_id, denomination, serial_number = parse_key_filename(path)

    # Read ANs
    ans = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and len(line) == 32:
                an_bytes = bytes.fromhex(line)
                ans.append(an_bytes)

    if len(ans) != 25:
        raise ValueError(f"Expected 25 ANs in key file, got {len(ans)}")

    return WalletKey(
        coin_id=coin_id,
        denomination=denomination,
        serial_number=serial_number,
        ans=ans,
        file_path=path
    )


# ============================================================================
# SERVER FETCH
# ============================================================================

def fetch_qmail_servers(url: str) -> Tuple[bool, List[Dict], str]:
    """Fetch QMail server list from directory URL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={'User-Agent': 'QMail-Test/1.0'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))

        servers = []
        server_list = data.get('servers', data.get('qmail_servers', []))
        if isinstance(data, list):
            server_list = data

        for srv in server_list:
            ip = srv.get('ip_address', srv.get('ip', srv.get('host', '')))
            port = srv.get('port', 50000)
            server_index = srv.get('server_index')

            if server_index is None:
                server_id_str = srv.get('server_id', '')
                if server_id_str.startswith('RAIDA'):
                    try:
                        server_index = int(server_id_str[5:])
                    except ValueError:
                        server_index = port - 50000 if port >= 50000 else 0
                else:
                    server_index = port - 50000 if port >= 50000 else 0

            if ip:
                servers.append({
                    "host": ip,
                    "port": port,
                    "raida_id": server_index
                })

        servers.sort(key=lambda s: s['raida_id'])
        return True, servers, ""

    except Exception as e:
        return False, [], f"Error: {e}"


# ============================================================================
# NETWORK
# ============================================================================

def send_tcp_request(host: str, port: int, request: bytes,
                    timeout_ms: int = READ_TIMEOUT_MS) -> Tuple[bool, bytes, int, str]:
    """Send TCP request and receive response."""
    sock = None
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_MS / 1000.0)
        sock.connect((host, port))
        sock.sendall(request)
        sock.settimeout(timeout_ms / 1000.0)

        # Read response
        response = b''
        while len(response) < 32:
            chunk = sock.recv(32 - len(response))
            if not chunk:
                break
            response += chunk

        # Check body length
        if len(response) >= 24:
            body_len = struct.unpack('>H', response[22:24])[0]
            if body_len > 0 and body_len < 0xFFFF:
                while len(response) < 32 + body_len:
                    chunk = sock.recv(min(4096, 32 + body_len - len(response)))
                    if not chunk:
                        break
                    response += chunk

        elapsed_ms = int((time.time() - start_time) * 1000)
        return True, response, elapsed_ms, ""

    except socket.timeout:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, b'', elapsed_ms, "Connection timeout"
    except socket.error as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, b'', elapsed_ms, str(e)
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


# ============================================================================
# DISPLAY
# ============================================================================

def hex_dump(data: bytes, max_bytes: int = 64) -> str:
    """Create hex dump of data."""
    if not data:
        return "  (empty)"

    lines = []
    data = data[:max_bytes]

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  0x{i:04X} | {hex_part} | {ascii_part}")

    return '\n'.join(lines)


def print_header(title: str):
    """Print section header."""
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def print_subheader(title: str):
    """Print sub-section header."""
    print("\n" + "-" * 72)
    print(f"  {title}")
    print("-" * 72)


# ============================================================================
# MAIN TEST
# ============================================================================

def run_peek_test():
    """Run PEEK test to check receiver's mailbox."""

    print_header("QMAIL PEEK TEST - Check Mailbox for New Mail")

    # Step 1: Load receiver key file
    print_subheader("Step 1: Loading Receiver Key File")
    print(f"  Key file: {RECEIVER_KEY_PATH}")

    try:
        receiver_key = load_key_file(RECEIVER_KEY_PATH)
        print(f"  [OK] Loaded key file")
        print(f"  Coin ID:       {receiver_key.coin_id}")
        print(f"  Denomination:  {receiver_key.denomination}")
        print(f"  Serial Number: {receiver_key.serial_number}")
        print(f"  ANs loaded:    {len(receiver_key.ans)}")
        print(f"  AN[0]:         {receiver_key.ans[0].hex()}")
    except Exception as e:
        print(f"  [FAIL] {e}")
        return False

    # Step 2: Fetch QMail servers
    print_subheader("Step 2: Fetching QMail Servers")
    print(f"  URL: {QMAIL_SERVERS_URL}")

    success, servers, error = fetch_qmail_servers(QMAIL_SERVERS_URL)
    if not success:
        print(f"  [FAIL] {error}")
        return False

    print(f"  [OK] Found {len(servers)} servers")
    for srv in servers:
        print(f"    R{srv['raida_id']:02d}: {srv['host']}:{srv['port']}")

    # Step 3: Import protocol module
    print_subheader("Step 3: Importing Protocol Module")

    try:
        import protocol
        print("  [OK] Imported protocol module")
    except ImportError as e:
        print(f"  [FAIL] {e}")
        return False

    # Step 4: Send PEEK to each server (or just one for testing)
    print_subheader("Step 4: Sending PEEK Requests")

    # Use timestamp 0 to get all tells
    since_timestamp = 0
    device_id = 1

    results = []
    tells_found = []

    for server in servers:
        raida_id = server['raida_id']

        # Get AN for this RAIDA
        if raida_id >= len(receiver_key.ans):
            print(f"  R{raida_id:02d}: [SKIP] No AN for this server")
            continue

        an = receiver_key.ans[raida_id]

        print(f"\n  R{raida_id:02d} ({server['host']}:{server['port']}):")
        print(f"    AN: {an.hex()}")

        # Build PEEK request
        err, request, challenge, nonce = protocol.build_complete_peek_request(
            raida_id=raida_id,
            denomination=receiver_key.denomination,
            serial_number=receiver_key.serial_number,
            device_id=device_id,
            an=an,
            since_timestamp=since_timestamp
        )

        if err != protocol.ProtocolErrorCode.SUCCESS:
            print(f"    [FAIL] Build error: {err}")
            results.append((raida_id, False, 0, f"Build error: {err}"))
            continue

        print(f"    Request: {len(request)} bytes")
        print(hex_dump(request, 48))

        # Send request
        success, response, elapsed_ms, error = send_tcp_request(
            server['host'], server['port'], request
        )

        if not success:
            print(f"    [FAIL] {error} ({elapsed_ms}ms)")
            results.append((raida_id, False, elapsed_ms, error))
            continue

        print(f"    Response: {len(response)} bytes ({elapsed_ms}ms)")
        print(hex_dump(response, 64))

        # Parse response
        if len(response) >= 32:
            # Status is typically at byte 32 (first byte of body)
            status = response[32] if len(response) > 32 else 0
            print(f"    Status: {status}")

            if status == 250 or status == 0:
                print(f"    [OK] Success")
                results.append((raida_id, True, elapsed_ms, status))

                # Try to decrypt and parse tell response
                if len(response) > 33:
                    encrypted_body = response[33:]
                    err, decrypted = protocol.decrypt_payload_with_an(
                        encrypted_body, an, nonce
                    )
                    if err == protocol.ProtocolErrorCode.SUCCESS and decrypted:
                        print(f"    Decrypted body: {len(decrypted)} bytes")
                        print(hex_dump(decrypted, 64))

                        # Parse tells
                        err, tells = protocol.parse_tell_response(decrypted)
                        if err == protocol.ProtocolErrorCode.SUCCESS:
                            print(f"    Tells found: {len(tells)}")
                            for tell in tells:
                                print(f"      GUID: {tell.file_guid.hex()}")
                                print(f"      Locker: {tell.locker_code.hex()}")
                                print(f"      Timestamp: {tell.timestamp}")
                                print(f"      Type: {tell.tell_type}")
                                print(f"      Servers: {tell.server_count}")
                                tells_found.append(tell)
            else:
                print(f"    [FAIL] Status {status}")
                results.append((raida_id, False, elapsed_ms, f"Status {status}"))
        else:
            print(f"    [FAIL] Response too short")
            results.append((raida_id, False, elapsed_ms, "Response too short"))

    # Summary
    print_header("PEEK TEST SUMMARY")

    success_count = sum(1 for r in results if r[1])
    print(f"  Servers queried: {len(results)}")
    print(f"  Successful:      {success_count}")
    print(f"  Failed:          {len(results) - success_count}")
    print(f"  Tells found:     {len(tells_found)}")

    if tells_found:
        print("\n  Received Tells:")
        for i, tell in enumerate(tells_found, 1):
            print(f"    {i}. GUID: {tell.file_guid.hex()}")
            print(f"       Type: {tell.tell_type}, Servers: {tell.server_count}")

    return success_count > 0


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 72)
    print("  QMAIL PEEK TEST")
    print("  Check mailbox for new mail notifications")
    print("=" * 72)

    success = run_peek_test()

    print("\n" + "=" * 72)
    if success:
        print("  TEST PASSED")
    else:
        print("  TEST FAILED")
    print("=" * 72 + "\n")

    sys.exit(0 if success else 1)
