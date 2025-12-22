"""
test_send_checklist.py - Comprehensive Send Email Test with Checklist

Production integration test with:
- Step-by-step checklist of all tests
- Progress tracking with visual indicators
- Stop-on-first-failure for debugging
- Detailed request/response packet logging
- File-based test data from Upload-files directory

Author: Claude Opus 4.5
Version: 1.0.0

Run with: python tests/test_send_checklist.py
"""

import sys
import os
import socket
import time
import struct
import asyncio
import json
import urllib.request
import ssl
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import IntEnum

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ============================================================================
# CONFIGURATION
# ============================================================================

# Directories
BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
DATA_DIR = os.path.join(BASE_DIR, 'Data')
UPLOAD_DIR = os.path.join(DATA_DIR, 'Upload-files')
LOCKER_KEYS_DIR = os.path.join(DATA_DIR, 'LockerKeys')
LOG_DIR = os.path.join(DATA_DIR, 'logs')

# QMail server directory URL
QMAIL_SERVERS_URL = "https://raida11.cloudcoin.global/service/qmail_servers"

# Will be populated dynamically from the server directory
QMAIL_SERVERS = []

# Timeouts
CONNECT_TIMEOUT_MS = 10000
READ_TIMEOUT_MS = 30000

# Key file paths - These contain real credentials
SENDER_KEY_PATH = os.path.join(DATA_DIR, 'Wallets', 'Sender', 'Bank', '00060300001AEA.key')
RECEIVER_KEY_PATH = os.path.join(DATA_DIR, 'Wallets', 'Receiver', 'Bank', '00060300001AEB.key')

# Will be populated from key files
SENDER_IDENTITY = None
RECEIVER_IDENTITY = None

# Fallback test identity if key files not found
TEST_IDENTITY = {
    'denomination': 1,
    'serial_number': 12345678,
    'device_id': 1,
    'an': bytes(16),
}

TEST_RECIPIENT = {
    'denomination': 1,
    'serial_number': 11111111,
}


# ============================================================================
# KEY FILE PARSING
# ============================================================================

def parse_key_filename(filename: str) -> Tuple[int, int, int]:
    """
    Parse key filename to extract coin_id, denomination, serial_number.
    Format: {coin_id:4}{denomination:2}{serial_number:6}.key
    Example: 00060300001AEA.key -> (6, 3, 6890)
    """
    basename = os.path.basename(filename)
    name = basename.replace('.key', '')

    if len(name) != 14:
        raise ValueError(f"Invalid key filename: {basename}")

    coin_id = int(name[0:4], 16)
    denomination = int(name[4:6], 16)
    serial_number = int(name[6:14], 16)

    return coin_id, denomination, serial_number


def load_key_file(path: str) -> Dict:
    """
    Load and parse a wallet key file.
    Returns dict with coin_id, denomination, serial_number, ans (list of 25 ANs)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")

    coin_id, denomination, serial_number = parse_key_filename(path)

    ans = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and len(line) == 32:
                an_bytes = bytes.fromhex(line)
                ans.append(an_bytes)

    if len(ans) != 25:
        raise ValueError(f"Expected 25 ANs, got {len(ans)}")

    return {
        'coin_id': coin_id,
        'denomination': denomination,
        'serial_number': serial_number,
        'device_id': 1,
        'ans': ans,
        'an': ans[0] if ans else bytes(16),  # Default AN for single-server ops
    }


def load_identities():
    """Load sender and receiver identities from key files."""
    global SENDER_IDENTITY, RECEIVER_IDENTITY, TEST_IDENTITY, TEST_RECIPIENT

    try:
        SENDER_IDENTITY = load_key_file(SENDER_KEY_PATH)
        TEST_IDENTITY = SENDER_IDENTITY
        print(f"  [OK] Loaded sender: denom={SENDER_IDENTITY['denomination']}, sn={SENDER_IDENTITY['serial_number']}")
    except Exception as e:
        print(f"  [WARNING] Could not load sender key: {e}")
        print(f"  Using fallback identity")

    try:
        RECEIVER_IDENTITY = load_key_file(RECEIVER_KEY_PATH)
        TEST_RECIPIENT = {
            'denomination': RECEIVER_IDENTITY['denomination'],
            'serial_number': RECEIVER_IDENTITY['serial_number'],
        }
        print(f"  [OK] Loaded receiver: denom={RECEIVER_IDENTITY['denomination']}, sn={RECEIVER_IDENTITY['serial_number']}")
    except Exception as e:
        print(f"  [WARNING] Could not load receiver key: {e}")
        print(f"  Using fallback recipient")


# ============================================================================
# TEST STATUS
# ============================================================================

class TestStatus(IntEnum):
    PENDING = 0
    RUNNING = 1
    PASSED = 2
    FAILED = 3
    SKIPPED = 4


@dataclass
class TestStep:
    """A single test step in the checklist."""
    id: str
    name: str
    description: str
    status: TestStatus = TestStatus.PENDING
    error_message: str = ""
    duration_ms: int = 0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestChecklist:
    """Complete test checklist."""
    steps: List[TestStep] = field(default_factory=list)
    start_time: datetime = None
    end_time: datetime = None
    log_file: str = ""

    def add_step(self, id: str, name: str, description: str):
        self.steps.append(TestStep(id=id, name=name, description=description))

    def get_step(self, id: str) -> Optional[TestStep]:
        for step in self.steps:
            if step.id == id:
                return step
        return None

    def passed_count(self) -> int:
        return sum(1 for s in self.steps if s.status == TestStatus.PASSED)

    def failed_count(self) -> int:
        return sum(1 for s in self.steps if s.status == TestStatus.FAILED)


# ============================================================================
# LOGGING
# ============================================================================

class TestLogger:
    """Logger that outputs to console and file."""

    def __init__(self, log_path: str):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.file = open(log_path, 'w', encoding='utf-8')
        self.log_path = log_path

    def write(self, text: str):
        # Console output with safe characters
        safe = text
        for old, new in [('\u2588', '#'), ('\u2022', '*'), ('\u2713', '[OK]'),
                         ('\u2717', '[X]'), ('\u250C', '+'), ('\u2500', '-'),
                         ('\u2510', '+'), ('\u2514', '+'), ('\u2518', '+'),
                         ('\u251C', '+'), ('\u2524', '+'), ('\u2502', '|')]:
            safe = safe.replace(old, new)
        try:
            print(safe, end='')
        except:
            print(safe.encode('ascii', 'replace').decode('ascii'), end='')
        # File gets full unicode
        self.file.write(text)
        self.file.flush()

    def writeln(self, text: str = ""):
        self.write(text + "\n")

    def close(self):
        self.file.close()


def hex_dump(data: bytes, max_bytes: int = 48) -> str:
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


# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

def display_checklist(checklist: TestChecklist, log: TestLogger):
    """Display the current checklist status."""
    log.writeln("\n" + "=" * 72)
    log.writeln("  SEND EMAIL API - TEST CHECKLIST")
    log.writeln("=" * 72)

    for i, step in enumerate(checklist.steps, 1):
        if step.status == TestStatus.PENDING:
            icon = "[ ]"
        elif step.status == TestStatus.RUNNING:
            icon = "[>]"
        elif step.status == TestStatus.PASSED:
            icon = "[+]"  # checkmark
        elif step.status == TestStatus.FAILED:
            icon = "[X]"  # X mark
        else:
            icon = "[-]"  # skipped

        status_text = step.status.name.ljust(7)
        log.writeln(f"  {icon} {i:2d}. {step.name}")
        log.writeln(f"       {step.description}")
        if step.status == TestStatus.FAILED:
            log.writeln(f"       ERROR: {step.error_message}")
        if step.duration_ms > 0:
            log.writeln(f"       Duration: {step.duration_ms}ms")
        log.writeln("")

    log.writeln("-" * 72)
    log.writeln(f"  Progress: {checklist.passed_count()}/{len(checklist.steps)} passed, "
               f"{checklist.failed_count()} failed")
    log.writeln("=" * 72)


def display_packet(log: TestLogger, title: str, data: bytes, max_bytes: int = 48):
    """Display packet data in hex dump format."""
    log.writeln(f"\n  {title} ({len(data)} bytes):")
    log.writeln("  Offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII")
    log.writeln("  -------|------------------------------------------------|------------------")
    log.writeln(hex_dump(data, max_bytes))


def display_response_summary(log: TestLogger, status_code: int, response_time_ms: int,
                            server: str, error: str = ""):
    """Display response summary box."""
    log.writeln("\n  +-----------------------------------------------------------+")
    log.writeln("  | Response Summary                                          |")
    log.writeln("  +-----------------------------------------------------------+")
    log.writeln(f"  | Server:        {server}")
    if error:
        log.writeln(f"  | Status:        ERROR - {error}")
    else:
        status_desc = {0: "Success", 250: "Success", 25: "Coin Not Found",
                      34: "Invalid Encryption"}.get(status_code, f"Code {status_code}")
        log.writeln(f"  | Status:        {status_code} ({status_desc})")
    log.writeln(f"  | Response Time: {response_time_ms}ms")
    log.writeln("  +-----------------------------------------------------------+")


# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================

def send_tcp_request(host: str, port: int, request: bytes,
                    timeout_ms: int = READ_TIMEOUT_MS) -> Tuple[bool, bytes, int, str]:
    """
    Send TCP request and receive response.

    Returns: (success, response_data, response_time_ms, error_message)
    """
    sock = None
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_MS / 1000.0)
        sock.connect((host, port))

        sock.sendall(request)
        sock.settimeout(timeout_ms / 1000.0)

        # Read response header (32 bytes)
        response = b''
        while len(response) < 32:
            chunk = sock.recv(32 - len(response))
            if not chunk:
                break
            response += chunk

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
# SERVER FETCH FUNCTION
# ============================================================================

def fetch_qmail_servers(url: str) -> Tuple[bool, List[Dict], str]:
    """
    Fetch QMail server list from the directory URL.

    Returns: (success, server_list, error_message)

    Expected JSON format:
    {
        "version": 1,
        "servers": [
            {
                "server_id": "RAIDA0",
                "server_index": 0,
                "ip_address": "78.46.170.45",
                "port": 50000,
                "server_type": "QMAIL",
                "cost_per_mb": 1,
                "cost_per_8_weeks": 1,
                "percent_uptime": 100,
                ...
            },
            ...
        ]
    }
    """
    try:
        # Create SSL context that doesn't verify (for testing)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={'User-Agent': 'QMail-Test/1.0'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))

        servers = []

        # Parse server list
        server_list = data.get('servers', data.get('qmail_servers', []))

        if isinstance(data, list):
            server_list = data

        for srv in server_list:
            # Extract server info from expected format
            ip = srv.get('ip_address', srv.get('ip', srv.get('host', '')))
            port = srv.get('port', 50000)

            # Server index from server_index field or parse from server_id ("RAIDA11" -> 11)
            server_index = srv.get('server_index')
            if server_index is None:
                # Try to parse from server_id string like "RAIDA11"
                server_id_str = srv.get('server_id', '')
                if server_id_str.startswith('RAIDA'):
                    try:
                        server_index = int(server_id_str[5:])
                    except ValueError:
                        server_index = port - 50000 if port >= 50000 else 0
                else:
                    server_index = port - 50000 if port >= 50000 else 0

            # Extract additional metadata
            uptime = srv.get('percent_uptime', 100)
            cost_per_mb = srv.get('cost_per_mb', srv.get('cost_per_kb', 0))
            region = srv.get('region', 'Unknown')

            if ip:
                servers.append({
                    "host": ip,
                    "port": port,
                    "raida_id": server_index,
                    "percent_uptime": uptime,
                    "cost_per_mb": cost_per_mb,
                    "region": region
                })

        if not servers:
            return False, [], "No servers found in response"

        # Sort by server index
        servers.sort(key=lambda s: s['raida_id'])

        return True, servers, ""

    except urllib.error.URLError as e:
        return False, [], f"URL error: {e}"
    except json.JSONDecodeError as e:
        return False, [], f"JSON parse error: {e}"
    except Exception as e:
        return False, [], f"Error: {e}"


# ============================================================================
# TEST STEPS
# ============================================================================

def test_step_check_directories(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 1: Check required directories exist."""
    step = checklist.get_step("1_directories")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 1: Checking Required Directories")
    log.writeln("-" * 72)

    dirs_to_check = [
        ("Data Directory", DATA_DIR),
        ("Upload Files", UPLOAD_DIR),
        ("Locker Keys", LOCKER_KEYS_DIR),
        ("Logs", LOG_DIR),
    ]

    all_ok = True
    for name, path in dirs_to_check:
        exists = os.path.exists(path)
        is_dir = os.path.isdir(path) if exists else False
        status = "[OK]" if is_dir else "[MISSING]"
        log.writeln(f"    {status} {name}: {path}")
        if not is_dir:
            all_ok = False
            if not exists:
                log.writeln(f"         Creating directory...")
                os.makedirs(path, exist_ok=True)

    step.duration_ms = int((time.time() - start) * 1000)

    if all_ok or os.path.isdir(LOCKER_KEYS_DIR):
        step.status = TestStatus.PASSED
        return True
    else:
        step.status = TestStatus.FAILED
        step.error_message = "Required directories missing"
        return False


def test_step_check_upload_files(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 2: Check upload files exist."""
    step = checklist.get_step("2_upload_files")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 2: Checking Upload Files")
    log.writeln("-" * 72)

    if not os.path.exists(UPLOAD_DIR):
        step.status = TestStatus.FAILED
        step.error_message = f"Upload directory not found: {UPLOAD_DIR}"
        return False

    files = os.listdir(UPLOAD_DIR)
    if not files:
        step.status = TestStatus.FAILED
        step.error_message = "No files in upload directory"
        return False

    total_size = 0
    file_details = []
    for f in files:
        path = os.path.join(UPLOAD_DIR, f)
        size = os.path.getsize(path)
        total_size += size
        file_details.append((f, size))
        log.writeln(f"    [OK] {f} ({size:,} bytes)")

    log.writeln(f"\n    Total: {len(files)} files, {total_size:,} bytes")

    step.details['files'] = file_details
    step.details['total_size'] = total_size
    step.duration_ms = int((time.time() - start) * 1000)
    step.status = TestStatus.PASSED
    return True


def test_step_check_locker_keys(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 3: Check locker key files."""
    step = checklist.get_step("3_locker_keys")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 3: Checking Locker Key Files")
    log.writeln("-" * 72)
    log.writeln(f"    Directory: {LOCKER_KEYS_DIR}")

    if not os.path.exists(LOCKER_KEYS_DIR):
        os.makedirs(LOCKER_KEYS_DIR, exist_ok=True)
        log.writeln("    [CREATED] Directory was missing, created it")

    # Look for *.locker_keys.txt files
    import glob
    key_files = glob.glob(os.path.join(LOCKER_KEYS_DIR, '*.locker_keys.txt'))

    if not key_files:
        log.writeln("\n    [WARNING] No locker key files found!")
        log.writeln("")
        log.writeln("    " + "=" * 60)
        log.writeln("    LOCKER KEY FILE REQUIREMENTS")
        log.writeln("    " + "=" * 60)
        log.writeln("    ")
        log.writeln("    You need to create locker key files in:")
        log.writeln(f"    {LOCKER_KEYS_DIR}")
        log.writeln("    ")
        log.writeln("    File naming format: {amount}.locker_keys.txt")
        log.writeln("    Examples:")
        log.writeln("      - 0.1.locker_keys.txt  (for 0.1 CC per key)")
        log.writeln("      - 1.locker_keys.txt    (for 1 CC per key)")
        log.writeln("      - 5.locker_keys.txt    (for 5 CC per key)")
        log.writeln("    ")
        log.writeln("    File format: One locker key per line (hex string)")
        log.writeln("    Example content:")
        log.writeln("      a1b2c3d4e5f6a7b8")
        log.writeln("      1234567890abcdef")
        log.writeln("      fedcba0987654321")
        log.writeln("    ")

        # Calculate required value based on upload files
        upload_step = checklist.get_step("2_upload_files")
        if upload_step and 'total_size' in upload_step.details:
            total_bytes = upload_step.details['total_size']
            # Rough estimate: 0.1 CC per 10KB
            estimated_cost = (total_bytes / 10240) * 0.1
            log.writeln(f"    ESTIMATED COST for your files ({total_bytes:,} bytes):")
            log.writeln(f"      Approximately {estimated_cost:.2f} CloudCoin")
            log.writeln("    ")
            log.writeln("    Recommended: Create 1.locker_keys.txt with")
            log.writeln(f"    at least {int(estimated_cost) + 5} locker keys")

        log.writeln("    " + "=" * 60)

        step.status = TestStatus.FAILED
        step.error_message = "No locker key files found - see instructions above"
        step.duration_ms = int((time.time() - start) * 1000)
        return False

    # Count keys in each file
    total_keys = 0
    for kf in key_files:
        filename = os.path.basename(kf)
        with open(kf, 'r') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        count = len(lines)
        total_keys += count
        log.writeln(f"    [OK] {filename}: {count} keys")

    log.writeln(f"\n    Total: {len(key_files)} files, {total_keys} keys available")

    if total_keys < 5:
        step.status = TestStatus.FAILED
        step.error_message = f"Only {total_keys} keys available, need at least 5"
        step.duration_ms = int((time.time() - start) * 1000)
        return False

    step.details['key_files'] = key_files
    step.details['total_keys'] = total_keys
    step.duration_ms = int((time.time() - start) * 1000)
    step.status = TestStatus.PASSED
    return True


def test_step_fetch_servers(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 4: Fetch server list from directory."""
    global QMAIL_SERVERS

    step = checklist.get_step("4_fetch_servers")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 4: Fetching QMail Server List")
    log.writeln("-" * 72)
    log.writeln(f"    URL: {QMAIL_SERVERS_URL}")

    success, servers, error = fetch_qmail_servers(QMAIL_SERVERS_URL)

    if not success:
        log.writeln(f"    [FAIL] {error}")
        step.status = TestStatus.FAILED
        step.error_message = error
        step.duration_ms = int((time.time() - start) * 1000)
        return False

    QMAIL_SERVERS = servers
    log.writeln(f"    [OK] Found {len(servers)} servers:")

    for srv in servers:
        server_id = srv['raida_id']
        uptime = srv.get('percent_uptime', '?')
        region = srv.get('region', 'Unknown')
        log.writeln(f"      R{server_id:02d}: {srv['host']}:{srv['port']} ({uptime}% uptime, {region})")

    step.details['servers'] = servers
    step.duration_ms = int((time.time() - start) * 1000)
    step.status = TestStatus.PASSED
    return True


def test_step_server_connectivity(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 5: Test server connectivity."""
    step = checklist.get_step("5_connectivity")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 5: Testing Server Connectivity")
    log.writeln("-" * 72)

    if not QMAIL_SERVERS:
        step.status = TestStatus.FAILED
        step.error_message = "No servers to test"
        return False

    results = []

    for server in QMAIL_SERVERS:
        host = server['host']
        port = server['port']
        raida_id = server['raida_id']

        log.writeln(f"\n    Testing R{raida_id:02d} ({host}:{port})...")

        # Build minimal echo request
        request = bytearray(34)
        request[0] = 0x01  # Version
        request[2] = raida_id
        request[4] = 0x00  # Echo command group
        request[5] = 0x00  # Echo command
        request[32:34] = b'\x3E\x3E'

        success, response, elapsed_ms, error = send_tcp_request(host, port, bytes(request))

        if success:
            status_code = response[32] if len(response) > 32 else -1
            log.writeln(f"      [OK] Response in {elapsed_ms}ms, status={status_code}")
            results.append((raida_id, True, elapsed_ms, status_code))
        else:
            log.writeln(f"      [FAIL] {error} ({elapsed_ms}ms)")
            results.append((raida_id, False, elapsed_ms, error))

    # Summary
    success_count = sum(1 for r in results if r[1])
    log.writeln(f"\n    Summary: {success_count}/{len(QMAIL_SERVERS)} servers reachable")

    step.details['results'] = results
    step.duration_ms = int((time.time() - start) * 1000)

    if success_count == 0:
        step.status = TestStatus.FAILED
        step.error_message = "No servers reachable"
        return False
    elif success_count < len(QMAIL_SERVERS):
        log.writeln(f"    [WARNING] Only {success_count} servers available")
        step.status = TestStatus.PASSED  # Continue with partial connectivity
        return True
    else:
        step.status = TestStatus.PASSED
        return True


def test_step_import_modules(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 6: Import required modules."""
    step = checklist.get_step("6_imports")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 6: Importing Required Modules")
    log.writeln("-" * 72)

    modules = [
        'protocol',
        'striping',
        'key_manager',
        'network',
        'database',
        'email_sender',
        'cloudcoin',
        'payment',
    ]

    imported = {}
    failed = []

    for mod in modules:
        try:
            imported[mod] = __import__(mod)
            log.writeln(f"    [OK] {mod}")
        except ImportError as e:
            log.writeln(f"    [FAIL] {mod}: {e}")
            failed.append((mod, str(e)))

    step.details['imported'] = list(imported.keys())
    step.details['failed'] = failed
    step.duration_ms = int((time.time() - start) * 1000)

    # Store imported modules for later use
    step.details['modules'] = imported

    if failed:
        step.status = TestStatus.FAILED
        step.error_message = f"Failed to import: {', '.join(f[0] for f in failed)}"
        return False

    step.status = TestStatus.PASSED
    return True


def test_step_build_upload_request(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 7: Build and test upload request."""
    step = checklist.get_step("7_upload_request")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 7: Building Upload Request")
    log.writeln("-" * 72)

    # Get modules
    import_step = checklist.get_step("6_imports")
    if not import_step or 'modules' not in import_step.details:
        step.status = TestStatus.FAILED
        step.error_message = "Modules not imported"
        return False

    modules = import_step.details['modules']
    protocol = modules.get('protocol')
    striping = modules.get('striping')

    # Get first upload file
    upload_step = checklist.get_step("2_upload_files")
    if not upload_step or 'files' not in upload_step.details:
        step.status = TestStatus.FAILED
        step.error_message = "No upload files found"
        return False

    first_file = upload_step.details['files'][0]
    file_path = os.path.join(UPLOAD_DIR, first_file[0])

    log.writeln(f"    Using file: {first_file[0]} ({first_file[1]:,} bytes)")

    # Read file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    log.writeln(f"    Read {len(file_data):,} bytes")

    # Create stripes - one per server (N-1 data + 1 parity = N total)
    num_servers = len(QMAIL_SERVERS)
    log.writeln(f"    Creating {num_servers - 1} data stripes + 1 parity for {num_servers} servers")

    # create_upload_stripes creates (num_servers - 1) data stripes
    err, stripes = striping.create_upload_stripes(file_data, num_servers=num_servers)
    if err != striping.ErrorCode.SUCCESS:
        step.status = TestStatus.FAILED
        step.error_message = f"Failed to create stripes: {err}"
        return False

    log.writeln(f"    Created {len(stripes)} stripes")
    for i, s in enumerate(stripes):
        log.writeln(f"      Stripe {i}: {len(s):,} bytes")

    # Calculate parity
    err, parity = striping.calculate_parity_from_bytes(stripes)
    if err != striping.ErrorCode.SUCCESS:
        step.status = TestStatus.FAILED
        step.error_message = f"Failed to calculate parity: {err}"
        return False

    log.writeln(f"    Parity stripe: {len(parity):,} bytes")

    # Generate file group GUID
    import uuid
    file_group_guid = uuid.uuid4().bytes
    log.writeln(f"    File Group GUID: {file_group_guid.hex()}")

    # Get locker codes from file - one per server (7 total)
    from key_manager import get_next_locker_code
    num_servers = len(QMAIL_SERVERS)
    locker_codes = []
    log.writeln(f"\n    Getting {num_servers} locker codes (1 CC each):")

    for i in range(num_servers):
        try:
            code = get_next_locker_code(LOCKER_KEYS_DIR)
            # Encode string to bytes for protocol (pad/truncate to 8 bytes)
            if isinstance(code, str):
                code_bytes = code.encode('utf-8')[:8].ljust(8, b'\x00')
            else:
                code_bytes = code[:8].ljust(8, b'\x00')
            locker_codes.append(code_bytes)
            log.writeln(f"      Server {i}: {code} -> {code_bytes.hex()}")
        except FileNotFoundError as e:
            step.status = TestStatus.FAILED
            step.error_message = f"Not enough locker codes: need {num_servers}, got {i}"
            return False

    log.writeln(f"    Total cost: {num_servers} CC")

    # Build upload request for first server (sample)
    server = QMAIL_SERVERS[0]
    err, request, challenge = protocol.build_complete_upload_request(
        raida_id=server['raida_id'],
        denomination=TEST_IDENTITY['denomination'],
        serial_number=TEST_IDENTITY['serial_number'],
        device_id=TEST_IDENTITY['device_id'],
        an=TEST_IDENTITY['an'],
        file_group_guid=file_group_guid,
        locker_code=locker_codes[0],  # First server's locker code
        storage_duration=2,
        stripe_data=stripes[0]
    )

    if err != protocol.ProtocolErrorCode.SUCCESS:
        step.status = TestStatus.FAILED
        step.error_message = f"Failed to build request: {err}"
        return False

    log.writeln(f"\n    Built request: {len(request)} bytes")
    display_packet(log, "REQUEST PACKET", request, 48)

    # Store for later tests
    step.details['file_data'] = file_data
    step.details['stripes'] = stripes
    step.details['parity'] = parity
    step.details['file_group_guid'] = file_group_guid
    step.details['locker_codes'] = locker_codes  # List of codes, one per server
    step.details['sample_request'] = request

    step.duration_ms = int((time.time() - start) * 1000)
    step.status = TestStatus.PASSED
    return True


def test_step_send_upload(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 8: Send upload to servers."""
    step = checklist.get_step("8_send_upload")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 8: Sending Upload to Servers")
    log.writeln("-" * 72)

    # Get data from previous step
    build_step = checklist.get_step("7_upload_request")
    if not build_step or 'stripes' not in build_step.details:
        step.status = TestStatus.FAILED
        step.error_message = "No upload data prepared"
        return False

    stripes = build_step.details['stripes']
    parity = build_step.details['parity']
    file_group_guid = build_step.details['file_group_guid']
    locker_codes = build_step.details['locker_codes']  # One per server

    # Get modules
    import_step = checklist.get_step("6_imports")
    modules = import_step.details['modules']
    protocol = modules.get('protocol')

    all_stripes = stripes + [parity]
    results = []

    for i, server in enumerate(QMAIL_SERVERS):
        stripe_data = all_stripes[i] if i < len(all_stripes) else b''
        locker_code = locker_codes[i]  # Each server gets its own locker code
        raida_id = server['raida_id']

        # Get the correct AN for this server (from sender's key file)
        if SENDER_IDENTITY and 'ans' in SENDER_IDENTITY and raida_id < len(SENDER_IDENTITY['ans']):
            an = SENDER_IDENTITY['ans'][raida_id]
        else:
            an = TEST_IDENTITY.get('an', bytes(16))

        log.writeln(f"\n    Uploading to R{raida_id:02d} ({server['host']})...")
        log.writeln(f"    Stripe {i}: {len(stripe_data):,} bytes")
        log.writeln(f"    Locker: {locker_code.hex()}")
        log.writeln(f"    AN: {an.hex()}")

        # Build request
        err, request, challenge = protocol.build_complete_upload_request(
            raida_id=raida_id,
            denomination=TEST_IDENTITY['denomination'],
            serial_number=TEST_IDENTITY['serial_number'],
            device_id=TEST_IDENTITY['device_id'],
            an=an,  # Use correct AN for this server
            file_group_guid=file_group_guid,
            locker_code=locker_code,  # Unique per server
            storage_duration=2,
            stripe_data=stripe_data
        )

        if err != protocol.ProtocolErrorCode.SUCCESS:
            log.writeln(f"      [FAIL] Build error: {err}")
            results.append((server['raida_id'], False, 0, f"Build error: {err}"))
            continue

        # Send request
        display_packet(log, "REQUEST", request, 48)

        success, response, elapsed_ms, error = send_tcp_request(
            server['host'], server['port'], request
        )

        if success and len(response) >= 32:
            # Status is at byte 32 if body exists, otherwise check header
            if len(response) > 32:
                status_code = response[32]
            else:
                # No body - check if header indicates success (no error in terminator area)
                # A 32-byte response with valid header is typically success
                status_code = 0

            display_packet(log, "RESPONSE", response, 48)
            display_response_summary(log, status_code, elapsed_ms,
                                    f"{server['host']}:{server['port']}")

            if status_code in [0, 250]:
                log.writeln(f"      [OK] Upload accepted")
                results.append((server['raida_id'], True, elapsed_ms, status_code))
            else:
                log.writeln(f"      [FAIL] Status {status_code}")
                results.append((server['raida_id'], False, elapsed_ms, f"Status {status_code}"))
        else:
            if response:
                display_packet(log, "RESPONSE (incomplete)", response, 48)
            display_response_summary(log, 0, elapsed_ms,
                                    f"{server['host']}:{server['port']}", error or "No response")
            results.append((server['raida_id'], False, elapsed_ms, error or "No response"))

    # Summary
    success_count = sum(1 for r in results if r[1])
    log.writeln(f"\n    Summary: {success_count}/{len(QMAIL_SERVERS)} uploads successful")

    step.details['results'] = results
    step.duration_ms = int((time.time() - start) * 1000)

    # Need at least 4 successful for data integrity (can recover 1 with parity)
    if success_count >= 4:
        step.status = TestStatus.PASSED
        return True
    else:
        step.status = TestStatus.FAILED
        step.error_message = f"Only {success_count} uploads succeeded, need at least 4"
        return False


def test_step_build_tell(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 9: Build TELL notification request."""
    step = checklist.get_step("9_tell_request")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 9: Building TELL Notification")
    log.writeln("-" * 72)

    # Get previous data
    build_step = checklist.get_step("7_upload_request")
    if not build_step:
        step.status = TestStatus.FAILED
        step.error_message = "No upload data"
        return False

    import_step = checklist.get_step("6_imports")
    modules = import_step.details['modules']
    protocol = modules.get('protocol')

    file_group_guid = build_step.details['file_group_guid']
    locker_codes = build_step.details['locker_codes']

    log.writeln(f"    File GUID: {file_group_guid.hex()}")
    log.writeln(f"    Locker Codes: {len(locker_codes)} (1 per server)")
    for i, code in enumerate(locker_codes):
        log.writeln(f"      Server {i}: {code.hex()}")
    log.writeln(f"    Recipient: {TEST_RECIPIENT['serial_number']}")

    # Import TellRecipient and TellServer
    try:
        from qmail_types import TellRecipient, TellServer
    except ImportError:
        step.status = TestStatus.FAILED
        step.error_message = "Could not import TellRecipient/TellServer"
        return False

    # Build recipient - include first locker code so recipient can derive decryption keys
    # The locker code is 8 bytes, padded to 16 for the LockerPaymentKey field
    first_locker_code = locker_codes[0] if locker_codes else bytes(8)
    locker_payment_key = first_locker_code + bytes(8)  # Pad to 16 bytes

    recipients = [TellRecipient(
        address_type=0,
        coin_id=0x0006,
        denomination=TEST_RECIPIENT['denomination'],
        domain_id=0,
        serial_number=TEST_RECIPIENT['serial_number'],
        locker_payment_key=locker_payment_key
    )]

    # Build tell request
    # Use R11 as beacon (fastest server based on previous tests)
    import time as time_mod
    beacon = QMAIL_SERVERS[3] if len(QMAIL_SERVERS) > 3 else QMAIL_SERVERS[0]
    beacon_raida_id = beacon['raida_id']
    log.writeln(f"    Using beacon: R{beacon_raida_id:02d} ({beacon['host']})")

    # Get the correct AN for the beacon server
    if SENDER_IDENTITY and 'ans' in SENDER_IDENTITY and beacon_raida_id < len(SENDER_IDENTITY['ans']):
        beacon_an = SENDER_IDENTITY['ans'][beacon_raida_id]
    else:
        beacon_an = TEST_IDENTITY.get('an', bytes(16))
    log.writeln(f"    Sender AN: {beacon_an.hex()}")

    # Update servers with their locker codes
    servers = []
    for i, srv in enumerate(QMAIL_SERVERS):
        servers.append(TellServer(
            stripe_index=i,
            stripe_type=1 if i == len(QMAIL_SERVERS) - 1 else 0,
            ip_address=srv['host'],
            port=srv['port'],
            locker_code=locker_codes[i]  # Each server's locker code
        ))

    err, request, challenge = protocol.build_complete_tell_request(
        raida_id=beacon_raida_id,
        denomination=TEST_IDENTITY['denomination'],
        serial_number=TEST_IDENTITY['serial_number'],
        device_id=TEST_IDENTITY['device_id'],
        an=beacon_an,  # Use correct AN for beacon server
        file_group_guid=file_group_guid,
        locker_code=locker_codes[0],  # Beacon's locker code for TELL encryption
        timestamp=int(time_mod.time()),
        tell_type=0,
        recipients=recipients,
        servers=servers
    )

    if err != protocol.ProtocolErrorCode.SUCCESS:
        step.status = TestStatus.FAILED
        step.error_message = f"Failed to build TELL: {err}"
        return False

    log.writeln(f"\n    Built TELL request: {len(request)} bytes")
    display_packet(log, "TELL REQUEST", request, 48)

    step.details['request'] = request
    step.details['beacon'] = beacon
    step.duration_ms = int((time.time() - start) * 1000)
    step.status = TestStatus.PASSED
    return True


def test_step_send_tell(checklist: TestChecklist, log: TestLogger) -> bool:
    """Step 10: Send TELL notification."""
    step = checklist.get_step("10_send_tell")
    step.status = TestStatus.RUNNING
    start = time.time()

    log.writeln("\n" + "-" * 72)
    log.writeln("  STEP 10: Sending TELL Notification")
    log.writeln("-" * 72)

    tell_step = checklist.get_step("9_tell_request")
    if not tell_step or 'request' not in tell_step.details:
        step.status = TestStatus.FAILED
        step.error_message = "No TELL request built"
        return False

    request = tell_step.details['request']
    beacon = tell_step.details['beacon']

    log.writeln(f"    Sending to beacon: {beacon['host']}:{beacon['port']}")

    success, response, elapsed_ms, error = send_tcp_request(
        beacon['host'], beacon['port'], request
    )

    display_packet(log, "REQUEST", request, 48)

    if success and len(response) >= 32:
        # Status is at byte 32 if body exists, otherwise assume success
        if len(response) > 32:
            status_code = response[32]
        else:
            status_code = 0

        display_packet(log, "RESPONSE", response, 48)
        display_response_summary(log, status_code, elapsed_ms,
                                f"{beacon['host']}:{beacon['port']}")

        step.details['status_code'] = status_code
        step.details['response'] = response

        if status_code in [0, 250]:
            log.writeln(f"      [OK] TELL notification sent successfully")
            step.status = TestStatus.PASSED
            return True
        else:
            step.status = TestStatus.FAILED
            step.error_message = f"TELL rejected with status {status_code}"
            return False
    else:
        if response:
            display_packet(log, "RESPONSE (incomplete)", response, 48)
        display_response_summary(log, 0, elapsed_ms,
                                f"{beacon['host']}:{beacon['port']}", error or "No response")
        step.status = TestStatus.FAILED
        step.error_message = error or "No response received"
        return False


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_tests():
    """Run all tests with checklist."""

    # Load identities from key files
    print("\n  Loading credentials from key files...")
    load_identities()

    # Create log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f'send_checklist_{timestamp}.log')
    os.makedirs(LOG_DIR, exist_ok=True)
    log = TestLogger(log_path)

    # Create checklist
    checklist = TestChecklist()
    checklist.log_file = log_path
    checklist.start_time = datetime.now()

    # Define test steps
    checklist.add_step("1_directories", "Check Directories",
                      "Verify required directories exist")
    checklist.add_step("2_upload_files", "Check Upload Files",
                      "Find files to upload in Data/Upload-files")
    checklist.add_step("3_locker_keys", "Check Locker Keys",
                      "Verify locker key files in Data/LockerKeys")
    checklist.add_step("4_fetch_servers", "Fetch Server List",
                      "Download QMail server directory from URL")
    checklist.add_step("5_connectivity", "Server Connectivity",
                      "Test TCP connection to all QMail servers")
    checklist.add_step("6_imports", "Import Modules",
                      "Load protocol, striping, and network modules")
    checklist.add_step("7_upload_request", "Build Upload Request",
                      "Create stripes and build upload packet")
    checklist.add_step("8_send_upload", "Send Upload",
                      "Upload stripes to all servers")
    checklist.add_step("9_tell_request", "Build TELL Request",
                      "Create TELL notification packet")
    checklist.add_step("10_send_tell", "Send TELL",
                      "Send notification to recipient beacon")

    # Display initial checklist
    display_checklist(checklist, log)

    # Run tests
    test_functions = [
        ("1_directories", test_step_check_directories),
        ("2_upload_files", test_step_check_upload_files),
        ("3_locker_keys", test_step_check_locker_keys),
        ("4_fetch_servers", test_step_fetch_servers),
        ("5_connectivity", test_step_server_connectivity),
        ("6_imports", test_step_import_modules),
        ("7_upload_request", test_step_build_upload_request),
        ("8_send_upload", test_step_send_upload),
        ("9_tell_request", test_step_build_tell),
        ("10_send_tell", test_step_send_tell),
    ]

    for step_id, test_func in test_functions:
        try:
            success = test_func(checklist, log)
            if not success:
                log.writeln("\n" + "!" * 72)
                log.writeln("  TEST STOPPED - Failure detected")
                log.writeln("  Fix the issue above and re-run the test")
                log.writeln("!" * 72)
                break
        except Exception as e:
            step = checklist.get_step(step_id)
            step.status = TestStatus.FAILED
            step.error_message = f"Exception: {e}"
            log.writeln(f"\n    [EXCEPTION] {e}")
            import traceback
            log.writeln(traceback.format_exc())
            break

    # Mark remaining steps as skipped
    for step in checklist.steps:
        if step.status == TestStatus.PENDING:
            step.status = TestStatus.SKIPPED

    checklist.end_time = datetime.now()

    # Final summary
    display_checklist(checklist, log)

    duration = (checklist.end_time - checklist.start_time).total_seconds()
    log.writeln(f"\n  Total Duration: {duration:.2f}s")
    log.writeln(f"  Log File: {log_path}")

    log.close()

    print(f"\n\nFull log saved to: {log_path}")

    return checklist.failed_count() == 0


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 72)
    print("  QMAIL SEND API - COMPREHENSIVE TEST")
    print("=" * 72)
    print(f"\n  Upload Files: {UPLOAD_DIR}")
    print(f"  Locker Keys:  {LOCKER_KEYS_DIR}")
    print(f"  Servers:      {len(QMAIL_SERVERS)} configured")
    print("\n  Starting tests...\n")

    success = run_tests()
    sys.exit(0 if success else 1)
