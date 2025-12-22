"""
test_send_production.py - Production Integration Test for Send Email API

Tests the send email API against real QMail production servers with detailed
request/response packet logging for debugging.

Features:
    - Connects to real production servers (raida0-4.cloudcoin.global)
    - Logs first 48 bytes of requests and responses in hex dump format
    - Shows timing information (response times, outliers, timeouts)
    - Outputs to both console and log file
    - Visual response time bars

Author: Claude Opus 4.5
Version: 1.0.0

Run with: python tests/test_send_production.py
"""

import sys
import os
import socket
import time
import struct
import asyncio
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from io import StringIO

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import modules
from protocol import (
    build_complete_upload_request, validate_upload_response,
    build_complete_tell_request, validate_tell_response,
    ProtocolErrorCode, CMD_GROUP_FILES, CMD_UPLOAD, CMD_TELL,
    ENC_SHARED_SECRET, ENC_LOCKER_CODE
)
from striping import create_upload_stripes, calculate_parity_from_bytes, ErrorCode as StripingErrorCode
from key_manager import get_keys_from_locker_code
from network import ServerInfo, NetworkErrorCode
from qmail_types import TellRecipient, TellServer

# ============================================================================
# CONFIGURATION
# ============================================================================

# Production QMail servers
PRODUCTION_SERVERS = [
    ServerInfo(host="raida0.cloudcoin.global", port=443, raida_id=0),
    ServerInfo(host="raida1.cloudcoin.global", port=443, raida_id=1),
    ServerInfo(host="raida2.cloudcoin.global", port=443, raida_id=2),
    ServerInfo(host="raida3.cloudcoin.global", port=443, raida_id=3),
    ServerInfo(host="raida4.cloudcoin.global", port=443, raida_id=4),
]

# Timeouts
CONNECT_TIMEOUT_MS = 5000
READ_TIMEOUT_MS = 30000
OUTLIER_THRESHOLD_MS = 1000

# Log file
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'Data', 'logs')
LOG_FILE = os.path.join(LOG_DIR, f'send_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')


# ============================================================================
# LOGGING UTILITIES
# ============================================================================

class DualLogger:
    """Logs to both console and file."""

    def __init__(self, log_path: str):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.file = open(log_path, 'w', encoding='utf-8')
        self.buffer = StringIO()
        # Set console to UTF-8 if possible
        try:
            import sys
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    def write(self, text: str):
        # Use ASCII-safe characters for console
        safe_text = text.replace('\u250C', '+').replace('\u2500', '-').replace('\u2510', '+')
        safe_text = safe_text.replace('\u2514', '+').replace('\u2518', '+')
        safe_text = safe_text.replace('\u251C', '+').replace('\u2524', '+')
        safe_text = safe_text.replace('\u2502', '|')
        safe_text = safe_text.replace('\u2588', '#')
        safe_text = safe_text.replace('\u2022', '*')
        safe_text = safe_text.replace('\u2713', '[OK]').replace('\u2717', '[X]')
        try:
            print(safe_text, end='')
        except:
            print(safe_text.encode('ascii', 'replace').decode('ascii'), end='')
        # File gets full unicode
        self.file.write(text)
        self.file.flush()

    def writeln(self, text: str = ""):
        self.write(text + "\n")

    def close(self):
        self.file.close()


def hex_dump(data: bytes, max_bytes: int = 48, offset: int = 0) -> str:
    """
    Create a hex dump of data similar to hex editors.

    Format:
    Offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII
    """
    if not data:
        return "  (empty)"

    lines = []
    data = data[:max_bytes]  # Limit to max_bytes

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]

        # Hex part
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        hex_part = hex_part.ljust(47)  # 16 bytes * 3 chars - 1 space

        # ASCII part
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        lines.append(f"  0x{offset + i:04X} | {hex_part} | {ascii_part}")

    return '\n'.join(lines)


def format_header_table() -> str:
    """Format header for hex dump table."""
    return """  Offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII
  -------|------------------------------------------------|------------------"""


def response_time_bar(ms: int, max_ms: int = 1000, width: int = 50) -> str:
    """Create a visual bar for response time."""
    if ms < 0:
        return "[TIMEOUT]"

    # Normalize to width
    bar_len = min(int((ms / max_ms) * width), width)

    if ms > OUTLIER_THRESHOLD_MS:
        return '!' * bar_len + f" {ms} ms (OUTLIER)"
    else:
        return '\u2588' * bar_len + f" {ms} ms"


def format_encryption_type(enc_type: int) -> str:
    """Format encryption type for display."""
    types = {
        0: "Type 0 (No Encryption)",
        1: "Type 1 (AES-128 CTR with AN)",
        2: "Type 2 (Locker Code based)"
    }
    return types.get(enc_type, f"Type {enc_type} (Unknown)")


def format_status_code(status: int) -> str:
    """Format status code with description."""
    codes = {
        0: "Success/No Error",
        11: "You Got Mail",
        12: "Session Timeout",
        16: "Invalid Packet Length",
        17: "UDP Frame Timeout",
        18: "Wrong RAIDA",
        25: "Encryption Coin Not Found",
        34: "Invalid Encryption",
        194: "Filesystem Error",
        198: "Invalid Parameter",
        202: "File Not Exist",
        250: "Success",
        252: "Internal Error",
        253: "Network Error"
    }
    desc = codes.get(status, "Unknown")
    return f"0x{status:02X} ({status}) [{desc}]"


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class PacketCapture:
    """Captures request/response packet details."""
    server: ServerInfo
    request_data: bytes = b''
    response_data: bytes = b''
    request_time: float = 0.0
    response_time_ms: int = -1
    success: bool = False
    error_message: str = ""
    status_code: int = 0


@dataclass
class TestResult:
    """Result of a test operation."""
    task_name: str
    task_id: str
    start_time: datetime
    end_time: datetime = None
    captures: List[PacketCapture] = field(default_factory=list)
    success_count: int = 0
    error_count: int = 0
    timeout_count: int = 0


# ============================================================================
# NETWORK FUNCTIONS WITH PACKET CAPTURE
# ============================================================================

def send_raw_request(
    server: ServerInfo,
    request: bytes,
    connect_timeout_ms: int = CONNECT_TIMEOUT_MS,
    read_timeout_ms: int = READ_TIMEOUT_MS
) -> PacketCapture:
    """
    Send a raw request to server and capture the exchange.

    Returns PacketCapture with all details.
    """
    capture = PacketCapture(server=server, request_data=request)

    sock = None
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout_ms / 1000.0)

        # Connect
        start_time = time.time()
        capture.request_time = start_time

        sock.connect((server.host, server.port))

        # Send request
        sock.sendall(request)

        # Set read timeout
        sock.settimeout(read_timeout_ms / 1000.0)

        # Read response header (32 bytes)
        response_header = b''
        while len(response_header) < 32:
            chunk = sock.recv(32 - len(response_header))
            if not chunk:
                break
            response_header += chunk

        if len(response_header) < 32:
            capture.error_message = f"Incomplete header: {len(response_header)} bytes"
            capture.response_time_ms = int((time.time() - start_time) * 1000)
            return capture

        # Parse body length from header (bytes 22-23)
        body_length = struct.unpack('>H', response_header[22:24])[0]

        # Read body
        response_body = b''
        if body_length > 0 and body_length < 0xFFFF:
            while len(response_body) < body_length:
                remaining = body_length - len(response_body)
                chunk = sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                response_body += chunk

        end_time = time.time()
        capture.response_time_ms = int((end_time - start_time) * 1000)
        capture.response_data = response_header + response_body

        # Parse status from response body
        if len(response_body) > 0:
            capture.status_code = response_body[0]

        capture.success = True

    except socket.timeout:
        capture.error_message = "Connection/Read Timeout"
        capture.response_time_ms = int((time.time() - capture.request_time) * 1000)
    except socket.error as e:
        capture.error_message = f"Socket Error: {e}"
        capture.response_time_ms = int((time.time() - capture.request_time) * 1000) if capture.request_time else -1
    except Exception as e:
        capture.error_message = f"Error: {e}"
        capture.response_time_ms = -1
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

    return capture


async def send_raw_request_async(
    server: ServerInfo,
    request: bytes,
    connect_timeout_ms: int = CONNECT_TIMEOUT_MS,
    read_timeout_ms: int = READ_TIMEOUT_MS
) -> PacketCapture:
    """Async version of send_raw_request."""
    capture = PacketCapture(server=server, request_data=request)

    try:
        start_time = time.time()
        capture.request_time = start_time

        # Connect with timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server.host, server.port),
            timeout=connect_timeout_ms / 1000.0
        )

        # Send request
        writer.write(request)
        await writer.drain()

        # Read response header
        response_header = await asyncio.wait_for(
            reader.readexactly(32),
            timeout=read_timeout_ms / 1000.0
        )

        # Parse body length
        body_length = struct.unpack('>H', response_header[22:24])[0]

        # Read body
        response_body = b''
        if body_length > 0 and body_length < 0xFFFF:
            response_body = await asyncio.wait_for(
                reader.readexactly(body_length),
                timeout=read_timeout_ms / 1000.0
            )

        end_time = time.time()
        capture.response_time_ms = int((end_time - start_time) * 1000)
        capture.response_data = response_header + response_body

        if len(response_body) > 0:
            capture.status_code = response_body[0]

        capture.success = True

        writer.close()
        await writer.wait_closed()

    except asyncio.TimeoutError:
        capture.error_message = "Timeout"
        capture.response_time_ms = int((time.time() - capture.request_time) * 1000)
    except asyncio.IncompleteReadError as e:
        capture.error_message = f"Incomplete read: {len(e.partial)} bytes"
        capture.response_data = e.partial
        capture.response_time_ms = int((time.time() - capture.request_time) * 1000)
    except Exception as e:
        capture.error_message = str(e)
        capture.response_time_ms = -1

    return capture


# ============================================================================
# REPORT FORMATTING
# ============================================================================

def format_task_header(task_name: str, task_id: str, start_time: datetime, log: DualLogger):
    """Format task header."""
    log.writeln("=" * 72)
    log.writeln(f"TASK: {task_name}")
    log.writeln(f"ID: {task_id} | Start: {start_time.strftime('%I:%M:%S %p')}")
    log.writeln("=" * 72)


def format_response_times(captures: List[PacketCapture], log: DualLogger):
    """Format response times with visual bars."""
    log.writeln("\n  Response Times (ms)")
    log.writeln("  " + "\u250C" + "\u2500" * 65 + "\u2510")

    for cap in captures:
        server_label = f"R{cap.server.raida_id:02d}"
        bar = response_time_bar(cap.response_time_ms)
        log.writeln(f"  \u2502 {server_label} {bar}")

    log.writeln("  " + "\u2514" + "\u2500" * 65 + "\u2518")

    # Statistics
    valid_times = [c.response_time_ms for c in captures if c.response_time_ms >= 0]
    if valid_times:
        log.writeln(f"  Min: {min(valid_times)} ms  |  Max: {max(valid_times)} ms  |  "
                   f"Avg: {sum(valid_times)//len(valid_times)} ms  |  "
                   f"Valid: {len(valid_times)}/{len(captures)}")


def format_summary_box(captures: List[PacketCapture], log: DualLogger):
    """Format summary box."""
    ready = sum(1 for c in captures if c.success and c.status_code in [0, 250])
    errors = sum(1 for c in captures if c.success and c.status_code not in [0, 250])
    timeouts = sum(1 for c in captures if not c.success)

    log.writeln("\n  " + "\u250C" + "\u2500" * 70 + "\u2510")
    log.writeln("  \u2502" + "RAIDA Response Summary".center(70) + "\u2502")
    log.writeln("  " + "\u251C" + "\u2500" * 70 + "\u2524")
    log.writeln(f"  \u2502 Ready:                                                             {ready:2d} \u2502")
    log.writeln(f"  \u2502 Errors (RAIDA errors):                                              {errors:2d} \u2502")
    log.writeln(f"  \u2502 Timeouts/No Reply:                                                  {timeouts:2d} \u2502")
    log.writeln("  " + "\u251C" + "\u2500" * 70 + "\u2524")
    log.writeln(f"  \u2502 Total Servers:                                                      {len(captures):2d} \u2502")
    log.writeln("  " + "\u2514" + "\u2500" * 70 + "\u2518")


def format_packet_details(capture: PacketCapture, encryption_type: int, log: DualLogger):
    """Format detailed packet information for a single server."""
    log.writeln("\n" + "=" * 79)
    log.writeln(f"  [RAIDA {capture.server.raida_id}] Encryption: {format_encryption_type(encryption_type)}")
    log.writeln("")

    # Request packet
    log.writeln(f"  REQUEST PACKET (QMail Binary) ({len(capture.request_data)} bytes):")
    log.writeln(format_header_table())
    log.writeln(hex_dump(capture.request_data, 48))

    # Challenge validation (bytes 0-15 of body after header)
    if len(capture.request_data) > 32:
        challenge = capture.request_data[32:48]
        # Check if challenge has valid CRC32 in last 4 bytes
        if len(challenge) >= 16:
            random_part = challenge[:12]
            crc_part = challenge[12:16]
            import zlib
            expected_crc = zlib.crc32(random_part) & 0xFFFFFFFF
            actual_crc = struct.unpack('>I', crc_part)[0]
            if expected_crc == actual_crc:
                log.writeln("\n  Challenge: VALID \u2713")
            else:
                log.writeln("\n  Challenge: INVALID \u2717")

    # Response header
    log.writeln("\n  +-----------------------------------------------------------+")
    log.writeln("  | Response Header                                           |")
    log.writeln("  +-----------------------------------------------------------+")

    if capture.response_data and len(capture.response_data) >= 32:
        resp_header = capture.response_data[:32]
        raida_id = resp_header[2] if len(resp_header) > 2 else 0
        cmd_group = resp_header[4] if len(resp_header) > 4 else 0
        body_len = struct.unpack('>H', resp_header[22:24])[0] if len(resp_header) >= 24 else 0

        log.writeln(f"  | RAIDA ID:        {raida_id}")
        log.writeln(f"  | Status Code:     {format_status_code(capture.status_code)}")
        log.writeln(f"  | Command Group:   0x{cmd_group:02X}")
        log.writeln(f"  | Body Length:     {body_len} bytes")
        log.writeln(f"  | Response Time:   {capture.response_time_ms} ms")
        log.writeln("  +-----------------------------------------------------------+")

        # Response body hex dump
        if len(capture.response_data) > 32:
            body_len = min(len(capture.response_data) - 32, 48)
            log.writeln(f"  Response body ({len(capture.response_data) - 32} bytes, showing first {body_len}):")
            log.writeln(format_header_table())
            log.writeln(hex_dump(capture.response_data[32:32+body_len], 48))
    else:
        if capture.error_message:
            log.writeln(f"  | Status Code:     [Network: {capture.error_message}]")
        else:
            log.writeln(f"  | Status Code:     [No Response]")
        log.writeln(f"  | Response Time:   {capture.response_time_ms} ms")
        log.writeln("  +-----------------------------------------------------------+")
        log.writeln(f"  Response body: 0 bytes")


def format_task_footer(result: TestResult, log: DualLogger):
    """Format task footer."""
    duration = (result.end_time - result.start_time).total_seconds()

    log.writeln("\n  Results:")
    log.writeln(f"    Ready: {result.success_count}/{len(result.captures)} "
               f"({100*result.success_count/max(1,len(result.captures)):.1f}%)")
    if result.timeout_count > 0:
        log.writeln(f"    Timeout: {result.timeout_count}/{len(result.captures)} "
                   f"({100*result.timeout_count/max(1,len(result.captures)):.1f}%)")

    log.writeln("\n" + "=" * 72)
    log.writeln(f"TASK COMPLETE | Duration: {duration:.3f}s")
    log.writeln("=" * 72)


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_echo_request(servers: List[ServerInfo], log: DualLogger) -> TestResult:
    """
    Test basic connectivity with echo-like requests.

    This tests that servers are reachable and responding.
    """
    task_id = datetime.now().strftime("%b-%d-%y_%I-%M-%S-%p")
    result = TestResult(
        task_name="Echo/Connectivity Test",
        task_id=task_id,
        start_time=datetime.now()
    )

    format_task_header(result.task_name, task_id, result.start_time, log)

    log.writeln("\n  Server Connectivity:")
    log.writeln(f"    \u2022 Encryption: None (testing raw connectivity)")
    log.writeln(f"    \u2022 Testing {len(servers)} QMail servers...")

    # Build minimal request (just header with echo command)
    for server in servers:
        # Build a minimal 32-byte header request
        request = bytearray(34)
        request[0] = 0x01  # Version
        request[2] = server.raida_id  # RAIDA ID
        request[4] = 0x00  # Command group 0 (echo)
        request[5] = 0x00  # Command 0 (echo)
        request[32:34] = b'\x3E\x3E'  # Terminator

        capture = send_raw_request(server, bytes(request))
        result.captures.append(capture)

        if capture.success:
            result.success_count += 1
        elif "Timeout" in capture.error_message:
            result.timeout_count += 1
        else:
            result.error_count += 1

    format_response_times(result.captures, log)
    format_summary_box(result.captures, log)

    # Show errors
    log.writeln("\n  Errors:")
    for cap in result.captures:
        if not cap.success:
            format_packet_details(cap, 0, log)

    result.end_time = datetime.now()
    format_task_footer(result, log)

    return result


def test_upload_request(
    servers: List[ServerInfo],
    test_data: bytes,
    identity: Dict[str, Any],
    log: DualLogger
) -> TestResult:
    """
    Test upload request to QMail servers.

    This tests the full upload flow with real packet construction.
    """
    task_id = datetime.now().strftime("%b-%d-%y_%I-%M-%S-%p")
    result = TestResult(
        task_name="Upload Stripe Test",
        task_id=task_id,
        start_time=datetime.now()
    )

    format_task_header(result.task_name, task_id, result.start_time, log)

    # Generate file group GUID
    import uuid
    file_group_guid = uuid.uuid4().bytes

    # Create stripes from test data
    err, stripes = create_upload_stripes(test_data, num_servers=len(servers))
    err, parity = calculate_parity_from_bytes(stripes)
    all_stripes = stripes + [parity]

    log.writeln("\n  Upload Configuration:")
    log.writeln(f"    \u2022 Encryption: Type 1 (AES-128 CTR with AN)")
    log.writeln(f"    \u2022 File Size: {len(test_data)} bytes")
    log.writeln(f"    \u2022 Stripes: {len(stripes)} data + 1 parity")
    log.writeln(f"    \u2022 File Group GUID: {file_group_guid.hex()}")
    log.writeln(f"    \u2022 Sending upload requests to {len(servers)} servers...")

    # Build and send upload requests
    for i, server in enumerate(servers):
        stripe_data = all_stripes[i] if i < len(all_stripes) else b''

        # Build upload request using protocol module
        locker_code = identity.get('locker_code', os.urandom(8))
        err, request, challenge = build_complete_upload_request(
            raida_id=server.raida_id,
            denomination=identity.get('denomination', 1),
            serial_number=identity.get('serial_number', 12345678),
            device_id=identity.get('device_id', 1),
            an=identity.get('an', bytes(16)),
            file_group_guid=file_group_guid,
            locker_code=locker_code,
            storage_duration=2,  # One month
            stripe_data=stripe_data
        )

        if err != ProtocolErrorCode.SUCCESS:
            capture = PacketCapture(server=server, error_message=f"Protocol error: {err}")
            result.captures.append(capture)
            result.error_count += 1
            continue

        capture = send_raw_request(server, request)
        result.captures.append(capture)

        if capture.success and capture.status_code in [0, 250]:
            result.success_count += 1
        elif capture.success:
            result.error_count += 1
        else:
            result.timeout_count += 1

    format_response_times(result.captures, log)
    format_summary_box(result.captures, log)

    # Detailed packet info for each server
    log.writeln("\n  Detailed Packet Analysis:")
    for cap in result.captures:
        format_packet_details(cap, ENC_SHARED_SECRET, log)

    result.end_time = datetime.now()
    format_task_footer(result, log)

    return result


def test_tell_request(
    servers: List[ServerInfo],
    identity: Dict[str, Any],
    recipient: Dict[str, Any],
    log: DualLogger
) -> TestResult:
    """
    Test TELL notification request.
    """
    task_id = datetime.now().strftime("%b-%d-%y_%I-%M-%S-%p")
    result = TestResult(
        task_name="Tell Notification Test",
        task_id=task_id,
        start_time=datetime.now()
    )

    format_task_header(result.task_name, task_id, result.start_time, log)

    import uuid
    file_group_guid = uuid.uuid4().bytes
    locker_code = os.urandom(8)

    log.writeln("\n  Tell Configuration:")
    log.writeln(f"    \u2022 Encryption: Type 1 (AES-128 CTR with AN)")
    log.writeln(f"    \u2022 File Group GUID: {file_group_guid.hex()}")
    log.writeln(f"    \u2022 Locker Code: {locker_code.hex()}")
    log.writeln(f"    \u2022 Recipient: {recipient.get('serial_number', 0)}")
    log.writeln(f"    \u2022 Sending TELL to beacon server...")

    # Build tell server list using TellServer objects
    tell_servers = []
    for i, srv in enumerate(servers):
        tell_servers.append(TellServer(
            stripe_index=i,
            stripe_type=1 if i == len(servers) - 1 else 0,  # Last is parity
            ip_address=srv.host,
            port=srv.port
        ))

    # Build recipients list using TellRecipient objects
    recipients_list = [TellRecipient(
        address_type=0,  # TO recipient
        coin_id=0x0006,
        denomination=recipient.get('denomination', 1),
        domain_id=0,
        serial_number=recipient.get('serial_number', 11111111),
        locker_payment_key=bytes(16)  # Placeholder
    )]

    # Use first server as beacon
    beacon_server = servers[0]

    # Build tell request
    import time as time_module
    err, request, challenge = build_complete_tell_request(
        raida_id=beacon_server.raida_id,
        denomination=identity.get('denomination', 1),
        serial_number=identity.get('serial_number', 12345678),
        device_id=identity.get('device_id', 1),
        an=identity.get('an', bytes(16)),
        file_group_guid=file_group_guid,
        locker_code=locker_code,
        timestamp=int(time_module.time()),
        tell_type=0,  # QMAIL tell
        recipients=recipients_list,
        servers=tell_servers
    )

    if err != ProtocolErrorCode.SUCCESS:
        log.writeln(f"\n  ERROR: Failed to build tell request: {err}")
        result.error_count += 1
    else:
        capture = send_raw_request(beacon_server, request)
        result.captures.append(capture)

        if capture.success and capture.status_code in [0, 250]:
            result.success_count += 1
        elif capture.success:
            result.error_count += 1
        else:
            result.timeout_count += 1

        format_packet_details(capture, ENC_SHARED_SECRET, log)

    result.end_time = datetime.now()
    format_task_footer(result, log)

    return result


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_production_tests():
    """Run all production tests."""

    # Create logger
    log = DualLogger(LOG_FILE)

    log.writeln("=" * 72)
    log.writeln("  QMAIL SEND API - PRODUCTION INTEGRATION TEST")
    log.writeln(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.writeln(f"  Log File: {LOG_FILE}")
    log.writeln("=" * 72)

    # Test identity (replace with real values for actual testing)
    identity = {
        'denomination': 1,
        'serial_number': 12345678,  # Replace with real serial
        'device_id': 1,
        'an': bytes(16),  # Replace with real AN
    }

    # Test recipient
    recipient = {
        'denomination': 1,
        'serial_number': 11111111,  # Replace with real recipient
    }

    # Test data
    test_email = b"From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test email."

    all_results = []

    # Test 1: Echo/Connectivity
    log.writeln("\n\n")
    result = test_echo_request(PRODUCTION_SERVERS, log)
    all_results.append(result)

    # Test 2: Upload Request
    log.writeln("\n\n")
    result = test_upload_request(PRODUCTION_SERVERS, test_email, identity, log)
    all_results.append(result)

    # Test 3: Tell Request
    log.writeln("\n\n")
    result = test_tell_request(PRODUCTION_SERVERS, identity, recipient, log)
    all_results.append(result)

    # Final summary
    log.writeln("\n\n")
    log.writeln("=" * 72)
    log.writeln("  FINAL SUMMARY")
    log.writeln("=" * 72)

    total_success = sum(r.success_count for r in all_results)
    total_errors = sum(r.error_count for r in all_results)
    total_timeouts = sum(r.timeout_count for r in all_results)
    total_tests = sum(len(r.captures) for r in all_results)

    log.writeln(f"\n  Total Tests: {total_tests}")
    log.writeln(f"  Successful: {total_success}")
    log.writeln(f"  Errors: {total_errors}")
    log.writeln(f"  Timeouts: {total_timeouts}")
    log.writeln(f"\n  Success Rate: {100*total_success/max(1,total_tests):.1f}%")

    log.writeln(f"\n  Log saved to: {LOG_FILE}")
    log.writeln("=" * 72)

    log.close()

    print(f"\n\nFull log saved to: {LOG_FILE}")

    return total_errors == 0 and total_timeouts == 0


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    success = run_production_tests()
    sys.exit(0 if success else 1)
