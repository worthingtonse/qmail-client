"""
raida_diagnostics.py - RAIDA Diagnostic Tool

Usage:
    python raida_diagnostics.py [options]
    
Options:
    --raida N       Query only RAIDA N (0-24)
    --output FILE   Write detailed report to FILE
    --json          Output as JSON
    --clear         Clear diagnostic buffers on all RAIDA
    --config FILE   Use custom config file for RAIDA addresses

Example:
    python raida_diagnostics.py                    # Query all RAIDA
    python raida_diagnostics.py --raida 5          # Query only RAIDA 5
    python raida_diagnostics.py --output diag.log  # Save to file
"""

import os
import sys
import socket
import struct
import time
import threading
import argparse
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional, Any
from enum import IntEnum

# ============================================================================
# CONSTANTS
# ============================================================================

RAIDA_COUNT = 25
RAIDA_TIMEOUT = 10  # seconds for diagnostic queries
REQUEST_HEADER_SIZE = 32
RESPONSE_HEADER_SIZE = 32

# Command codes
CMD_GROUP_STATUS = 0
CMD_DIAGNOSTIC_REPORT = 4
CMD_DIAGNOSTIC_CLEAR = 5

# Coin ID for CloudCoin
COIN_ID = 0x0006

# Terminator
TERMINATOR = bytes([0x3E, 0x3E])

# Default RAIDA servers (fallback)
DEFAULT_RAIDA_SERVERS = [
    ("78.46.170.45", 50000),
    ("47.229.9.94", 50001),
    ("209.46.126.167", 50002),
    ("116.203.157.233", 50003),
    ("95.183.51.104", 50004),
    ("31.163.201.90", 50005),
    ("52.14.83.91", 50006),
    ("161.97.169.229", 50007),
    ("13.234.55.11", 50008),
    ("124.187.106.233", 50009),
    ("94.130.179.247", 50010),
    ("67.181.90.11", 50011),
    ("3.16.169.178", 50012),
    ("113.30.247.109", 50013),
    ("168.220.219.199", 50014),
    ("185.37.61.73", 50015),
    ("193.7.195.250", 50016),
    ("5.161.63.179", 50017),
    ("76.114.47.144", 50018),
    ("190.105.235.113", 50019),
    ("184.18.166.118", 50020),
    ("125.236.210.184", 50021),
    ("5.161.123.254", 50022),
    ("130.255.77.156", 50023),
    ("209.205.66.24", 50024),
]

# ============================================================================
# DIAGNOSTIC EVENT TYPES (Must match server)
# ============================================================================

class DiagEventType(IntEnum):
    NONE = 0x00
    CLIENT_REQUEST = 0x01
    CLIENT_RESPONSE = 0x02
    INTER_RAIDA_CONNECT = 0x10
    INTER_RAIDA_SEND = 0x11
    INTER_RAIDA_RECV = 0x12
    INTER_RAIDA_TIMEOUT = 0x13
    INTER_RAIDA_REQUEST = 0x20
    INTER_RAIDA_RESPONSE = 0x21
    KEY_LOOKUP = 0x30
    KEY_ENCRYPT = 0x31
    KEY_DECRYPT = 0x32
    TICKET_CREATE = 0x40
    TICKET_VALIDATE = 0x41
    TICKET_LOOKUP = 0x42
    TICKET_EXPIRED = 0x43
    FIX_RECEIVED = 0x50
    FIX_VOTE_COUNT = 0x51
    FIX_RESULT = 0x52


EVENT_TYPE_NAMES = {
    0x00: "NONE",
    0x01: "CLIENT_REQUEST",
    0x02: "CLIENT_RESPONSE",
    0x10: "INTER_RAIDA_CONNECT",
    0x11: "INTER_RAIDA_SEND",
    0x12: "INTER_RAIDA_RECV",
    0x13: "INTER_RAIDA_TIMEOUT",
    0x20: "INTER_RAIDA_REQUEST",
    0x21: "INTER_RAIDA_RESPONSE",
    0x30: "KEY_LOOKUP",
    0x31: "KEY_ENCRYPT",
    0x32: "KEY_DECRYPT",
    0x40: "TICKET_CREATE",
    0x41: "TICKET_VALIDATE",
    0x42: "TICKET_LOOKUP",
    0x43: "TICKET_EXPIRED",
    0x50: "FIX_RECEIVED",
    0x51: "FIX_VOTE_COUNT",
    0x52: "FIX_RESULT",
}

# ============================================================================
# DIAGNOSTIC ERROR CODES (Must match server)
# ============================================================================

class DiagErrorCode(IntEnum):
    SUCCESS = 0x00
    DNS_FAILED = 0x01
    CONN_REFUSED = 0x02
    CONN_TIMEOUT = 0x03
    HOST_UNREACHABLE = 0x04
    NET_UNREACHABLE = 0x05
    CONN_RESET = 0x06
    SEND_FAILED = 0x07
    RECV_FAILED = 0x08
    RECV_TIMEOUT = 0x09
    KEY_FILE_NOT_FOUND = 0x20
    KEY_FILE_UNREADABLE = 0x21
    KEY_SELECTOR_INVALID = 0x22
    KEY_PARSE_FAILED = 0x23
    ENCRYPT_FAILED = 0x40
    DECRYPT_FAILED = 0x41
    MARKER_MISMATCH = 0x42
    HMAC_MISMATCH = 0x43
    TICKET_NOT_FOUND = 0x60
    TICKET_EXPIRED = 0x61
    TICKET_ALREADY_CLAIMED = 0x62
    TICKET_POOL_FULL = 0x63
    INVALID_PACKET_SIZE = 0x80
    INVALID_RAIDA_ID = 0x81
    INVALID_COMMAND = 0x82
    COIN_NOT_FOUND = 0x83
    AN_MISMATCH = 0x84
    DEN_SN_MISMATCH = 0x85
    INSUFFICIENT_VOTES = 0xA0
    ZERO_TICKET = 0xA1


ERROR_CODE_NAMES = {
    0x00: "SUCCESS",
    0x01: "DNS_FAILED - Could not resolve hostname",
    0x02: "CONN_REFUSED - Connection refused (port closed/blocked)",
    0x03: "CONN_TIMEOUT - Connection timed out (firewall dropping)",
    0x04: "HOST_UNREACHABLE - No route to host",
    0x05: "NET_UNREACHABLE - Network unreachable",
    0x06: "CONN_RESET - Connection reset by peer",
    0x07: "SEND_FAILED - Failed to send data",
    0x08: "RECV_FAILED - Failed to receive data",
    0x09: "RECV_TIMEOUT - Receive timed out",
    0x20: "KEY_FILE_NOT_FOUND - Inter-RAIDA key file missing",
    0x21: "KEY_FILE_UNREADABLE - Cannot read key file",
    0x22: "KEY_SELECTOR_INVALID - Key selector out of range",
    0x23: "KEY_PARSE_FAILED - Failed to parse key file",
    0x40: "ENCRYPT_FAILED - AES encryption failed",
    0x41: "DECRYPT_FAILED - AES decryption failed",
    0x42: "MARKER_MISMATCH - Decrypted marker != 0xEEEE (key mismatch)",
    0x43: "HMAC_MISMATCH - HMAC verification failed",
    0x60: "TICKET_NOT_FOUND - Ticket not in pool",
    0x61: "TICKET_EXPIRED - Ticket too old",
    0x62: "TICKET_ALREADY_CLAIMED - Ticket already used",
    0x63: "TICKET_POOL_FULL - No free ticket slots",
    0x80: "INVALID_PACKET_SIZE - Wrong request size",
    0x81: "INVALID_RAIDA_ID - Bad RAIDA ID",
    0x82: "INVALID_COMMAND - Unknown command",
    0x83: "COIN_NOT_FOUND - Coin not in database",
    0x84: "AN_MISMATCH - AN does not match",
    0x85: "DEN_SN_MISMATCH - Denomination/SN mismatch in ticket",
    0xA0: "INSUFFICIENT_VOTES - Not enough votes for fix (need 14+)",
    0xA1: "ZERO_TICKET - Ticket was 0 (skipped)",
}

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DiagEntry:
    """Single diagnostic event entry."""
    timestamp: int = 0
    event_type: int = 0
    command_group: int = 0
    command_code: int = 0
    peer_id: int = 0
    status: int = 0  # 1=success, 0=fail
    error_code: int = 0
    extra: bytes = field(default_factory=lambda: bytes(16))
    message: str = ""
    
    @property
    def event_name(self) -> str:
        return EVENT_TYPE_NAMES.get(self.event_type, f"UNKNOWN_{self.event_type:02X}")
    
    @property
    def error_name(self) -> str:
        return ERROR_CODE_NAMES.get(self.error_code, f"UNKNOWN_ERROR_{self.error_code:02X}")
    
    @property
    def status_str(self) -> str:
        return "✓ PASS" if self.status == 1 else "✗ FAIL"
    
    @property
    def timestamp_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")
    
    @property
    def peer_str(self) -> str:
        if self.peer_id == 0xFF:
            return "CLIENT"
        return f"RAIDA{self.peer_id}"


@dataclass
class RaidaDiagReport:
    """Diagnostic report from a single RAIDA."""
    raida_id: int = -1
    reachable: bool = False
    error_message: str = ""
    timestamp: int = 0
    overall_status: int = 0  # 1=OK, 0=has failures
    entry_count: int = 0
    connectivity_bitmap: int = 0
    last_fix_tickets_bitmap: int = 0
    last_fix_validation_bitmap: int = 0
    last_fix_votes: int = 0
    last_fix_coin_den: int = 0
    last_fix_coin_sn: int = 0
    entries: List[DiagEntry] = field(default_factory=list)
    
    @property
    def status_str(self) -> str:
        if not self.reachable:
            return "✗ UNREACHABLE"
        return "✓ OK" if self.overall_status == 1 else "✗ HAS FAILURES"
    
    def get_connected_raida(self) -> List[int]:
        """Return list of RAIDA IDs that this RAIDA can connect to."""
        connected = []
        for i in range(25):
            if self.connectivity_bitmap & (1 << i):
                connected.append(i)
        return connected
    
    def get_disconnected_raida(self) -> List[int]:
        """Return list of RAIDA IDs that this RAIDA cannot connect to."""
        disconnected = []
        for i in range(25):
            if not (self.connectivity_bitmap & (1 << i)):
                disconnected.append(i)
        return disconnected
    
    def get_tickets_received(self) -> List[int]:
        """Return list of RAIDA IDs that provided tickets in last Fix."""
        received = []
        for i in range(25):
            if self.last_fix_tickets_bitmap & (1 << i):
                received.append(i)
        return received
    
    def get_validations_passed(self) -> List[int]:
        """Return list of RAIDA IDs whose validations passed in last Fix."""
        passed = []
        for i in range(25):
            if self.last_fix_validation_bitmap & (1 << i):
                passed.append(i)
        return passed


# ============================================================================
# PROTOCOL FUNCTIONS
# ============================================================================

def generate_challenge() -> bytes:
    """Generate 16-byte challenge (12 random + 4 CRC32)."""
    random_bytes = os.urandom(12)
    crc = zlib.crc32(random_bytes) & 0xFFFFFFFF
    return random_bytes + struct.pack('>I', crc)


def build_request_header(raida_id: int, command_group: int, command_code: int, body_length: int) -> bytes:
    """Build 32-byte request header (Type 0, unencrypted)."""
    header = bytearray(REQUEST_HEADER_SIZE)
    
    # Routing bytes (0-7)
    header[0] = 0x01  # Bitfield
    header[1] = 0x00  # Split ID
    header[2] = raida_id  # RAIDA ID
    header[3] = 0x00  # Shard ID
    header[4] = command_group  # Command Group
    header[5] = command_code  # Command Code
    struct.pack_into('>H', header, 6, COIN_ID)  # Coin ID
    
    # Presentation bytes (8-15)
    header[8] = 0x00  # Bitfield
    
    # Encryption bytes (16-23)
    header[16] = 0x00  # Encryption type = NONE
    header[17] = 0x00  # Denomination
    struct.pack_into('>I', header, 18, 0)  # Serial number
    struct.pack_into('>H', header, 22, body_length)  # Body length
    
    # Nonce bytes (24-31)
    nonce = os.urandom(8)
    header[24:32] = nonce
    
    return bytes(header)


def build_diagnostic_request(raida_id: int, clear: bool = False) -> bytes:
    """Build diagnostic request packet."""
    # Body: 16-byte challenge + 2-byte terminator
    challenge = generate_challenge()
    body = challenge + TERMINATOR
    
    command_code = CMD_DIAGNOSTIC_CLEAR if clear else CMD_DIAGNOSTIC_REPORT
    header = build_request_header(raida_id, CMD_GROUP_STATUS, command_code, len(body))
    
    return header + body


def parse_diagnostic_response(response: bytes, raida_id: int) -> RaidaDiagReport:
    """Parse diagnostic response from RAIDA."""
    report = RaidaDiagReport(raida_id=raida_id)
    
    if len(response) < RESPONSE_HEADER_SIZE:
        report.error_message = f"Response too short: {len(response)} bytes"
        return report
    
    # Parse response header
    resp_raida_id = response[0]
    resp_status = response[2]
    
    if resp_status != 0:  # STATUS_SUCCESS = 0
        report.error_message = f"Server returned error code: {resp_status} (0x{resp_status:02X})"
        return report
    
    # Get body size from header (bytes 9-11)
    body_size = (response[9] << 16) | (response[10] << 8) | response[11]
    
    body = response[RESPONSE_HEADER_SIZE:]
    if len(body) < 25:  # Minimum header size
        report.error_message = f"Body too short: {len(body)} bytes"
        return report
    
    report.reachable = True
    
    # Parse body header (25 bytes)
    ptr = 0
    
    # RAIDA ID (1 byte)
    report.raida_id = body[ptr]
    ptr += 1
    
    # Timestamp (4 bytes, big-endian)
    report.timestamp = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
    ptr += 4
    
    # Overall status (1 byte)
    report.overall_status = body[ptr]
    ptr += 1
    
    # Entry count (1 byte)
    report.entry_count = body[ptr]
    ptr += 1
    
    # Connectivity bitmap (4 bytes)
    report.connectivity_bitmap = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
    ptr += 4
    
    # Last Fix tickets bitmap (4 bytes)
    report.last_fix_tickets_bitmap = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
    ptr += 4
    
    # Last Fix validation bitmap (4 bytes)
    report.last_fix_validation_bitmap = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
    ptr += 4
    
    # Last Fix votes (1 byte)
    report.last_fix_votes = body[ptr]
    ptr += 1
    
    # Last Fix coin den (1 byte)
    report.last_fix_coin_den = body[ptr]
    ptr += 1
    
    # Last Fix coin SN (4 bytes)
    report.last_fix_coin_sn = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
    ptr += 4
    
    # Parse entries (60 bytes each)
    ENTRY_SIZE = 60
    for i in range(report.entry_count):
        if ptr + ENTRY_SIZE > len(body):
            break
        
        entry = DiagEntry()
        entry.timestamp = (body[ptr] << 24) | (body[ptr+1] << 16) | (body[ptr+2] << 8) | body[ptr+3]
        ptr += 4
        
        entry.event_type = body[ptr]
        ptr += 1
        
        entry.command_group = body[ptr]
        ptr += 1
        
        entry.command_code = body[ptr]
        ptr += 1
        
        entry.peer_id = body[ptr]
        ptr += 1
        
        entry.status = body[ptr]
        ptr += 1
        
        entry.error_code = body[ptr]
        ptr += 1
        
        ptr += 2  # Reserved
        
        entry.extra = bytes(body[ptr:ptr+16])
        ptr += 16
        
        # Message (32 bytes, null-terminated string)
        msg_bytes = body[ptr:ptr+32]
        try:
            entry.message = msg_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        except:
            entry.message = ""
        ptr += 32
        
        report.entries.append(entry)
    
    return report


# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================

def query_raida(raida_id: int, host: str, port: int, clear: bool = False) -> RaidaDiagReport:
    """Query a single RAIDA for diagnostic information."""
    report = RaidaDiagReport(raida_id=raida_id)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(RAIDA_TIMEOUT)
        sock.connect((host, port))
        
        request = build_diagnostic_request(raida_id, clear)
        sock.sendall(request)
        
        # Receive response header
        response_header = b''
        while len(response_header) < RESPONSE_HEADER_SIZE:
            chunk = sock.recv(RESPONSE_HEADER_SIZE - len(response_header))
            if not chunk:
                report.error_message = "Connection closed while reading header"
                sock.close()
                return report
            response_header += chunk
        
        # Get body size from header
        body_size = (response_header[9] << 16) | (response_header[10] << 8) | response_header[11]
        
        # Receive body
        response_body = b''
        while len(response_body) < body_size:
            chunk = sock.recv(min(4096, body_size - len(response_body)))
            if not chunk:
                break
            response_body += chunk
        
        sock.close()
        
        return parse_diagnostic_response(response_header + response_body, raida_id)
        
    except socket.timeout:
        report.error_message = f"Connection timeout to {host}:{port}"
        return report
    except ConnectionRefusedError:
        report.error_message = f"Connection refused by {host}:{port}"
        return report
    except Exception as e:
        report.error_message = f"Error: {str(e)}"
        return report


def query_all_raida(servers: List[Tuple[str, int]], clear: bool = False) -> List[RaidaDiagReport]:
    """Query all RAIDA servers in parallel."""
    reports = [None] * RAIDA_COUNT
    threads = []
    
    def query_thread(raida_id: int, host: str, port: int):
        reports[raida_id] = query_raida(raida_id, host, port, clear)
    
    for i, (host, port) in enumerate(servers):
        if i >= RAIDA_COUNT:
            break
        t = threading.Thread(target=query_thread, args=(i, host, port))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Fill any missing reports
    for i in range(RAIDA_COUNT):
        if reports[i] is None:
            reports[i] = RaidaDiagReport(raida_id=i, error_message="Not queried")
    
    return reports


# ============================================================================
# REPORT GENERATION
# ============================================================================

def print_separator(char: str = "─", width: int = 80):
    """Print a separator line."""
    print(char * width)


def print_header(title: str, width: int = 80):
    """Print a header with border."""
    print("═" * width)
    print(f" {title}".center(width))
    print("═" * width)


def generate_summary_report(reports: List[RaidaDiagReport]) -> str:
    """Generate summary table of all RAIDA."""
    lines = []
    
    lines.append("")
    lines.append("RAIDA  STATUS         ENTRIES  CONNECTIVITY  LAST_FIX_VOTES  ERROR")
    lines.append("─" * 80)
    
    for report in reports:
        if not report.reachable:
            lines.append(f"  {report.raida_id:2d}   ✗ UNREACHABLE  -        -             -               {report.error_message[:30]}")
        else:
            conn_ok = bin(report.connectivity_bitmap).count('1')
            status = "✓ OK" if report.overall_status == 1 else "✗ FAIL"
            fix_info = f"{report.last_fix_votes}/14" if report.last_fix_coin_sn > 0 else "-"
            lines.append(f"  {report.raida_id:2d}   {status:13s}  {report.entry_count:3d}      {conn_ok:2d}/24          {fix_info:14s}  ")
    
    return "\n".join(lines)


def generate_failure_details(reports: List[RaidaDiagReport]) -> str:
    """Generate detailed failure information."""
    lines = []
    
    for report in reports:
        if not report.reachable:
            continue
        
        # Find failure entries
        failures = [e for e in report.entries if e.status == 0]
        if not failures:
            continue
        
        lines.append("")
        lines.append(f"FAILURE DETAILS FOR RAIDA {report.raida_id}")
        lines.append("─" * 80)
        
        for entry in failures:
            lines.append(f"[{entry.timestamp_str}] {entry.event_name}")
            lines.append(f"           Peer: {entry.peer_str}")
            lines.append(f"           Command: Group {entry.command_group}, Code {entry.command_code}")
            lines.append(f"           Status: {entry.status_str}")
            lines.append(f"           Error: {entry.error_name}")
            if entry.message:
                lines.append(f"           Message: {entry.message}")
            lines.append("")
    
    return "\n".join(lines)


def generate_connectivity_matrix(reports: List[RaidaDiagReport]) -> str:
    """Generate inter-RAIDA connectivity matrix."""
    lines = []
    
    lines.append("")
    lines.append("INTER-RAIDA CONNECTIVITY MATRIX")
    lines.append("(Row = Source RAIDA, Column = Can connect to)")
    lines.append("─" * 80)
    
    # Header row
    header = "     "
    for i in range(25):
        header += f"{i:2d} "
    lines.append(header)
    lines.append("")
    
    for report in reports:
        if not report.reachable:
            row = f" {report.raida_id:2d}  " + " ? " * 25
        else:
            row = f" {report.raida_id:2d}  "
            for i in range(25):
                if i == report.raida_id:
                    row += " - "
                elif report.connectivity_bitmap & (1 << i):
                    row += " ✓ "
                else:
                    row += " ✗ "
        lines.append(row)
    
    return "\n".join(lines)


def generate_last_fix_analysis(reports: List[RaidaDiagReport]) -> str:
    """Generate analysis of the last Fix command on each RAIDA with failures."""
    lines = []
    
    for report in reports:
        if not report.reachable:
            continue
        if report.last_fix_coin_sn == 0:
            continue
        if report.last_fix_votes >= 14:
            continue  # Fix succeeded, skip
        
        lines.append("")
        lines.append(f"LAST FIX ANALYSIS FOR RAIDA {report.raida_id}")
        lines.append("─" * 80)
        lines.append(f"Coin: denomination={report.last_fix_coin_den}, SN={report.last_fix_coin_sn}")
        lines.append(f"Votes received: {report.last_fix_votes}/14 (INSUFFICIENT)")
        lines.append("")
        
        tickets_received = report.get_tickets_received()
        validations_passed = report.get_validations_passed()
        
        lines.append(f"Tickets received from {len(tickets_received)}/25 RAIDA: {tickets_received}")
        lines.append(f"Validations passed from {len(validations_passed)}/25 RAIDA: {validations_passed}")
        lines.append("")
        
        # Analyze what went wrong
        missing_tickets = [i for i in range(25) if i not in tickets_received and i != report.raida_id]
        failed_validations = [i for i in tickets_received if i not in validations_passed]
        
        if missing_tickets:
            lines.append(f"RAIDA that didn't provide tickets (client-side issue): {missing_tickets}")
        
        if failed_validations:
            lines.append(f"RAIDA whose validations failed (inter-RAIDA issue): {failed_validations}")
            lines.append("")
            lines.append("Check these specific failures in the event log above.")
        
        # Check connectivity for failed validations
        disconnected = report.get_disconnected_raida()
        conn_issues = [r for r in failed_validations if r in disconnected]
        if conn_issues:
            lines.append("")
            lines.append(f"RAIDA with connectivity issues: {conn_issues}")
            lines.append("These RAIDA could not be reached from RAIDA {report.raida_id}")
    
    return "\n".join(lines)


def generate_root_cause_analysis(reports: List[RaidaDiagReport]) -> str:
    """Attempt to identify root cause of failures."""
    lines = []
    
    lines.append("")
    lines.append("ROOT CAUSE ANALYSIS")
    lines.append("═" * 80)
    
    # Count issues
    unreachable_count = sum(1 for r in reports if not r.reachable)
    has_failures_count = sum(1 for r in reports if r.reachable and r.overall_status == 0)
    
    if unreachable_count > 0:
        lines.append(f"• {unreachable_count} RAIDA server(s) are UNREACHABLE from this client")
        unreachable = [r.raida_id for r in reports if not r.reachable]
        lines.append(f"  Unreachable: {unreachable}")
        lines.append("  → Check network connectivity, firewall rules, or if servers are running")
        lines.append("")
    
    # Analyze error patterns
    error_counts: Dict[int, int] = {}
    for report in reports:
        for entry in report.entries:
            if entry.status == 0:
                error_counts[entry.error_code] = error_counts.get(entry.error_code, 0) + 1
    
    if error_counts:
        lines.append("Error frequency across all RAIDA:")
        for err_code, count in sorted(error_counts.items(), key=lambda x: -x[1]):
            err_name = ERROR_CODE_NAMES.get(err_code, f"UNKNOWN_{err_code:02X}")
            lines.append(f"  • {err_name}: {count} occurrence(s)")
        lines.append("")
    
    # Specific recommendations
    if DiagErrorCode.CONN_REFUSED in error_counts or DiagErrorCode.CONN_TIMEOUT in error_counts:
        lines.append("NETWORK ISSUES DETECTED:")
        lines.append("  • Some inter-RAIDA connections are failing")
        lines.append("  • Check firewall rules between RAIDA servers")
        lines.append("  • Verify all RAIDA services are running")
        lines.append("")
    
    if DiagErrorCode.KEY_FILE_NOT_FOUND in error_counts:
        lines.append("KEY FILE ISSUES DETECTED:")
        lines.append("  • Some inter-RAIDA key files are missing")
        lines.append("  • Check /opt/raidaX/Data/inter_raida_encryption_keys/")
        lines.append("  • Ensure key files exist for all RAIDA pairs")
        lines.append("")
    
    if DiagErrorCode.MARKER_MISMATCH in error_counts:
        lines.append("KEY MISMATCH ISSUES DETECTED:")
        lines.append("  • Decryption is producing wrong marker bytes")
        lines.append("  • This indicates the encryption keys don't match between RAIDA")
        lines.append("  • Verify R{X}-256/R{Y}.toml matches R{Y}-256/R{X}.toml")
        lines.append("")
    
    if DiagErrorCode.INSUFFICIENT_VOTES in error_counts:
        lines.append("INSUFFICIENT VOTES FOR FIX:")
        lines.append("  • Fix commands are not getting enough confirmations (need 14+)")
        lines.append("  • This is usually caused by inter-RAIDA connectivity/key issues above")
        lines.append("")
    
    if not error_counts:
        lines.append("No errors detected in diagnostic logs.")
        lines.append("If healing is still failing, try:")
        lines.append("  1. Run healing again to generate fresh diagnostic data")
        lines.append("  2. Check client-side logs for issues before requests reach servers")
        lines.append("")
    
    return "\n".join(lines)


def generate_full_report(reports: List[RaidaDiagReport]) -> str:
    """Generate complete diagnostic report."""
    lines = []
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("")
    print_header(f"RAIDA DIAGNOSTIC REPORT - {timestamp}")
    
    lines.append(generate_summary_report(reports))
    lines.append(generate_failure_details(reports))
    lines.append(generate_last_fix_analysis(reports))
    lines.append(generate_connectivity_matrix(reports))
    lines.append(generate_root_cause_analysis(reports))
    
    return "\n".join(lines)


# ============================================================================
# MAIN
# ============================================================================

def load_raida_servers(config_file: Optional[str] = None) -> List[Tuple[str, int]]:
    """Load RAIDA server addresses from config file or use defaults."""
    if config_file and os.path.exists(config_file):
        try:
            import tomllib
            with open(config_file, 'rb') as f:
                config = tomllib.load(f)
            
            if 'raida_servers' in config:
                servers = []
                for entry in config['raida_servers']:
                    servers.append((entry['address'], entry['port']))
                return servers
        except Exception as e:
            print(f"Warning: Failed to load config file: {e}")
    
    return DEFAULT_RAIDA_SERVERS


def main():
    parser = argparse.ArgumentParser(
        description="RAIDA Diagnostic Tool - Debug healing and inter-RAIDA communication"
    )
    parser.add_argument('--raida', type=int, help='Query only specific RAIDA (0-24)')
    parser.add_argument('--output', type=str, help='Write detailed report to file')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--clear', action='store_true', help='Clear diagnostic buffers')
    parser.add_argument('--config', type=str, help='Config file with RAIDA addresses')
    
    args = parser.parse_args()
    
    # Load RAIDA servers
    servers = load_raida_servers(args.config)
    
    print_header("RAIDA DIAGNOSTIC TOOL")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    if args.clear:
        print("Clearing diagnostic buffers on all RAIDA...")
        reports = query_all_raida(servers, clear=True)
        cleared = sum(1 for r in reports if r.reachable)
        print(f"Cleared {cleared}/{RAIDA_COUNT} RAIDA diagnostic buffers")
        return
    
    if args.raida is not None:
        if args.raida < 0 or args.raida >= RAIDA_COUNT:
            print(f"Error: RAIDA ID must be 0-{RAIDA_COUNT-1}")
            sys.exit(1)
        
        print(f"Querying RAIDA {args.raida}...")
        host, port = servers[args.raida]
        report = query_raida(args.raida, host, port)
        reports = [report]
    else:
        print(f"Querying all {RAIDA_COUNT} RAIDA servers...")
        reports = query_all_raida(servers)
    
    # Generate report
    if args.json:
        # JSON output
        output = []
        for r in reports:
            entry = {
                'raida_id': r.raida_id,
                'reachable': r.reachable,
                'overall_status': r.overall_status,
                'error_message': r.error_message,
                'entry_count': r.entry_count,
                'connectivity_bitmap': r.connectivity_bitmap,
                'last_fix_votes': r.last_fix_votes,
                'entries': [
                    {
                        'timestamp': e.timestamp,
                        'event_type': e.event_name,
                        'peer_id': e.peer_id,
                        'status': e.status,
                        'error_code': e.error_code,
                        'error_name': e.error_name,
                        'message': e.message,
                    }
                    for e in r.entries
                ]
            }
            output.append(entry)
        
        json_str = json.dumps(output, indent=2)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(json_str)
            print(f"JSON report written to {args.output}")
        else:
            print(json_str)
    else:
        # Text output
        report_text = generate_full_report(reports)
        
        # Always print to console
        print(generate_summary_report(reports))
        
        # Check for failures and print details
        has_failures = any(r.reachable and r.overall_status == 0 for r in reports)
        unreachable = sum(1 for r in reports if not r.reachable)
        
        if has_failures or unreachable > 0:
            print(generate_failure_details(reports))
            print(generate_last_fix_analysis(reports))
            print(generate_root_cause_analysis(reports))
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\nFull report written to {args.output}")
    
    # Summary
    print()
    print_separator("═")
    reachable = sum(1 for r in reports if r.reachable)
    failures = sum(1 for r in reports if r.reachable and r.overall_status == 0)
    print(f"Summary: {reachable}/{len(reports)} RAIDA reachable, {failures} with recent failures")
    print_separator("═")


if __name__ == "__main__":
    import zlib  # Needed for generate_challenge
    main()