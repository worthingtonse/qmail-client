"""
locker_download.py - Locker Download Module for QMail Client

This module handles downloading CloudCoins from RAIDA lockers.
When QMail receives a Tell notification (from PING or PEEK), it contains
a locker code that can be used to retrieve coins.

Author: Claude Opus 4.5
Version: 2.0.0

Workflow (Updated for Command 8- DOWNLOAD):
1. Receive locker code (8 bytes) from Tell notification
2. Derive 25 locker keys: MD5(raida_id + locker_code_hex) with 0xFF padding
3. Generate 25 unique seeds (one per RAIDA for security)
4. Send RAIDA Locker DOWNLOAD (command 8) to all RAIDAs in parallel
5. Parse response to get coin list (denomination, serial_number)
6. Compute ANs locally: MD5("{raida_id}{serial_number}{seed_hex}")
7. Save coins to Fracked folder as .bin files

Usage:
    from locker_download import download_from_locker, LockerDownloadResult

    result, coins = await download_from_locker(
        locker_code=locker_code_bytes,
        wallet_path="Data/Wallets/Default",
        db_handle=db,
        logger_handle=logger
    )

    if result == LockerDownloadResult.SUCCESS:
        print(f"Downloaded {len(coins)} coins")
"""

import os
import asyncio
import secrets
import struct
import hashlib
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import IntEnum

# Import protocol functions for locker commands
try:
    from protocol import (
        ProtocolErrorCode,
        build_complete_locker_download_request,
        parse_locker_download_response,
        decrypt_locker_response,
    )
    from key_manager import get_keys_from_locker_code
    from cloudcoin import (
        LockerCoin, CloudCoinErrorCode,
        write_coin_file, generate_coin_filename,
        CC_RAIDA_COUNT, CC_AN_LENGTH,
    )
    from network_async import (
        connect_async, disconnect_async, send_raw_request_async,
        NetworkErrorCode, ServerInfo, AsyncConnection,
    )
    from wallet_structure import initialize_wallet_structure
except ImportError:
    # Fallback for standalone testing
    from protocol import (
        ProtocolErrorCode,
        build_complete_locker_download_request,
        parse_locker_download_response,
        decrypt_locker_response,
    )
    from key_manager import get_keys_from_locker_code
    from cloudcoin import (
        LockerCoin, CloudCoinErrorCode,
        write_coin_file, generate_coin_filename,
        CC_RAIDA_COUNT, CC_AN_LENGTH,
    )
    from network_async import (
        connect_async, disconnect_async, send_raw_request_async,
        NetworkErrorCode, ServerInfo, AsyncConnection,
    )
    from wallet_structure import initialize_wallet_structure

# Import logger
try:
    from logger import log_error, log_info, log_debug, log_warning
except ImportError:
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")


# ============================================================================
# CONSTANTS
# ============================================================================

# Module context for logging
LOCKER_CONTEXT = "LockerDownload"

# RAIDA configuration
RAIDA_COUNT = 25
MINIMUM_PASS_COUNT = 13  # Need 13/25 for consensus (majority)
AN_LENGTH = 16

# Default timeouts (milliseconds)
DEFAULT_DOWNLOAD_TIMEOUT_MS = 15000  # 15 seconds for DOWNLOAD command

# RAIDA server discovery URL
RAIDA_SERVERS_URL = "https://raida11.cloudcoin.global/service/raida_servers"


# ============================================================================
# RESULT CODES
# ============================================================================

class LockerDownloadResult(IntEnum):
    """Result codes for locker download operations."""
    SUCCESS = 0
    ERR_INVALID_LOCKER_CODE = 1
    ERR_LOCKER_NOT_FOUND = 2
    ERR_LOCKER_EMPTY = 3
    ERR_NETWORK_ERROR = 4
    ERR_INSUFFICIENT_RESPONSES = 5
    ERR_FILE_WRITE_ERROR = 6
    ERR_NO_RAIDA_SERVERS = 7
    ERR_KEY_DERIVATION_FAILED = 8
    ERR_PROTOCOL_ERROR = 9


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DownloadedCoin:
    """
    Coin data structure for tracking during download.

    With the new DOWNLOAD command (85), we no longer need PANs.
    ANs are computed locally using: MD5("{raida_id}{serial_number}{seed_hex}")
    """
    denomination: int
    serial_number: int
    ans: List[bytes] = field(default_factory=list)   # 25 ANs (computed from seeds)
    statuses: List[bool] = field(default_factory=list)  # 25 pass/fail results

    def to_locker_coin(self) -> LockerCoin:
        """Convert to LockerCoin for file writing."""
        # Build POWN string from statuses
        pown_chars = []
        for status in self.statuses:
            pown_chars.append('p' if status else 'f')
        pown_string = ''.join(pown_chars).ljust(25, 'u')

        return LockerCoin(
            serial_number=self.serial_number,
            denomination=self.denomination,
            ans=self.ans,
            pown_string=pown_string
        )

    @property
    def pass_count(self) -> int:
        """Count successful RAIDA responses."""
        return sum(self.statuses)


# ============================================================================
# RAIDA SERVER FUNCTIONS
# ============================================================================

async def get_raida_servers(
    db_handle: Any,
    logger_handle: Optional[object] = None
) -> List[ServerInfo]:
    """
    Get list of 25 RAIDA servers.

    First tries database, then fetches from RAIDA_SERVERS_URL.

    Args:
        db_handle: Database handle (may have get_raida_servers method)
        logger_handle: Optional logger handle

    Returns:
        List of 25 ServerInfo objects, or empty list on error
    """
    servers = []

    # Try database first
    if db_handle is not None:
        try:
            if hasattr(db_handle, 'get_raida_servers'):
                servers = db_handle.get_raida_servers()
            elif hasattr(db_handle, 'raida_servers'):
                servers = db_handle.raida_servers
        except Exception as e:
            log_debug(logger_handle, LOCKER_CONTEXT,
                      f"Could not get servers from database: {e}")

    if servers and len(servers) == RAIDA_COUNT:
        log_debug(logger_handle, LOCKER_CONTEXT,
                  f"Got {len(servers)} RAIDA servers from database")
        return servers

    # Fetch from URL
    log_info(logger_handle, LOCKER_CONTEXT,
             f"Fetching RAIDA servers from {RAIDA_SERVERS_URL}")

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(RAIDA_SERVERS_URL, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    servers = _parse_raida_servers_response(data, logger_handle)
                    if servers and len(servers) == RAIDA_COUNT:
                        log_info(logger_handle, LOCKER_CONTEXT,
                                 f"Fetched {len(servers)} RAIDA servers from URL")
                        return servers
    except ImportError:
        log_warning(logger_handle, LOCKER_CONTEXT,
                    "aiohttp not installed, using hardcoded servers")
    except Exception as e:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Failed to fetch RAIDA servers", str(e))

    # Fallback: hardcoded default servers
    servers = _get_default_raida_servers()
    log_warning(logger_handle, LOCKER_CONTEXT,
                f"Using {len(servers)} hardcoded default RAIDA servers")
    return servers


def _parse_raida_servers_response(
    data: Dict,
    logger_handle: Optional[object] = None
) -> List[ServerInfo]:
    """Parse RAIDA servers from JSON response."""
    servers = []
    try:
        server_list = data.get('servers', data.get('raida_servers', []))
        for item in server_list:
            raida_id = item.get('raida_id', item.get('id', len(servers)))
            host = item.get('host', item.get('ip', ''))
            port = item.get('port', 50000 + raida_id)

            if host:
                servers.append(ServerInfo(
                    host=host,
                    port=int(port),
                    raida_id=int(raida_id),
                    shard_id=0
                ))
    except Exception as e:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Failed to parse RAIDA servers", str(e))
    return servers


def _get_default_raida_servers() -> List[ServerInfo]:
    """Get hardcoded default RAIDA servers with actual IP addresses."""
    # Actual RAIDA server IP addresses (from config.py)
    raida_ips = [
        "78.46.170.45",      # RAIDA 0
        "47.229.9.94",       # RAIDA 1
        "209.46.126.167",    # RAIDA 2
        "116.203.157.233",   # RAIDA 3
        "95.183.51.104",     # RAIDA 4
        "31.163.201.90",     # RAIDA 5
        "52.14.83.91",       # RAIDA 6
        "161.97.169.229",    # RAIDA 7
        "13.234.55.11",      # RAIDA 8
        "124.187.106.233",   # RAIDA 9
        "94.130.179.247",    # RAIDA 10
        "67.181.90.11",      # RAIDA 11
        "3.16.169.178",      # RAIDA 12
        "113.30.247.109",    # RAIDA 13
        "168.220.219.199",   # RAIDA 14
        "185.37.61.73",      # RAIDA 15
        "193.7.195.250",     # RAIDA 16
        "5.161.63.179",      # RAIDA 17
        "76.114.47.144",     # RAIDA 18
        "190.105.235.113",   # RAIDA 19
        "184.18.166.118",    # RAIDA 20
        "125.236.210.184",   # RAIDA 21
        "5.161.123.254",     # RAIDA 22
        "130.255.77.156",    # RAIDA 23
        "209.205.66.24",     # RAIDA 24
    ]

    servers = []
    for i in range(RAIDA_COUNT):
        servers.append(ServerInfo(
            host=raida_ips[i],
            port=50000 + i,
            raida_id=i,
            shard_id=0
        ))
    return servers


# ============================================================================
# AN COMPUTATION FUNCTION
# ============================================================================

def compute_coin_an(denomination: int, serial_number: int, seed: bytes) -> bytes:
    """
    Computes the NEW Authenticity Number for a downloaded coin.
    Matches server formula: MD5(binary: 1-byte Denom + 4-byte SN + 16-byte Seed) + 0xFFFFFFFF
    """
    # 1. Binary concatenation: 1 byte Denom + 4 byte SN + 16 byte Seed = 21 bytes
    # Use '>' for Big Endian to match the server's 'put_u32'
    binary_input = struct.pack(">B", denomination) + struct.pack(">I", serial_number) + seed
    
    # 2. Hash the 21-byte buffer
    digest = bytearray(hashlib.md5(binary_input).digest())
    
    # 3. CRUCIAL: Set the last 4 bytes to 0xFF for locker compatibility
    digest[12:16] = b'\xff\xff\xff\xff'
    
    return bytes(digest)

# ============================================================================
# LOCKER DOWNLOAD FUNCTIONS (Command 8)
# ============================================================================

async def _download_single_raida(
    raida_id: int,
    locker_code_str: str,  # FIXED: Changed from locker_key: bytes
    seed: bytes,
    server: ServerInfo,
    timeout_ms: int = DEFAULT_DOWNLOAD_TIMEOUT_MS,
    logger_handle: Optional[object] = None
) -> Tuple[NetworkErrorCode, List[Tuple[int, int]]]:
    """
    Send DOWNLOAD request to a single RAIDA.

    The DOWNLOAD command (8) replaces the old PEEK + REMOVE flow.
    It returns the list of coins in the locker, and the RAIDA updates
    each coin's AN using the seed provided.

    Args:
        raida_id: RAIDA server ID (0-24)
        locker_code_str: Locker code string (e.g., "ABC-1234") - NOT bytes!
        seed: 16-byte random seed for AN generation (unique per RAIDA!)
        server: ServerInfo for the RAIDA
        timeout_ms: Request timeout in milliseconds
        logger_handle: Optional logger handle

    Returns:
        Tuple of (error_code, [(denomination, serial_number), ...])
    """
    conn = None
    try:
        # Build complete request (header + payload)
        # FIXED: Use locker_code_str parameter name to match protocol.py signature
        err, request, challenge, nonce = build_complete_locker_download_request(
            raida_id=raida_id,
            locker_code_str=locker_code_str,  # FIXED: Correct parameter name
            seed=seed,
            logger_handle=logger_handle
        )
        if err != ProtocolErrorCode.SUCCESS:
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} failed to build request", f"error={err}")
            return NetworkErrorCode.ERR_SEND_FAILED, []

        # DEBUG: Print raw request details
        log_debug(logger_handle, LOCKER_CONTEXT,
                 f"RAIDA {raida_id} request: total={len(request)} bytes")

        # Connect to server
        err, conn = await connect_async(
            server_info=server,
            logger_handle=logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} connection failed", f"error={err}")
            return err, []

        # Send raw pre-built request and receive response
        err, response_header, response_body = await send_raw_request_async(
            conn=conn,
            raw_request=request,
            timeout_ms=timeout_ms,
            logger_handle=logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} send/receive failed", f"error={err}")
            return err, []

        # Check response status
        if response_header:
            status_code = response_header.status
            log_debug(logger_handle, LOCKER_CONTEXT,
                     f"RAIDA {raida_id} response: status={status_code} (0x{status_code:02x}), "
                     f"body_size={response_header.body_size}")
            
            # Check for error status codes
            if status_code not in (250, 241):  # SUCCESS or ALL_PASS
                log_warning(logger_handle, LOCKER_CONTEXT,
                           f"RAIDA {raida_id} returned status {status_code}")
                # Don't fail immediately - locker might just be empty on this RAIDA

        # For encryption type 0 (no encryption), use response body directly
        decrypted = response_body

        # Parse coin list
        err, coins = parse_locker_download_response(decrypted, logger_handle)
        if err != ProtocolErrorCode.SUCCESS:
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} failed to parse response", f"error={err}")
            return NetworkErrorCode.ERR_INVALID_RESPONSE, []

        log_debug(logger_handle, LOCKER_CONTEXT,
                  f"RAIDA {raida_id} DOWNLOAD: {len(coins)} coins")
        return NetworkErrorCode.SUCCESS, coins

    except asyncio.TimeoutError:
        log_warning(logger_handle, LOCKER_CONTEXT,
                    f"RAIDA {raida_id} DOWNLOAD timeout")
        return NetworkErrorCode.ERR_TIMEOUT, []
    except Exception as e:
        log_error(logger_handle, LOCKER_CONTEXT,
                  f"RAIDA {raida_id} DOWNLOAD exception", str(e))
        # FIXED: Use ERR_INTERNAL instead of non-existent ERR_UNKNOWN
        return NetworkErrorCode.ERR_INTERNAL, []
    finally:
        if conn:
            await disconnect_async(conn, logger_handle)


async def _download_all_raidas(
    locker_code_str: str,  # FIXED: Changed from locker_keys: List[bytes]
    seeds: List[bytes],
    servers: List[ServerInfo],
    timeout_ms: int = DEFAULT_DOWNLOAD_TIMEOUT_MS,
    logger_handle: Optional[object] = None
) -> Tuple[int, Dict[int, List[Tuple[int, int]]]]:
    """
    Send DOWNLOAD to all 25 RAIDAs in parallel.

    Args:
        locker_code_str: The locker code string (e.g., "ABC-1234")
        seeds: List of 25 unique seeds (one per RAIDA for security!)
        servers: List of 25 ServerInfo objects
        timeout_ms: Request timeout
        logger_handle: Optional logger handle

    Returns:
        Tuple of (success_count, {raida_id: [(denom, sn), ...]})
    """
    tasks = []
    for raida_id in range(RAIDA_COUNT):
        task = _download_single_raida(
            raida_id=raida_id,
            locker_code_str=locker_code_str,  # FIXED: Pass string, not bytes
            seed=seeds[raida_id],
            server=servers[raida_id],
            timeout_ms=timeout_ms,
            logger_handle=logger_handle
        )
        tasks.append(task)

    # Run all DOWNLOAD requests in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results per RAIDA
    success_count = 0
    coin_lists_per_raida = {}

    for raida_id, result in enumerate(results):
        if isinstance(result, Exception):
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} DOWNLOAD exception", str(result))
            continue

        err, coins = result
        if err == NetworkErrorCode.SUCCESS:
            success_count += 1
            coin_lists_per_raida[raida_id] = coins
        else:
            log_debug(logger_handle, LOCKER_CONTEXT,
                      f"RAIDA {raida_id} DOWNLOAD failed: {err}")

    log_info(logger_handle, LOCKER_CONTEXT,
             f"DOWNLOAD complete: {success_count}/{RAIDA_COUNT} success")

    return success_count, coin_lists_per_raida

# ============================================================================
# MAIN DOWNLOAD FUNCTION
# ============================================================================

# async def download_from_locker(
#     locker_code: bytes,
#     wallet_path: str,
#     db_handle: Any = None,
#     logger_handle: Optional[object] = None
# ) -> Tuple[LockerDownloadResult, List[LockerCoin]]:
#     """
#     Download CloudCoins from a RAIDA locker using new DOWNLOAD command (85).

#     This is the main async function for locker download. Suitable for
#     direct calls or API use.

#     Workflow (Updated for Command 8):
#     1. Validate locker code (must be 8 bytes)
#     2. Derive 25 locker keys using MD5(raida_id + locker_code) + 0xFF padding
#     3. Generate 25 unique seeds (one per RAIDA for security!)
#     4. Get RAIDA server list
#     5. Parallel DOWNLOAD to all 25 RAIDAs (replaces PEEK + REMOVE)
#     6. Check consensus (need >= 13 successful responses)
#     7. Merge coin lists and compute ANs locally
#     8. Save coins to Fracked folder

#     Args:
#         locker_code: 8-byte locker code from Tell notification
#         wallet_path: Path to wallet folder (coins go to Fracked subfolder)
#         db_handle: Database handle for RAIDA server lookup
#         logger_handle: Optional logger handle

#     Returns:
#         Tuple of (result_code, list_of_LockerCoin)
#         On success, coins are saved to wallet_path/Fracked/
#     """
#     log_info(logger_handle, LOCKER_CONTEXT,
#              f"Starting locker download for {locker_code.hex()[:16]}...")

#     # 1. Validate locker code
#     if not locker_code or len(locker_code) < 8:
#         log_error(logger_handle, LOCKER_CONTEXT,
#                   "Invalid locker code", f"length={len(locker_code) if locker_code else 0}")
#         return LockerDownloadResult.ERR_INVALID_LOCKER_CODE, []

#     # Use first 8 bytes
#     locker_code = locker_code[:8]

#     # 2. Derive 25 locker keys
#     try:
#         locker_keys = get_keys_from_locker_code(locker_code)
#         if len(locker_keys) != RAIDA_COUNT:
#             raise ValueError(f"Expected {RAIDA_COUNT} keys, got {len(locker_keys)}")
#     except Exception as e:
#         log_error(logger_handle, LOCKER_CONTEXT,
#                   "Key derivation failed", str(e))
#         return LockerDownloadResult.ERR_KEY_DERIVATION_FAILED, []

#     log_debug(logger_handle, LOCKER_CONTEXT,
#               f"Derived {len(locker_keys)} locker keys")

#     # 3. Generate 25 unique seeds (one per RAIDA for security!)
#     # Each RAIDA gets a unique seed so administrators can't compute other RAIDAs' ANs
#     seeds = [secrets.token_bytes(AN_LENGTH) for _ in range(RAIDA_COUNT)]
#     log_debug(logger_handle, LOCKER_CONTEXT,
#               f"Generated {len(seeds)} unique seeds for AN generation")

#     # 4. Get RAIDA servers
#     servers = await get_raida_servers(db_handle, logger_handle)
#     if not servers or len(servers) != RAIDA_COUNT:
#         log_error(logger_handle, LOCKER_CONTEXT,
#                   "Failed to get RAIDA servers",
#                   f"got {len(servers) if servers else 0} servers")
#         return LockerDownloadResult.ERR_NO_RAIDA_SERVERS, []

#     # 5. Parallel DOWNLOAD to all RAIDAs (single command replaces PEEK + REMOVE)
#     download_success, coin_lists_per_raida = await _download_all_raidas(
#         locker_keys, seeds, servers, logger_handle=logger_handle
#     )

#     # 6. Check consensus
#     if download_success < MINIMUM_PASS_COUNT:
#         log_error(logger_handle, LOCKER_CONTEXT,
#                   "Insufficient DOWNLOAD responses",
#                   f"{download_success}/{RAIDA_COUNT} < {MINIMUM_PASS_COUNT}")
#         return LockerDownloadResult.ERR_INSUFFICIENT_RESPONSES, []

#     # 7. Merge coin lists and determine which RAIDAs have each coin
#     # Build: {(denom, sn): [raida_ids that returned this coin]}
#     coin_raida_map: Dict[Tuple[int, int], List[int]] = {}
#     for raida_id, coins in coin_lists_per_raida.items():
#         for denom, sn in coins:
#             key = (denom, sn)
#             if key not in coin_raida_map:
#                 coin_raida_map[key] = []
#             coin_raida_map[key].append(raida_id)

#     if not coin_raida_map:
#         log_info(logger_handle, LOCKER_CONTEXT, "Locker is empty")
#         return LockerDownloadResult.ERR_LOCKER_EMPTY, []

#     log_info(logger_handle, LOCKER_CONTEXT,
#              f"Found {len(coin_raida_map)} unique coins in locker")

#     # 8. For each coin, compute ANs and build POWN string
#     fracked_path = os.path.join(wallet_path, "Fracked")
#     os.makedirs(fracked_path, exist_ok=True)

#     saved_coins = []
#     for (denom, sn), raida_ids in coin_raida_map.items():
#         # Initialize coin with all ANs as zeros and all statuses as fail
#         ans = [bytes(AN_LENGTH)] * RAIDA_COUNT
#         statuses = [False] * RAIDA_COUNT

#         # For each RAIDA that returned this coin, compute the AN
#         for raida_id in raida_ids:
#             ans[raida_id] = compute_coin_an(raida_id, sn, seeds[raida_id])
#             statuses[raida_id] = True

#         # Create DownloadedCoin for conversion
#         coin = DownloadedCoin(
#             denomination=denom,
#             serial_number=sn,
#             ans=ans,
#             statuses=statuses
#         )

#         pass_count = coin.pass_count

#         # Only save if at least one RAIDA passed
#         if pass_count > 0:
#             locker_coin = coin.to_locker_coin()

#             filename = generate_coin_filename(
#                 locker_coin.denomination,
#                 locker_coin.serial_number
#             )
#             filepath = os.path.join(fracked_path, filename)

#             err = write_coin_file(filepath, locker_coin, logger_handle)
#             if err == CloudCoinErrorCode.SUCCESS:
#                 saved_coins.append(locker_coin)
#                 log_debug(logger_handle, LOCKER_CONTEXT,
#                           f"Saved coin SN={locker_coin.serial_number} "
#                           f"({pass_count}/25 passed)")
#             else:
#                 log_error(logger_handle, LOCKER_CONTEXT,
#                           f"Failed to save coin SN={locker_coin.serial_number}",
#                           f"error={err}")
#         else:
#             log_warning(logger_handle, LOCKER_CONTEXT,
#                         f"Coin SN={sn} had 0 passes, not saved")

#     if not saved_coins:
#         log_error(logger_handle, LOCKER_CONTEXT,
#                   "No coins saved", "all coins had 0 passes")
#         return LockerDownloadResult.ERR_FILE_WRITE_ERROR, []

#     total_value = sum(10.0 ** c.denomination for c in saved_coins
#                       if c.denomination != 11)
#     log_info(logger_handle, LOCKER_CONTEXT,
#              f"Locker download complete: {len(saved_coins)} coins saved, "
#              f"total value={total_value}")

#     return LockerDownloadResult.SUCCESS, saved_coins


async def download_from_locker(
    locker_code: bytes,
    wallet_path: str,
    db_handle: Any,
    logger_handle: Optional[object] = None
) -> Tuple[LockerDownloadResult, List[Any]]:
    """
    Download coins from a RAIDA locker using the new DOWNLOAD command (8).

    This function:
    1. Validates the locker code
    2. Converts locker code bytes to string for protocol
    3. Generates 25 unique seeds (one per RAIDA)
    4. Gets RAIDA server list
    5. Sends parallel DOWNLOAD requests to all 25 RAIDAs
    6. Checks consensus (need >= 13 successful responses)
    7. Merges coin lists and computes ANs locally
    8. Grades coins and saves to appropriate folders:
       - 25/25 passes -> Bank (authentic)
       - 13-24 passes -> Fracked (needs healing)
       - <13 passes -> Counterfeit

    Args:
        locker_code: 8-byte locker code (e.g., b'ABC-1234')
        wallet_path: Path to wallet folder (coins go to Bank/Fracked/Counterfeit)
        db_handle: Database handle for RAIDA server lookup
        logger_handle: Optional logger handle

    Returns:
        Tuple of (result_code, list_of_saved_coins)
        On success, coins are graded and saved to appropriate folders
    """
    log_info(logger_handle, LOCKER_CONTEXT,
             f"Starting locker download for {locker_code.hex()[:16]}...")

    # 1. Validate locker code
    if not locker_code or len(locker_code) < 8:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Invalid locker code", f"length={len(locker_code) if locker_code else 0}")
        return LockerDownloadResult.ERR_INVALID_LOCKER_CODE, []

    # Use first 8 bytes (strip null padding if present)
    locker_code = locker_code[:8]

    # FIXED: Convert bytes to string for protocol.py
    # The locker code is stored as b'ABC-1234' but protocol expects "ABC-1234"
    locker_code_str = locker_code.decode('ascii', errors='ignore').strip().rstrip('\x00')
    
    log_info(logger_handle, LOCKER_CONTEXT,
             f"Locker code string: {locker_code_str}")

    # Validate format: should be XXX-XXXX (8 chars with hyphen at position 3)
    if len(locker_code_str) < 7 or '-' not in locker_code_str:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Invalid locker code format", f"expected 'XXX-XXXX', got '{locker_code_str}'")
        return LockerDownloadResult.ERR_INVALID_LOCKER_CODE, []

    # 2. Generate 25 unique seeds (one per RAIDA for security!)
    # Each RAIDA gets a unique seed so administrators can't compute other RAIDAs' ANs
    seeds = [secrets.token_bytes(AN_LENGTH) for _ in range(RAIDA_COUNT)]
    log_debug(logger_handle, LOCKER_CONTEXT,
              f"Generated {len(seeds)} unique seeds for AN generation")

    # 3. Get RAIDA servers
    servers = await get_raida_servers(db_handle, logger_handle)
    if not servers or len(servers) != RAIDA_COUNT:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Failed to get RAIDA servers",
                  f"got {len(servers) if servers else 0} servers")
        return LockerDownloadResult.ERR_NO_RAIDA_SERVERS, []

    # 4. Parallel DOWNLOAD to all RAIDAs
    # FIXED: Pass locker_code_str (string) instead of locker_keys (list of bytes)
    download_success, coin_lists_per_raida = await _download_all_raidas(
        locker_code_str=locker_code_str,  # FIXED: Pass string
        seeds=seeds,
        servers=servers,
        logger_handle=logger_handle
    )

    # 5. Check consensus
    if download_success < MINIMUM_PASS_COUNT:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "Insufficient DOWNLOAD responses",
                  f"{download_success}/{RAIDA_COUNT} < {MINIMUM_PASS_COUNT}")
        return LockerDownloadResult.ERR_INSUFFICIENT_RESPONSES, []

    # 6. Merge coin lists and determine which RAIDAs have each coin
    # Build: {(denom, sn): [raida_ids that returned this coin]}
    coin_raida_map: Dict[Tuple[int, int], List[int]] = {}
    for raida_id, coins in coin_lists_per_raida.items():
        for denom, sn in coins:
            key = (denom, sn)
            if key not in coin_raida_map:
                coin_raida_map[key] = []
            coin_raida_map[key].append(raida_id)

    if not coin_raida_map:
        log_info(logger_handle, LOCKER_CONTEXT, "Locker is empty")
        return LockerDownloadResult.ERR_LOCKER_EMPTY, []

    log_info(logger_handle, LOCKER_CONTEXT,
             f"Found {len(coin_raida_map)} unique coins in locker")

    # 7. For each coin, compute ANs, grade, and save to appropriate folder
    # Create all necessary folders
    bank_path = os.path.join(wallet_path, "Bank")
    fracked_path = os.path.join(wallet_path, "Fracked")
    counterfeit_path = os.path.join(wallet_path, "Counterfeit")
    os.makedirs(bank_path, exist_ok=True)
    os.makedirs(fracked_path, exist_ok=True)
    os.makedirs(counterfeit_path, exist_ok=True)

    saved_coins = []
    bank_count = 0
    fracked_count = 0
    counterfeit_count = 0

    for (denom, sn), raida_ids in coin_raida_map.items():
        # Initialize coin with all ANs as zeros and all statuses as fail
        ans = [bytes(AN_LENGTH)] * RAIDA_COUNT
        statuses = [False] * RAIDA_COUNT

        # For each RAIDA that returned this coin, compute the AN
        for raida_id in raida_ids:
            # FIXED: compute_coin_an signature is (denomination, serial_number, seed)
            # But looking at the original code, it was (raida_id, sn, seed) which is WRONG
            # The correct call should be (denom, sn, seed) per the docstring
            ans[raida_id] = compute_coin_an(denom, sn, seeds[raida_id])
            statuses[raida_id] = True

        # Create DownloadedCoin for conversion
        coin = DownloadedCoin(
            denomination=denom,
            serial_number=sn,
            ans=ans,
            statuses=statuses
        )

        pass_count = coin.pass_count

        # Skip coins with 0 passes (should not happen but safety check)
        if pass_count == 0:
            log_warning(logger_handle, LOCKER_CONTEXT,
                        f"Coin SN={sn} had 0 passes, not saved")
            continue

        # Convert to LockerCoin for file writing
        locker_coin = coin.to_locker_coin()

        # Generate filename
        filename = generate_coin_filename(
            locker_coin.denomination,
            locker_coin.serial_number
        )

        # GRADING LOGIC: Determine destination folder based on pass count
        if pass_count == RAIDA_COUNT:
            # All 25 passed - authentic, goes to Bank
            dest_folder = bank_path
            grade = "BANK"
            bank_count += 1
        elif pass_count >= MINIMUM_PASS_COUNT:
            # 13-24 passed - fracked, needs healing
            dest_folder = fracked_path
            grade = "FRACKED"
            fracked_count += 1
        else:
            # Less than 13 passed - counterfeit
            dest_folder = counterfeit_path
            grade = "COUNTERFEIT"
            counterfeit_count += 1

        filepath = os.path.join(dest_folder, filename)

        err = write_coin_file(filepath, locker_coin, logger_handle)
        if err == CloudCoinErrorCode.SUCCESS:
            saved_coins.append(locker_coin)
            log_info(logger_handle, LOCKER_CONTEXT,
                      f"Saved coin DN={denom} SN={sn} ({pass_count}/25) -> {grade}")
        else:
            log_error(logger_handle, LOCKER_CONTEXT,
                      f"Failed to save coin SN={sn}", f"error={err}")

    if not saved_coins:
        log_error(logger_handle, LOCKER_CONTEXT,
                  "No coins saved", "all writes failed")
        return LockerDownloadResult.ERR_FILE_WRITE_ERROR, []

    # Calculate total value
    total_value = sum(10.0 ** c.denomination for c in saved_coins
                      if hasattr(c, 'denomination') and c.denomination != 11)

    log_info(logger_handle, LOCKER_CONTEXT,
             f"Download complete: {len(saved_coins)} coins saved "
             f"(Bank: {bank_count}, Fracked: {fracked_count}, Counterfeit: {counterfeit_count}) "
             f"Total value: ~{total_value:.6f} CC")

    return LockerDownloadResult.SUCCESS, saved_coins


def derive_locker_keys(locker_code: str) -> list:
    """
    Derive 25 locker IDs (one per RAIDA) from a locker code in "XXX-XXXX" format.

    Algorithm (matches Go GetLockerIDsFromTransmitCode):
    1. Split code by hyphen: "ABC-1234" -> parts[0]="ABC", parts[1]="1234"
    2. For each RAIDA i: MD5("{i}{parts[0]}-{parts[1]}") e.g., MD5("0ABC-1234")
    3. Set bytes 12-15 to 0xFF

    Args:
        locker_code: String in "XXX-XXXX" format (8 chars with hyphen at index 3)

    Returns:
        List of 25 locker keys (16 bytes each)
    """
    # Handle bytes input for backwards compatibility
    if isinstance(locker_code, bytes):
        locker_code = locker_code.decode('ascii', errors='ignore')

    # Strip whitespace but preserve case to match Go implementation
    locker_code = locker_code.strip()

    # Split by hyphen
    parts = locker_code.split('-')
    if len(parts) != 2:
        raise ValueError(f"Invalid locker code format: expected 'XXX-XXXX', got '{locker_code}'")

    locker_ids = []
    for raida_id in range(25):
        # Build string exactly as Go does: "{raida_id}{parts[0]}-{parts[1]}"
        key_material = f"{raida_id}{parts[0]}-{parts[1]}"

        # MD5 hash
        md5_hash = hashlib.md5(key_material.encode('ascii')).digest()

        # Convert to bytearray to modify last 4 bytes
        locker_key = bytearray(md5_hash)
        locker_key[12] = 0xFF
        locker_key[13] = 0xFF
        locker_key[14] = 0xFF
        locker_key[15] = 0xFF

        locker_ids.append(bytes(locker_key))

    return locker_ids


# ============================================================================
# SYNCHRONOUS WRAPPER
# ============================================================================

def download_from_locker_sync(
    locker_code: bytes,
    wallet_path: str,
    db_handle: Any = None,
    logger_handle: Optional[object] = None
) -> Tuple[LockerDownloadResult, List[LockerCoin]]:
    """
    Synchronous wrapper for download_from_locker.

    Use this when calling from non-async code.

    Args:
        Same as download_from_locker

    Returns:
        Same as download_from_locker
    """
    return asyncio.run(download_from_locker(
        locker_code, wallet_path, db_handle, logger_handle
    ))


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the locker_download module.
    """
    # Ensure wallet folders exist
    initialize_wallet_structure()

    print("=" * 60)
    print("locker_download.py - Locker Download Module v2.0")
    print("=" * 60)

    # Test key derivation
    print("\n1. Testing key derivation...")
    test_locker_code = bytes.fromhex("0102030405060708")
    keys = get_keys_from_locker_code(test_locker_code)
    assert len(keys) == 25
    # Check 0xFF padding
    for i, key in enumerate(keys):
        assert key[12:16] == b'\xff\xff\xff\xff', f"Key {i} missing 0xFF padding"
    print(f"   Generated {len(keys)} keys with 0xFF padding")
    print("   SUCCESS: Key derivation works")

    # Test compute_coin_an
    print("\n2. Testing compute_coin_an (AN generation)...")
    test_seed = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    test_sn = 12345678
    test_raida = 5

    # Expected: MD5("512345678" + "0102030405060708090a0b0c0d0e0f10")
    expected_input = f"{test_raida}{test_sn}{test_seed.hex()}"
    expected_an = hashlib.md5(expected_input.encode('ascii')).digest()
    actual_an = compute_coin_an(test_raida, test_sn, test_seed)

    assert actual_an == expected_an, f"AN mismatch: {actual_an.hex()} != {expected_an.hex()}"
    print(f"   Input string: {expected_input[:40]}...")
    print(f"   Generated AN: {actual_an.hex()}")
    print("   SUCCESS: AN computation matches server formula")

    # Test DownloadedCoin (no PANs in new version)
    print("\n3. Testing DownloadedCoin...")
    coin = DownloadedCoin(
        denomination=1,
        serial_number=12345678,
        ans=[bytes(16)] * 25,
        statuses=[True] * 13 + [False] * 12
    )
    assert coin.pass_count == 13
    locker_coin = coin.to_locker_coin()
    assert locker_coin.pown_string.count('p') == 13
    assert locker_coin.pown_string.count('f') == 12
    print(f"   POWN string: {locker_coin.pown_string}")
    print("   SUCCESS: DownloadedCoin conversion works")

    print("\n" + "=" * 60)
    print("All locker_download tests passed!")
    print("=" * 60)
