"""
heal_network.py - RAIDA Network Communication for Healing Operations

This module handles TCP socket communication with RAIDA servers
and provides threaded parallel operations for healing commands.

Author: Claude Opus 4.5
Version: 1.0.0
Date: 2025-12-26

Network Configuration:
    - RAIDA servers use binary protocol over TCP
    - Default port: 50000 + raida_id (RAIDA 0 = 50000, RAIDA 24 = 50024)
    - Server info should be queried from database when available
    - Hostname pattern: raida{N}.cloudcoin.global

Threading Strategy:
    Uses Python threading module for parallel RAIDA calls.
    Each RAIDA is contacted in its own thread for maximum parallelism.
    Designed for easy conversion to C pthreads later.
"""

import socket
import struct
import threading
import logging
import json
import urllib.request
import urllib.error
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field

# Import from heal_protocol
try:
    from heal_protocol import (
        RAIDA_COUNT, RAIDA_TIMEOUT, AN_SIZE,
        REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
        CMD_GROUP_HEALING, CMD_GET_TICKET, CMD_FIND, CMD_FIX,
        HealErrorCode,
        build_request_header, parse_response_header,
        build_get_ticket_body, build_find_body, build_fix_body,
        parse_get_ticket_response, parse_find_response, parse_fix_response,
        generate_pg, calculate_new_an, TERMINATOR
    )
except ImportError:
    from heal_protocol import (
        RAIDA_COUNT, RAIDA_TIMEOUT, AN_SIZE,
        REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
        CMD_GROUP_HEALING, CMD_GET_TICKET, CMD_FIND, CMD_FIX,
        HealErrorCode,
        build_request_header, parse_response_header,
        build_get_ticket_body, build_find_body, build_fix_body,
        parse_get_ticket_response, parse_find_response, parse_fix_response,
        generate_pg, calculate_new_an, TERMINATOR
    )

# Import CloudCoinBin for type hints
try:
    from heal_file_io import CloudCoinBin
except ImportError:
    from heal_file_io import CloudCoinBin


# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger("heal_network")


# ============================================================================
# RAIDA SERVER CONFIGURATION
# ============================================================================

# Default RAIDA configuration
RAIDA_URL_PATTERN = "raida{}.cloudcoin.global"
RAIDA_BASE_PORT = 50000  # Port = 50000 + raida_id

# URL to fetch RAIDA server list (fallback when database unavailable)
RAIDA_SERVERS_URL = "https://raida11.cloudcoin.global/service/raida_servers"

# Cached server info (populated by get_raida_servers)
_raida_servers_cache: Optional[List['RaidaServer']] = None
_cache_lock = threading.Lock()


@dataclass
class RaidaServer:
    """
    RAIDA server connection information.

    Attributes:
        raida_id: RAIDA index (0-24)
        host: Server hostname or IP
        port: Server port number
        is_online: Whether server responded recently
    """
    raida_id: int = 0
    host: str = ""
    port: int = 0
    is_online: bool = True


def get_default_raida_servers() -> List[RaidaServer]:
    """
    Get default RAIDA server configuration.

    Uses the pattern: raida{N}.cloudcoin.global:5000{N}

    Returns:
        List of 25 RaidaServer objects
    """
    servers = []
    for i in range(RAIDA_COUNT):
        servers.append(RaidaServer(
            raida_id=i,
            host=RAIDA_URL_PATTERN.format(i),
            port=RAIDA_BASE_PORT + i
        ))
    return servers


def fetch_raida_servers_from_url() -> Optional[List[RaidaServer]]:
    """
    Fetch RAIDA server list from the discovery URL.

    Uses synchronous HTTP (urllib) for compatibility with threaded design.

    The RAIDA servers URL returns plain text in format:
        IP:PORT
        IP:PORT
        ...
    (one server per line, 25 lines total)

    Returns:
        List of RaidaServer objects, or None if fetch failed
    """
    try:
        logger.debug(f"Fetching RAIDA servers from {RAIDA_SERVERS_URL}")
        req = urllib.request.Request(
            RAIDA_SERVERS_URL,
            headers={'User-Agent': 'QMail-Heal/1.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            text = response.read().decode('utf-8')

            # Parse plain text format: IP:PORT per line
            lines = text.strip().split('\n')
            servers = []

            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue

                # Parse IP:PORT format
                if ':' in line:
                    parts = line.split(':')
                    host = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except (ValueError, IndexError):
                        port = RAIDA_BASE_PORT + i
                else:
                    host = line
                    port = RAIDA_BASE_PORT + i

                servers.append(RaidaServer(
                    raida_id=i,
                    host=host,
                    port=port
                ))

            if len(servers) >= RAIDA_COUNT:
                logger.info(f"Fetched {len(servers)} RAIDA servers from URL")
                return servers[:RAIDA_COUNT]
            else:
                logger.warning(f"Only {len(servers)} servers from URL, need {RAIDA_COUNT}")
                return None

    except urllib.error.URLError as e:
        logger.warning(f"Failed to fetch RAIDA servers from URL: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching RAIDA servers: {e}")

    return None


def get_raida_servers(db_handle: Any = None) -> List[RaidaServer]:
    """
    Get RAIDA server configuration.

    Priority:
    1. Cached servers (if available)
    2. Database query (if db_handle provided)
    3. URL fetch from RAIDA_SERVERS_URL
    4. Default configuration (hardcoded)

    Args:
        db_handle: Optional database handle with get_raida_servers() method

    Returns:
        List of 25 RaidaServer objects
    """
    global _raida_servers_cache

    with _cache_lock:
        # Return cached if available
        if _raida_servers_cache is not None:
            return _raida_servers_cache

        # Try database first
        if db_handle is not None:
            try:
                if hasattr(db_handle, 'get_raida_servers'):
                    db_servers = db_handle.get_raida_servers()
                    if db_servers and len(db_servers) == RAIDA_COUNT:
                        _raida_servers_cache = [
                            RaidaServer(
                                raida_id=s.raida_id if hasattr(s, 'raida_id') else i,
                                host=s.host if hasattr(s, 'host') else s.get('host', ''),
                                port=s.port if hasattr(s, 'port') else s.get('port', RAIDA_BASE_PORT + i)
                            )
                            for i, s in enumerate(db_servers)
                        ]
                        logger.debug("Using RAIDA servers from database")
                        return _raida_servers_cache
            except Exception as e:
                logger.warning(f"Could not get servers from database: {e}")

        # Try URL fetch
        url_servers = fetch_raida_servers_from_url()
        if url_servers:
            _raida_servers_cache = url_servers
            return _raida_servers_cache

        # Use hardcoded defaults as last resort
        logger.info("Using default hardcoded RAIDA servers")
        _raida_servers_cache = get_default_raida_servers()
        return _raida_servers_cache


def clear_server_cache() -> None:
    """Clear the cached server list to force refresh."""
    global _raida_servers_cache
    with _cache_lock:
        _raida_servers_cache = None


def get_raida_endpoint(raida_id: int) -> Tuple[str, int]:
    """
    Get hostname and port for a specific RAIDA.

    Args:
        raida_id: RAIDA index (0-24)

    Returns:
        Tuple of (hostname, port)
    """
    servers = get_raida_servers()
    if 0 <= raida_id < len(servers):
        return servers[raida_id].host, servers[raida_id].port
    return RAIDA_URL_PATTERN.format(raida_id), RAIDA_BASE_PORT + raida_id


# ============================================================================
# LOW-LEVEL NETWORK OPERATIONS
# ============================================================================

def send_request(
    raida_id: int,
    request_data: bytes,
    timeout: float = RAIDA_TIMEOUT
) -> Tuple[HealErrorCode, bytes]:
    """
    Send a request to a RAIDA server and receive response.

    Uses TCP socket for reliable communication.

    Args:
        raida_id: Target RAIDA server ID (0-24)
        request_data: Complete request (header + body)
        timeout: Socket timeout in seconds

    Returns:
        Tuple of (error_code, response_bytes)
    """
    host, port = get_raida_endpoint(raida_id)

    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to RAIDA
        sock.connect((host, port))

        # Send request
        sock.sendall(request_data)

        # Receive response header
        response_header = b''
        while len(response_header) < RESPONSE_HEADER_SIZE:
            chunk = sock.recv(RESPONSE_HEADER_SIZE - len(response_header))
            if not chunk:
                sock.close()
                return HealErrorCode.ERR_NETWORK_ERROR, b''
            response_header += chunk

        # Parse header to get body size
        _, _, _, body_size = parse_response_header(response_header)

        # Receive body if present
        response_body = b''
        if body_size > 0:
            while len(response_body) < body_size:
                chunk = sock.recv(min(4096, body_size - len(response_body)))
                if not chunk:
                    break
                response_body += chunk

        sock.close()
        return HealErrorCode.SUCCESS, response_header + response_body

    except socket.timeout:
        logger.warning(f"RAIDA{raida_id} timeout ({host}:{port})")
        return HealErrorCode.ERR_NETWORK_ERROR, b''
    except socket.error as e:
        logger.warning(f"RAIDA{raida_id} socket error: {e}")
        return HealErrorCode.ERR_NETWORK_ERROR, b''
    except Exception as e:
        logger.error(f"RAIDA{raida_id} unexpected error: {e}")
        return HealErrorCode.ERR_INTERNAL, b''


# ============================================================================
# GET TICKET OPERATIONS
# ============================================================================

def get_ticket_from_raida(
    raida_id: int,
    coins: List[CloudCoinBin],
    result_dict: Dict[int, Tuple[int, List[bool]]]
) -> None:
    """
    Get ticket from a single RAIDA for a batch of coins (thread worker).

    Args:
        raida_id: Target RAIDA ID
        coins: List of coins to authenticate
        result_dict: Shared dict to store results {raida_id: (ticket_id, passed_list)}
    """
    coin_data = [(c.denomination, c.serial_number, c.ans[raida_id]) for c in coins]
    body = build_get_ticket_body(coin_data)

    # Build header
    header = build_request_header(
        raida_id=raida_id,
        command_group=CMD_GROUP_HEALING,
        command_code=CMD_GET_TICKET,
        body_length=len(body)
    )

    request = header + body
    err, response = send_request(raida_id, request)

    if err == HealErrorCode.SUCCESS:
        err, ticket_id, coin_results = parse_get_ticket_response(response, len(coins))
        if err == HealErrorCode.SUCCESS:
            result_dict[raida_id] = (ticket_id, coin_results)
            logger.debug(f"RAIDA{raida_id}: ticket={ticket_id:08x}, passed={sum(coin_results)}/{len(coin_results)}")
        else:
            result_dict[raida_id] = (0, [False] * len(coins))
    else:
        result_dict[raida_id] = (0, [False] * len(coins))


def get_tickets_parallel(coins: List[CloudCoinBin]) -> Tuple[List[int], Dict[int, List[bool]]]:
    """
    Get tickets from all RAIDA in parallel for a batch of coins.

    Args:
        coins: List of coins to get tickets for

    Returns:
        Tuple of:
            - List of 25 ticket IDs (0 if failed)
            - Dict mapping raida_id -> list of pass/fail results for each coin
    """
    result_dict: Dict[int, Tuple[int, List[bool]]] = {}
    threads = []

    for raida_id in range(RAIDA_COUNT):
        t = threading.Thread(
            target=get_ticket_from_raida,
            args=(raida_id, coins, result_dict)
        )
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join()

    # Extract results
    tickets = [0] * RAIDA_COUNT
    results: Dict[int, List[bool]] = {i: [] for i in range(RAIDA_COUNT)}

    for raida_id in range(RAIDA_COUNT):
        if raida_id in result_dict:
            tickets[raida_id], results[raida_id] = result_dict[raida_id]
        else:
            results[raida_id] = [False] * len(coins)

    return tickets, results


# ============================================================================
# FIND OPERATIONS (LIMBO RESOLUTION)
# ============================================================================

def find_on_raida(
    raida_id: int,
    coins: List[CloudCoinBin],
    result_dict: Dict[int, List[str]]
) -> None:
    """
    Execute Find command on a single RAIDA for a batch of coins (thread worker).

    Args:
        raida_id: Target RAIDA ID
        coins: List of coins to find (must have both ANs and PANs)
        result_dict: Shared dict to store results {raida_id: ['an'/'pan'/'neither'/'error']}
    """
    coin_data = [(c.denomination, c.serial_number, c.ans[raida_id], c.pans[raida_id]) for c in coins]
    body = build_find_body(coin_data)

    # Build header
    header = build_request_header(
        raida_id=raida_id,
        command_group=CMD_GROUP_HEALING,
        command_code=CMD_FIND,
        body_length=len(body)
    )

    request = header + body
    err, response = send_request(raida_id, request)

    if err == HealErrorCode.SUCCESS:
        err, find_results = parse_find_response(response, len(coins))
        if err == HealErrorCode.SUCCESS:
            result_dict[raida_id] = find_results
            logger.debug(f"RAIDA{raida_id}: find results = {find_results}")
        else:
            result_dict[raida_id] = ['error'] * len(coins)
    else:
        result_dict[raida_id] = ['error'] * len(coins)


def find_parallel(coins: List[CloudCoinBin]) -> Dict[int, List[str]]:
    """
    Execute Find command on all RAIDA in parallel for a batch of coins.

    Args:
        coins: List of coins to find (must have both ANs and PANs)

    Returns:
        Dict mapping raida_id -> list of results ('an'/'pan'/'neither'/'error')
    """
    result_dict: Dict[int, List[str]] = {}
    threads = []

    for raida_id in range(RAIDA_COUNT):
        t = threading.Thread(
            target=find_on_raida,
            args=(raida_id, coins, result_dict)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Ensure all raida have a result
    for raida_id in range(RAIDA_COUNT):
        if raida_id not in result_dict:
            result_dict[raida_id] = ['error'] * len(coins)

    return result_dict


# ============================================================================
# FIX OPERATIONS
# ============================================================================

def fix_on_raida(
    raida_id: int,
    coins: List[CloudCoinBin],
    pg: bytes,
    tickets: List[int],
    result_dict: Dict[int, List[bool]]
) -> None:
    """
    Execute Fix command on a single RAIDA for a batch of coins (thread worker).

    Args:
        raida_id: Target RAIDA ID (the fracked RAIDA to fix)
        coins: List of coins to fix
        pg: 16-byte password generator
        tickets: List of 25 ticket IDs from other RAIDA
        result_dict: Shared dict to store results {raida_id: [passed_list]}
    """
    coin_data = [(c.denomination, c.serial_number) for c in coins]
    body = build_fix_body(coin_data, pg, tickets)

    # Build header
    header = build_request_header(
        raida_id=raida_id,
        command_group=CMD_GROUP_HEALING,
        command_code=CMD_FIX,
        body_length=len(body)
    )

    request = header + body
    err, response = send_request(raida_id, request)

    if err != HealErrorCode.SUCCESS:
        logger.warning(f"RAIDA{raida_id} FIX command failed: error={err}")
        result_dict[raida_id] = [False] * len(coins)
        return

    if err == HealErrorCode.SUCCESS:
        err, fix_results = parse_fix_response(response, len(coins))
        if err == HealErrorCode.SUCCESS:
            result_dict[raida_id] = fix_results
            logger.debug(f"RAIDA{raida_id}: fix results = {fix_results}")
        else:
            result_dict[raida_id] = [False] * len(coins)
    else:
        result_dict[raida_id] = [False] * len(coins)


def fix_coins_parallel(
    coins: List[CloudCoinBin],
    fracked_raida: List[int],
    pg: bytes,
    tickets: List[int]
) -> Dict[int, List[bool]]:
    """
    Fix a list of coins on multiple fracked RAIDA using tickets (Parallel version).

    Args:
        coins: List of coins to fix
        fracked_raida: List of RAIDA IDs that need fixing
        pg: 16-byte password generator
        tickets: List of 25 ticket IDs from get_tickets_parallel

    Returns:
        A dictionary mapping each fracked RAIDA ID to a list of boolean success statuses for each coin.
    """
    if not fracked_raida or not coins:
        return {}

    # Fix on each fracked RAIDA in parallel
    result_dict: Dict[int, List[bool]] = {}
    threads = []

    for raida_id in fracked_raida:
        t = threading.Thread(
            target=fix_on_raida,
            args=(raida_id, coins, pg, tickets, result_dict)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return result_dict


# ============================================================================
# BATCH OPERATIONS (for orchestrator compatibility)
# ============================================================================

def get_tickets_for_coins_batch(
    coins: List[CloudCoinBin]
) -> Tuple[List[int], Dict[int, List[bool]]]:
    """
    Get tickets for multiple coins from all RAIDA.

    This is the batch version that heal.py expects.
    It makes one request per RAIDA for all coins.

    Args:
        coins: List of coins to get tickets for

    Returns:
        Tuple of:
            - List of 25 ticket IDs
            - Dict mapping raida_id -> list of pass/fail per coin
    """
    if not coins:
        return [0] * RAIDA_COUNT, {}

    return get_tickets_parallel(coins)


def find_coins_batch(coins: List[CloudCoinBin]) -> Dict[int, List[str]]:
    """
    Execute Find command for multiple coins on all RAIDA.

    This is the batch version that heal.py expects.
    It makes one request per RAIDA for all coins.

    Args:
        coins: List of coins to find (must have both ANs and PANs)

    Returns:
        Dict mapping raida_id -> list of results per coin ('an'/'pan'/'neither'/'error')
    """
    if not coins:
        return {}

    return find_parallel(coins)


def fix_coins_on_raida_set_batch(
    coins: List[CloudCoinBin],
    fracked_raida: set,
    pg: bytes,
    tickets: List[int]
) -> Dict[int, List[bool]]:
    """
    Fix multiple coins on fracked RAIDA using tickets.

    This is the batch version that heal.py expects.
    It makes one request per fracked RAIDA for all coins.

    Args:
        coins: List of coins to fix
        fracked_raida: Set of RAIDA IDs that need fixing
        pg: 16-byte password generator (for AN calculation)
        tickets: List of 25 ticket IDs

    Returns:
        Dict mapping raida_id -> list of pass/fail per coin
    """
    if not coins or not fracked_raida:
        return {}

    return fix_coins_parallel(coins, list(fracked_raida), pg, tickets)


# ============================================================================
# SELF-TEST
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("heal_network.py - Self Tests")
    print("=" * 60)

    # Test 1: Default server configuration
    print("\n1. Testing default server configuration...")
    servers = get_default_raida_servers()
    assert len(servers) == 25
    assert servers[0].port == 50000
    assert servers[13].port == 50013
    assert servers[24].port == 50024
    assert "raida0" in servers[0].host
    assert "raida24" in servers[24].host
    print(f"   PASS: 25 servers, ports 50000-50024")

    # Test 2: Get RAIDA endpoint
    print("\n2. Testing get_raida_endpoint...")
    host, port = get_raida_endpoint(5)
    assert port == 50005
    assert "raida5" in host
    print(f"   PASS: RAIDA5 = {host}:{port}")

    # Test 3: Server cache
    print("\n3. Testing server cache...")
    clear_server_cache()
    servers1 = get_raida_servers()
    servers2 = get_raida_servers()
    assert servers1 is servers2  # Should be same cached object
    print("   PASS: Cache working")

    # Test 4: RaidaServer dataclass
    print("\n4. Testing RaidaServer dataclass...")
    server = RaidaServer(raida_id=10, host="test.com", port=50010)
    assert server.raida_id == 10
    assert server.host == "test.com"
    assert server.port == 50010
    assert server.is_online == True
    print(f"   PASS: {server}")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
    print("\nNote: Network tests require live RAIDA servers.")
    print("Use heal.py to test actual network operations.")
