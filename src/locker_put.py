"""
Locker PUT command implementation.

Uploads coins to a RAIDA locker. The locker key is derived from a transmission
code using MD5 hash with the RAIDA ID prefix.

Protocol (from server code analysis):
- Command Group: 8
- Command Code: 82 (0x52)
- Encryption Type: 0 (NO encryption - body sent in plaintext)

Body format:
- Challenge (16 bytes): 12 random + 4 CRC32
- For each coin: DN (1 byte) + SN (4 bytes big-endian)
- SUM (16 bytes): XOR of all coin ANs
- LockerKey (16 bytes): with last 4 bytes = 0xFF
- Terminator (2 bytes): 0x3E3E

Response status:
- 241 (0xF1): All Pass
- 242 (0xF2): All Fail
- 243 (0xF3): Mixed
"""

import os
import struct
import zlib
import socket
import asyncio
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass
from enum import IntEnum

# Constants
RAIDA_COUNT = 25
CMD_GROUP_LOCKER = 8
CMD_LOCKER_PUT = 82  # 0x52
COIN_TYPE = 0x0006
TERMINATOR = bytes([0x3E, 0x3E])

# Response status codes
STATUS_ALL_PASS = 241  # 0xF1
STATUS_ALL_FAIL = 242  # 0xF2
STATUS_MIXED = 243     # 0xF3


class PutResult(IntEnum):
    SUCCESS = 0
    PARTIAL_SUCCESS = 1
    ALL_FAIL = 2
    NETWORK_ERROR = 3
    INVALID_PARAM = 4


@dataclass
class CoinForPut:
    """Coin data needed for PUT command."""
    denomination: int
    serial_number: int
    ans: List[bytes]  # 25 x 16-byte ANs, one per RAIDA


# Default RAIDA servers
RAIDA_SERVERS = [
    ("78.46.170.45", 50000),      # RAIDA 0
    ("47.229.9.94", 50001),       # RAIDA 1
    ("209.46.126.167", 50002),    # RAIDA 2
    ("116.203.157.233", 50003),   # RAIDA 3
    ("95.183.51.104", 50004),     # RAIDA 4
    ("31.163.201.90", 50005),     # RAIDA 5
    ("52.14.83.91", 50006),       # RAIDA 6
    ("161.97.169.229", 50007),    # RAIDA 7
    ("13.234.55.11", 50008),      # RAIDA 8
    ("124.187.106.233", 50009),   # RAIDA 9
    ("94.130.179.247", 50010),    # RAIDA 10
    ("67.181.90.11", 50011),      # RAIDA 11
    ("3.16.169.178", 50012),      # RAIDA 12
    ("113.30.247.109", 50013),    # RAIDA 13
    ("168.220.219.199", 50014),   # RAIDA 14
    ("185.37.61.73", 50015),      # RAIDA 15
    ("193.7.195.250", 50016),     # RAIDA 16
    ("5.161.63.179", 50017),      # RAIDA 17
    ("31.186.58.178", 50018),     # RAIDA 18
    ("190.105.235.113", 50019),   # RAIDA 19
    ("184.18.166.118", 50020),    # RAIDA 20
    ("125.236.210.184", 50021),   # RAIDA 21
    ("219.97.17.29", 50022),      # RAIDA 22
    ("130.255.77.156", 50023),    # RAIDA 23
    ("27.100.58.116", 50024),     # RAIDA 24
]


def generate_challenge() -> bytes:
    """Generate 16-byte challenge: 12 random + 4 CRC32 (big-endian)."""
    random_bytes = os.urandom(12)
    crc32_val = zlib.crc32(random_bytes) & 0xFFFFFFFF
    crc32_bytes = struct.pack('>I', crc32_val)
    return random_bytes + crc32_bytes


def compute_an_xor_sum(coins: List[CoinForPut], raida_id: int) -> bytes:
    """
    Compute XOR sum of all coin ANs for a specific RAIDA.

    Each AN is treated as 4 little-endian 32-bit integers,
    XORed together, then converted back to bytes (little-endian).
    """
    sum0, sum1, sum2, sum3 = 0, 0, 0, 0

    for coin in coins:
        an = coin.ans[raida_id]
        # Convert to 4 little-endian 32-bit integers
        i0 = an[0] | (an[1] << 8) | (an[2] << 16) | (an[3] << 24)
        i1 = an[4] | (an[5] << 8) | (an[6] << 16) | (an[7] << 24)
        i2 = an[8] | (an[9] << 8) | (an[10] << 16) | (an[11] << 24)
        i3 = an[12] | (an[13] << 8) | (an[14] << 16) | (an[15] << 24)

        sum0 ^= i0
        sum1 ^= i1
        sum2 ^= i2
        sum3 ^= i3

    # Convert back to bytes (little-endian for each 32-bit word)
    result = bytearray(16)
    for i, s in enumerate([sum0, sum1, sum2, sum3]):
        result[i*4] = s & 0xFF
        result[i*4 + 1] = (s >> 8) & 0xFF
        result[i*4 + 2] = (s >> 16) & 0xFF
        result[i*4 + 3] = (s >> 24) & 0xFF

    return bytes(result)


def build_put_request(
    raida_id: int,
    coins: List[CoinForPut],
    locker_key: bytes
) -> Tuple[bytes, bytes]:
    """
    Build PUT request for a single RAIDA.

    Args:
        raida_id: Target RAIDA (0-24)
        coins: List of coins to put in locker
        locker_key: 16-byte locker key (last 4 bytes must be 0xFF)

    Returns:
        Tuple of (complete request bytes, challenge bytes)
    """
    # Validate locker key format
    if len(locker_key) < 16:
        raise ValueError("Locker key must be 16 bytes")
    if locker_key[12:16] != bytes([0xFF, 0xFF, 0xFF, 0xFF]):
        raise ValueError("Locker key last 4 bytes must be 0xFF")

    # Generate challenge
    challenge = generate_challenge()

    # Build body
    # Body size: Challenge(16) + Coins(5*n) + Sum(16) + LockerKey(16) + Terminator(2)
    body_size = 16 + (5 * len(coins)) + 16 + 16 + 2
    body = bytearray(body_size)

    # Challenge (0-15)
    body[0:16] = challenge

    # Coin data (DN + SN for each)
    offset = 16
    for coin in coins:
        body[offset] = coin.denomination & 0xFF
        body[offset + 1] = (coin.serial_number >> 24) & 0xFF
        body[offset + 2] = (coin.serial_number >> 16) & 0xFF
        body[offset + 3] = (coin.serial_number >> 8) & 0xFF
        body[offset + 4] = coin.serial_number & 0xFF
        offset += 5

    # XOR sum of ANs (16 bytes)
    xor_sum = compute_an_xor_sum(coins, raida_id)
    body[offset:offset + 16] = xor_sum
    offset += 16

    # Locker key (16 bytes)
    body[offset:offset + 16] = locker_key[:16]
    offset += 16

    # Terminator
    body[offset:offset + 2] = TERMINATOR

    # Build header (32 bytes) - NO encryption
    header = bytearray(32)
    header[0] = 0x01                          # BF
    header[1] = 0x00                          # SP
    header[2] = raida_id                      # RI
    header[3] = 0x00                          # SH
    header[4] = CMD_GROUP_LOCKER              # CG: 8
    header[5] = CMD_LOCKER_PUT                # CM: 82 (0x52)
    struct.pack_into('>H', header, 6, COIN_TYPE)  # ID: 0x0006

    # Presentation bytes (8-15) - all zeros
    # Encryption bytes (16-23) - all zeros (type 0 = no encryption)
    # Nonce bytes (24-31) - all zeros

    # Body length at bytes 22-23
    struct.pack_into('>H', header, 22, len(body))

    return bytes(header) + bytes(body), challenge


def send_put_request(
    host: str,
    port: int,
    request: bytes,
    timeout: float = 10.0
) -> Optional[bytes]:
    """Send PUT request and receive response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(request)
        response = sock.recv(4096)
        return response
    except Exception as e:
        print(f"Network error: {e}")
        return None
    finally:
        sock.close()


def parse_put_response(
    response: bytes,
    expected_challenge: bytes,
    coin_count: int
) -> Tuple[int, List[bool]]:
    """
    Parse PUT response.

    Args:
        response: Raw response bytes
        expected_challenge: Challenge sent in request
        coin_count: Number of coins in request

    Returns:
        Tuple of (status code, list of per-coin results)
    """
    if len(response) < 32:
        return -1, [False] * coin_count

    # Parse header
    status = response[2]

    # Verify challenge echo (bytes 16-31 in response)
    if len(response) >= 32:
        echoed_challenge = response[16:32]
        if echoed_challenge != expected_challenge:
            print(f"Challenge mismatch!")

    # Parse results based on status
    if status == STATUS_ALL_PASS:
        return status, [True] * coin_count
    elif status == STATUS_ALL_FAIL:
        return status, [False] * coin_count
    elif status == STATUS_MIXED:
        # Parse per-coin results from body
        # Body format: 4 bytes padding + bitfield
        results = []
        if len(response) > 36:
            body = response[32:]
            # Skip 4 padding bytes
            bitfield_start = 4
            for i in range(coin_count):
                byte_idx = bitfield_start + (i // 8)
                bit_idx = i % 8
                if byte_idx < len(body):
                    passed = bool((body[byte_idx] >> bit_idx) & 1)
                    results.append(passed)
                else:
                    results.append(False)
        else:
            results = [False] * coin_count
        return status, results
    else:
        # Error status
        return status, [False] * coin_count


async def put_to_locker(
    coins: List[CoinForPut],
    locker_keys: List[bytes],
    timeout: float = 10.0
) -> Tuple[PutResult, Dict[int, Tuple[int, List[bool]]]]:
    """
    Put coins into locker on all RAIDA.

    Args:
        coins: List of coins to store
        locker_keys: 25 x 16-byte locker keys (one per RAIDA)
        timeout: Request timeout in seconds

    Returns:
        Tuple of (overall result, per-RAIDA results dict)
    """
    results: Dict[int, Tuple[int, List[bool]]] = {}

    async def put_single_raida(raida_id: int):
        host, port = RAIDA_SERVERS[raida_id]
        locker_key = locker_keys[raida_id]

        try:
            request, challenge = build_put_request(raida_id, coins, locker_key)

            # Run synchronous socket in executor
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, send_put_request, host, port, request, timeout
            )

            if response is None:
                results[raida_id] = (-1, [False] * len(coins))
                return

            status, coin_results = parse_put_response(response, challenge, len(coins))
            results[raida_id] = (status, coin_results)

        except Exception as e:
            print(f"RAIDA {raida_id} error: {e}")
            results[raida_id] = (-1, [False] * len(coins))

    # Run all RAIDA requests concurrently
    tasks = [put_single_raida(i) for i in range(RAIDA_COUNT)]
    await asyncio.gather(*tasks)



# DEBUG: Log all results
    for raida_id, (status, coin_results) in sorted(results.items()):
        print(f"RAIDA {raida_id}: status={status} (0x{status:02x})" if status >= 0 else f"RAIDA {raida_id}: status={status}")
       
    # Determine overall result
    pass_count = sum(1 for s, _ in results.values() if s == STATUS_ALL_PASS)

    if pass_count >= 13:
        return PutResult.SUCCESS, results
    elif pass_count > 0:
        return PutResult.PARTIAL_SUCCESS, results
    else:
        return PutResult.ALL_FAIL, results


# Test function
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '.')

    from key_manager import get_keys_from_locker_code

    async def test_put():
        # Create a test coin with random ANs
        test_coin = CoinForPut(
            denomination=1,
            serial_number=12345678,
            ans=[os.urandom(16) for _ in range(25)]
        )

        # Generate locker code and keys
        locker_code = "TST-1234"
        locker_keys = get_keys_from_locker_code(locker_code)

        print(f"Testing PUT with locker code: {locker_code}")
        print(f"Coin: DN={test_coin.denomination}, SN={test_coin.serial_number}")
        print()

        # Test single RAIDA first
        raida_id = 11
        host, port = RAIDA_SERVERS[raida_id]
        locker_key = locker_keys[raida_id]

        print(f"Testing RAIDA {raida_id} ({host}:{port})")
        print(f"Locker key: {locker_key.hex()}")

        request, challenge = build_put_request(raida_id, [test_coin], locker_key)
        print(f"Request size: {len(request)} bytes")
        print(f"Header: {request[:32].hex()}")
        print(f"Body: {request[32:].hex()}")
        print(f"Challenge: {challenge.hex()}")

        response = send_put_request(host, port, request)
        if response:
            print(f"Response size: {len(response)} bytes")
            print(f"Response header: {response[:32].hex()}")
            status = response[2]
            print(f"Status: {status} (0x{status:02x})")
            if status == STATUS_ALL_PASS:
                print("SUCCESS - All coins stored!")
            elif status == STATUS_ALL_FAIL:
                print("FAIL - All coins failed")
            elif status == STATUS_MIXED:
                print("MIXED - Some coins passed")
            else:
                print(f"Error status: {status}")
        else:
            print("No response received")

    asyncio.run(test_put())
