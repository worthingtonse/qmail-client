"""Test PUT command on multiple RAIDA to verify protocol."""
import sys
import os
import asyncio
sys.path.insert(0, 'src')

from locker_put import (
    CoinForPut, build_put_request, send_put_request, RAIDA_SERVERS,
    STATUS_ALL_PASS, STATUS_ALL_FAIL, STATUS_MIXED
)
from key_manager import get_keys_from_locker_code

# Status code meanings (from server code)
STATUS_NAMES = {
    40: "ERROR_INVALID_SN_OR_DENOMINATION",
    241: "STATUS_ALL_PASS",
    242: "STATUS_ALL_FAIL",
    243: "STATUS_MIXED",
    34: "ERROR_INVALID_CRC",
    16: "ERROR_INVALID_PACKET_LENGTH",
}

async def test_put():
    # Create a test coin with random ANs
    test_coin = CoinForPut(
        denomination=1,
        serial_number=12345678,
        ans=[os.urandom(16) for _ in range(25)]
    )

    locker_code = "TST-2024"
    locker_keys = get_keys_from_locker_code(locker_code)

    print(f"Testing PUT with locker code: {locker_code}")
    print(f"Coin: DN={test_coin.denomination}, SN={test_coin.serial_number}")
    print(f"(Expecting error since coin doesn't exist on RAIDA)")
    print()

    results = {}

    for raida_id in [0, 3, 7, 11, 15, 20]:
        host, port = RAIDA_SERVERS[raida_id]
        locker_key = locker_keys[raida_id]

        request, challenge = build_put_request(raida_id, [test_coin], locker_key)
        response = send_put_request(host, port, request, timeout=10)

        if response:
            status = response[2]
            echoed = response[16:32]
            challenge_ok = echoed == challenge

            status_name = STATUS_NAMES.get(status, f"UNKNOWN({status})")
            print(f"RAIDA {raida_id:2d}: Status={status:3d} (0x{status:02x}) {status_name:30s} Challenge OK: {challenge_ok}")
            results[raida_id] = status
        else:
            print(f"RAIDA {raida_id:2d}: No response")
            results[raida_id] = None

    print()
    print("Summary:")
    crc_errors = sum(1 for s in results.values() if s == 34)
    length_errors = sum(1 for s in results.values() if s == 16)
    sn_errors = sum(1 for s in results.values() if s == 40)
    print(f"  CRC errors (0x22): {crc_errors}")
    print(f"  Length errors (0x10): {length_errors}")
    print(f"  SN/DN errors (0x28): {sn_errors}")

    if crc_errors == 0 and length_errors == 0:
        print("\nProtocol is CORRECT! Errors are due to invalid coin, not protocol.")

if __name__ == "__main__":
    asyncio.run(test_put())
