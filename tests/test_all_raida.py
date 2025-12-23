"""
Test all 25 RAIDA servers and display their response status codes.
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from locker_download import get_raida_servers, RAIDA_COUNT
from key_manager import get_keys_from_locker_code
from network_async import (
    connect_async, send_raw_request_async, disconnect_async, NetworkErrorCode
)
from protocol import build_complete_locker_download_request, ProtocolErrorCode
import secrets


async def test_all_raida(locker_key):
    print(f'Testing locker key: {locker_key}')
    print('=' * 85)

    # Get locker keys
    locker_keys = get_keys_from_locker_code(locker_key.encode('utf-8'))

    # Generate seeds
    seeds = [secrets.token_bytes(16) for _ in range(25)]

    # Get servers (suppress logging)
    servers = await get_raida_servers(None, None)

    # Track results
    results = {}

    print(f"\nConnecting to {RAIDA_COUNT} RAIDA servers...\n")

    # Test each RAIDA
    for raida_id in range(25):
        server = servers[raida_id]
        host = server.host
        port = server.port

        try:
            # Build request
            err, request, challenge, nonce = build_complete_locker_download_request(
                raida_id=raida_id,
                locker_key=locker_keys[raida_id],
                seed=seeds[raida_id],
                logger_handle=None
            )

            if err != ProtocolErrorCode.SUCCESS:
                results[raida_id] = {'status': 'BUILD_ERROR', 'code': 0, 'host': host, 'port': port}
                continue

            # Connect
            err, conn = await connect_async(
                server_info=server,
                timeout_ms=8000,
                logger_handle=None
            )

            if err != NetworkErrorCode.SUCCESS:
                results[raida_id] = {'status': 'CONNECT_FAIL', 'code': 0, 'host': host, 'port': port}
                continue

            try:
                # Send request
                err, response_header, response_body = await send_raw_request_async(
                    conn=conn,
                    raw_request=request,
                    timeout_ms=8000,
                    logger_handle=None
                )

                if err != NetworkErrorCode.SUCCESS:
                    results[raida_id] = {'status': 'SEND_ERROR', 'code': 0, 'host': host, 'port': port, 'err': err.name}
                else:
                    status_code = response_header.status if response_header else -1
                    body_size = response_header.body_size if response_header else 0
                    body_hex = response_body.hex() if response_body else ''
                    results[raida_id] = {'status': 'OK', 'code': status_code, 'host': host, 'port': port, 'body': body_size, 'body_hex': body_hex}
            finally:
                await disconnect_async(conn, None)

        except asyncio.TimeoutError:
            results[raida_id] = {'status': 'TIMEOUT', 'code': 0, 'host': host, 'port': port}
        except Exception as e:
            results[raida_id] = {'status': 'ERROR', 'code': 0, 'host': host, 'port': port, 'err': str(e)[:40]}

    # Print results table
    print(f"{'RAIDA':<6} {'IP Address':<18} {'Port':<7} {'Code':<6} {'Hex':<6} {'Body':<6} {'Meaning'}")
    print('-' * 85)

    status_meanings = {
        16: 'Locker empty (valid response)',
        33: 'Challenge/decryption failed',
        34: 'Invalid packet length (CRC)',
        179: 'Locker does not exist',
        250: 'Success with coins',
        255: 'All fail / cmd unsupported',
    }

    for raida_id in range(25):
        r = results.get(raida_id, {'status': 'UNKNOWN', 'code': 0, 'host': '', 'port': 0})
        host = r.get('host', '')
        port = r.get('port', 0)
        status = r.get('status', '')
        code = r.get('code', 0)
        body = r.get('body', 0)

        if status == 'OK':
            meaning = status_meanings.get(code, f'Unknown status')
            print(f"{raida_id:<6} {host:<18} {port:<7} {code:<6} 0x{code:02x}   {body:<6} {meaning}")
        else:
            extra = r.get('err', '')
            print(f"{raida_id:<6} {host:<18} {port:<7} {'--':<6} {'--':<6} {'--':<6} {status} {extra}")

    print('=' * 85)

    # Summary
    ok_count = sum(1 for r in results.values() if r['status'] == 'OK')
    status_16 = sum(1 for r in results.values() if r.get('code') == 16)
    status_33 = sum(1 for r in results.values() if r.get('code') == 33)
    status_34 = sum(1 for r in results.values() if r.get('code') == 34)
    status_255 = sum(1 for r in results.values() if r.get('code') == 255)

    print(f"\nSummary: {ok_count}/25 responded")
    print(f"  Status 16  (0x10) - Locker empty/valid: {status_16}")
    print(f"  Status 33  (0x21) - Challenge failed:   {status_33}")
    print(f"  Status 34  (0x22) - CRC/packet error:   {status_34}")
    print(f"  Status 255 (0xff) - Cmd unsupported:    {status_255}")


if __name__ == "__main__":
    locker_key = sys.argv[1] if len(sys.argv) > 1 else "ETD-CJ9X"
    asyncio.run(test_all_raida(locker_key))
