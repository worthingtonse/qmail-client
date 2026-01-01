"""
Test all 25 RAIDA servers and display their response status codes.
"""
import sys
import os
import asyncio
import secrets
import hashlib

# Ensure path is correct for your local setup
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from locker_download import get_raida_servers, RAIDA_COUNT
from network_async import (
    connect_async, send_raw_request_async, disconnect_async, NetworkErrorCode
)
from protocol import build_complete_locker_download_request, ProtocolErrorCode

async def test_all_raida(locker_key):
    print(f'Testing locker key: {locker_key}')
    print('=' * 85)

    # Note: We no longer need to derive keys here because 
    # build_complete_locker_download_request handles it internally.

    # Generate 25 unique 16-byte seeds
    seeds = [secrets.token_bytes(16) for _ in range(25)]

    # Get server list
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
            # Build request using the human-readable string (e.g., "JP6-57GN")
            err, request, challenge, nonce = build_complete_locker_download_request(
                raida_id=raida_id,
                locker_code_str=locker_key, 
                seed=seeds[raida_id],
                logger_handle=None
            )

            if err != ProtocolErrorCode.SUCCESS:
                results[raida_id] = {'status': 'BUILD_ERROR', 'code': 0, 'host': host, 'port': port}
                continue

            # Connect to RAIDA
            err, conn = await connect_async(
                server_info=server,
                timeout_ms=8000,
                logger_handle=None
            )

            if err != NetworkErrorCode.SUCCESS:
                results[raida_id] = {'status': 'CONNECT_FAIL', 'code': 0, 'host': host, 'port': port}
                continue

            try:
                # Send the pre-built 82-byte packet
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
                    results[raida_id] = {'status': 'OK', 'code': status_code, 'host': host, 'port': port, 'body': body_size}
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
        16:  'Invalid Packet Length (Check Offset)',
        242: 'status all fail',
        250: 'Success (All Pass)',
        179: 'Locker Does Not Exist',
        33:  'Challenge Failed'
    }

    for raida_id in range(25):
        r = results.get(raida_id, {'status': 'UNKNOWN', 'code': 0, 'host': '', 'port': 0})
        host = r.get('host', '')
        port = r.get('port', 0)
        status = r.get('status', '')
        code = r.get('code', 0)
        body = r.get('body', 0)

        if status == 'OK':
            meaning = status_meanings.get(code, f'Unknown Status')
            print(f"{raida_id:<6} {host:<18} {port:<7} {code:<6} 0x{code:02x}   {body:<6} {meaning}")
        else:
            extra = r.get('err', '')
            print(f"{raida_id:<6} {host:<18} {port:<7} {'--':<6} {'--':<6} {'--':<6} {status} {extra}")

    print('=' * 85)

if __name__ == "__main__":
    locker_key = sys.argv[1] if len(sys.argv) > 1 else "D9Z-CXZK"
    asyncio.run(test_all_raida(locker_key))