"""
Test all 25 RAIDA servers and display full hex REQUESTS and responses.
Shows both the request being sent and the response received.
"""
import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from locker_download import RAIDA_COUNT
from key_manager import get_keys_from_locker_code
from protocol import build_complete_locker_download_request, ProtocolErrorCode
import secrets


# Hardcoded RAIDA servers
RAIDA_SERVERS = [
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


def format_hex(data, width=16):
    """Format bytes as hex string with spaces, 16 bytes per line."""
    if not data:
        return "  (empty)"
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        lines.append(hex_str)
    return '\n'.join(lines)


def format_header_annotated(header):
    """Format 32-byte header with field annotations."""
    if len(header) < 32:
        return f"  Header too short: {len(header)} bytes"

    lines = []
    # Routing bytes (0-7)
    lines.append(f"  Routing (0-7):      {' '.join(f'{b:02x}' for b in header[0:8])}")
    lines.append(f"    BF={header[0]:02x} SP={header[1]:02x} RI={header[2]:02x} SH={header[3]:02x} CG={header[4]:02x} CM={header[5]:02x} ID={header[6]:02x}{header[7]:02x}")

    # Presentation bytes (8-15)
    lines.append(f"  Presentation (8-15): {' '.join(f'{b:02x}' for b in header[8:16])}")

    # Encryption bytes (16-23)
    lines.append(f"  Encryption (16-23):  {' '.join(f'{b:02x}' for b in header[16:24])}")
    lines.append(f"    EN={header[16]:02x} LK={header[17:22].hex()} BL={header[22]:02x}{header[23]:02x} ({(header[22]<<8)+header[23]} bytes)")

    # Nonce bytes (24-31)
    lines.append(f"  Nonce (24-31):       {' '.join(f'{b:02x}' for b in header[24:32])}")

    return '\n'.join(lines)


def test_raida(raida_id, host, port, locker_key, seed):
    """Build request and send to RAIDA. Returns request and response."""
    try:
        err, request, challenge, nonce = build_complete_locker_download_request(
            raida_id=raida_id,
            locker_key=locker_key,
            seed=seed,
            logger_handle=None
        )
        if err != ProtocolErrorCode.SUCCESS:
            return None, None, "BUILD_ERROR"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((host, port))
            sock.sendall(request)
            response = sock.recv(4096)
            return request, response, "OK"
        except socket.timeout:
            return request, None, "TIMEOUT"
        except ConnectionRefusedError:
            return request, None, "CONNECTION_REFUSED"
        except Exception as e:
            return request, None, str(e)[:40]
        finally:
            sock.close()
    except Exception as e:
        return None, None, str(e)[:40]


def main():
    locker_key = sys.argv[1] if len(sys.argv) > 1 else "RQG-2T38"
    print(f"Testing locker key: {locker_key}")
    print("=" * 80)

    locker_keys = get_keys_from_locker_code(locker_key.encode('utf-8'))
    seeds = [secrets.token_bytes(16) for _ in range(25)]

    for raida_id in range(25):
        host, port = RAIDA_SERVERS[raida_id]
        request, response, status = test_raida(
            raida_id, host, port,
            locker_keys[raida_id],
            seeds[raida_id]
        )

        print(f"\n{'='*80}")
        print(f"RAIDA {raida_id:2d} ({host}:{port})")
        print("=" * 80)

        if request:
            print(f"\nREQUEST ({len(request)} bytes):")
            print("-" * 60)
            print(format_header_annotated(request[:32]))
            print(f"\n  Full request hex (16 bytes per line):")
            print(format_hex(request))
        else:
            print(f"\n  Request build error: {status}")

        print(f"\nRESPONSE:")
        print("-" * 60)
        if response:
            resp_status = response[2] if len(response) > 2 else 0
            print(f"  Status byte: 0x{resp_status:02x} ({resp_status})")
            print(f"  Full response hex ({len(response)} bytes):")
            print(format_hex(response))
        else:
            print(f"  Error: {status}")


if __name__ == "__main__":
    main()
