"""
test_peek.py - PEEK Command Test
FIXED: Uses RAIDA 0, loads secret AN from .bin file, and uses correct offsets.
"""

import sys
import os
import socket
import struct
from typing import Tuple

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from protocol import build_complete_peek_request, ProtocolErrorCode, STATUS_SUCCESS
from config import load_config  

def load_identity_an(identity, logger=None):
    """
    Manually loads the 400-byte AN block from the coin file.
    Matches logic in app.py:407-422.
    """
    base_name = f"0006{identity.denomination:02X}{identity.serial_number:08X}"
    path_bin = os.path.join("Data", "Wallets", "Default", "Bank", f"{base_name}.BIN")
    path_key = os.path.join("Data", "Wallets", "Default", "Bank", f"{base_name}.KEY")
    
    key_file = path_bin if os.path.exists(path_bin) else path_key
    
    if not os.path.exists(key_file):
        print(f"  [FAIL] Identity coin file not found: {key_file}")
        return None

    try:
        with open(key_file, 'rb') as f:
            header = f.read(32)
            format_type = header[0]
            
            # Offsets: Format 9 = 39, Legacy = 48, else 32
            offset = 39 if format_type == 9 else 48 if format_type == 0 else 32
            f.seek(offset)
            an_block = f.read(400)
            
            if len(an_block) == 400:
                return an_block
    except Exception as e:
        print(f"  [ERROR] Failed to read AN from {key_file}: {e}")
    
    return None

def run_peek_test():
    print("\n" + "=" * 72)
    print("  QMAIL PEEK TEST - Target: RAIDA 0")
    print("=" * 72)

    # 1. Load configuration
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'qmail.toml')
    config = load_config(config_path)
    
    # FORCE Server 0 as requested
    raida0 = config.qmail_servers[0]
    target_ip = raida0.address
    target_port = raida0.port
    raida_id = raida0.index # Should be 0

    identity = config.identity
    print(f"Targeting: {target_ip}:{target_port} (RAIDA {raida_id})")
    print(f"Identity: SN {identity.serial_number}")

    # 2. Load Secret AN (The fix for the NoneType error)
    an_bytes = load_identity_an(identity)
    if an_bytes is None:
        return False

    # Extract the 16-byte slice for RAIDA 0
    server_an = an_bytes[raida_id * 16 : (raida_id + 1) * 16]
    print(f"  [OK] Loaded 16-byte key for RAIDA {raida_id}")

    # 3. Connect via Raw TCP
    try:
        conn = socket.create_connection((target_ip, target_port), timeout=10)
        print(f"  [OK] Connected to RAIDA {raida_id}")
    except Exception as e:
        print(f"  [FAIL] Connection failed: {e}")
        return False

    # 4. Build and Send Request
    err, request, challenge, _ = build_complete_peek_request(
        raida_id=raida_id,
        denomination=identity.denomination,
        serial_number=identity.serial_number,
        device_id=0,
        an=server_an,
        since_timestamp=0,
        encryption_type=0
    )

    if err != ProtocolErrorCode.SUCCESS:
        print(f"  [FAIL] Builder failed: {err}")
        conn.close()
        return False

    try:
        conn.sendall(request)
        response = conn.recv(2048)
        
        if len(response) < 32:
            print(f"  [FAIL] Response too short ({len(response)} bytes)")
            return False

        # Byte 2 Status Offset
        status = response[2]
        
        if status == STATUS_SUCCESS:
            print(f"  [OK] Success (250) - Received {len(response)} bytes.")
            return True
        elif status == 200:
            print(f"  [FAIL] Authentication Failed (200). RAIDA does not recognize this AN.")
            return False
        else:
            print(f"  [FAIL] Server Error Status: {status}")
            return False
    except Exception as e:
        print(f"  [FAIL] Network error during transfer: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = run_peek_test()
    print("\n" + "=" * 72)
    print("  TEST " + ("PASSED" if success else "FAILED"))
    print("=" * 72 + "\n")