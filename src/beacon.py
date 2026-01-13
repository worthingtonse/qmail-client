"""
gemini_beacon.py - Beacon Monitoring Module for QMail Client Core

This module provides a robust, thread-safe, and portable implementation for
monitoring a QMail beacon server for new mail notifications.

Author: Gemini
Phase: I
Version: 1.0.0

Architectural Philosophy:
This module is designed with a strong separation of concerns. Its ONLY
responsibility is to manage the long-polling lifecycle. It delegates all
protocol-specific byte manipulation, parsing, and encryption to specialized
helper modules (`gemini_protocol`, `network`). This makes the core beacon logic
simpler, more robust, and less prone to the protocol implementation bugs
found in other models. This design is clean, highly testable, and aligns
with the project's goal of eventual C-portability by creating clear,
well-defined module boundaries.
"""

import threading
import time
import os
import json
from typing import Any, Callable, List, Optional, Tuple

# Import project modules and types
# Note: This design relies on a clean network abstraction and protocol helpers.
try:
    import protocol
    import network
    import device_id as device_id_manager
    from qmail_types import (
        BeaconHandle,
        TellNotification,
        NetworkConfig,
        IdentityConfig,
        ServerConfig,
        BeaconConfig,
    )
    from network import NetworkErrorCode, StatusCode
    from logger import log_error, log_info, log_debug, log_warning
except ImportError:
    # Fallback for standalone testing
    print("ERROR: Cannot run gemini_beacon.py standalone. Missing core modules.")
    # Define dummy classes for type hinting if needed
    class BeaconHandle: pass
    class TellNotification: pass
    class NetworkConfig: pass
    class IdentityConfig: pass
    class ServerConfig: pass
    class BeaconConfig: pass
    class NetworkErrorCode: pass
    class StatusCode: pass
    def log_error(*args, **kwargs): pass
    def log_info(*args, **kwargs): pass
    def log_debug(*args, **kwargs): pass
    def log_warning(*args, **kwargs): pass
    print("Warning: Using dummy classes for type hinting.")


# ============================================================================
# PUBLIC API
# ============================================================================

# def init_beacon(
#     identity_config: IdentityConfig,
#     beacon_config: BeaconConfig,
#     network_config: NetworkConfig,
#     key_file_path: str,
#     state_file_path: str,
#     logger_handle: Optional[object] = None
# ) -> Optional[BeaconHandle]:
#     """
#     Initializes the Beacon Manager handle. 
#     FIXED: Supports binary .key files by skipping the 39-byte header and slicing the 400-byte key.
#     """
#     log_debug(logger_handle, "Beacon", f"Initializing beacon from {key_file_path}...")
    
#     encryption_key = None
#     try:
#         if key_file_path.lower().endswith('.key'):
#              if key_file_path.lower().endswith(('.key', '.bin')):
#             # Determine offset: .BIN is 32, .KEY is 39
#               offset = 32 if key_file_path.lower().endswith('.bin') else 39
            
#               with open(key_file_path, 'rb') as f:
#                 f.seek(offset) 
#                 full_key_bytes = f.read(400)
                
#                 if len(full_key_bytes) >= 400:
#                     start = beacon_config.server_index * 16
#                     encryption_key = full_key_bytes[start : start + 16]
#                 else:
#                     log_error(logger_handle, "Beacon", f"Key data too short in {key_file_path}")
#                     return None
#         else:
#             # Fallback for legacy keys.txt (text-based hex lines)
#             with open(key_file_path, 'r') as f:
#                 keys = [line.strip() for line in f.readlines() if line.strip()]
            
#             if len(keys) <= beacon_config.server_index:
#                 log_error(logger_handle, "Beacon", f"Key file has too few lines for index {beacon_config.server_index}.")
#                 return None
            
#             encryption_key = bytes.fromhex(keys[beacon_config.server_index])

#     except (IOError, ValueError) as e:
#         log_error(logger_handle, "Beacon", f"Failed to read or parse beacon key: {e}")
#         return None

#     # Get or generate a persistent Device ID
#     device_id, is_new = device_id_manager.get_or_create_device_id(state_file_path, logger_handle)

#     # Parse beacon server host and port
#     try:
#         if not beacon_config.url.startswith("tcp://"):
#             raise ValueError("Beacon URL must start with 'tcp://'")
#         host, port_str = beacon_config.url.replace("tcp://", "").split(":")
#         port = int(port_str)
#     except (ValueError, IndexError) as e:
#         log_error(logger_handle, "Beacon", f"Invalid beacon URL format '{beacon_config.url}': {e}")
#         return None

#     return BeaconHandle(
#         identity=identity_config,
#         beacon_config=beacon_config,
#         network_config=network_config,
#         beacon_server_info=ServerConfig(address=host, port=port, index=beacon_config.server_index),
#         encryption_key=encryption_key,
#         device_id=device_id,
#         state_file_path=state_file_path,
#         logger_handle=logger_handle
#     )

def init_beacon(
    identity_config: IdentityConfig,
    beacon_config: BeaconConfig,
    network_config: NetworkConfig,
    key_file_path: str,
    state_file_path: str,
    logger_handle: Optional[object] = None
) -> Optional[BeaconHandle]:
    """
    Initializes the Beacon Manager handle. 
    FIXED: Smart offset detection based on file size to handle .bin and .key correctly.
    """
    log_debug(logger_handle, "Beacon", f"Initializing beacon from {key_file_path}...")
    
    encryption_key = None
    try:
        # 1. Get exact file size to determine the header offset
        file_size = os.path.getsize(key_file_path)
        
        # Mapping based on standard CloudCoin formats:
        # 400 bytes: Raw AN block (Offset 0)
        # 439 bytes: Format 9 Binary (Offset 39)
        # 448 bytes: Legacy Binary (Offset 48)
        if file_size == 400:
            offset = 0
        elif file_size == 439:
            offset = 39
        elif file_size == 448:
            offset = 48
        else:
            # Fallback logic if it's a non-standard size
            offset = 39 if key_file_path.lower().endswith('.bin') else 0
            
        with open(key_file_path, 'rb') as f:
            f.seek(offset) 
            full_key_bytes = f.read(400)
            
            if len(full_key_bytes) >= 400:
                # Extract the 16-byte slice for the specific RAIDA
                start = beacon_config.server_index * 16
                encryption_key = full_key_bytes[start : start + 16]
            else:
                log_error(logger_handle, "Beacon", f"Key data too short in {key_file_path}")
                return None

    except Exception as e:
        log_error(logger_handle, "Beacon", f"Failed to read or parse beacon key: {e}")
        return None

    # Get or generate a persistent Device ID
    device_id, _ = device_id_manager.get_or_create_device_id(state_file_path, logger_handle)

    # Parse beacon server host and port
    host, port_str = beacon_config.url.replace("tcp://", "").split(":")

    return BeaconHandle(
        identity=identity_config,
        beacon_config=beacon_config,
        network_config=network_config,
        beacon_server_info=ServerConfig(address=host, port=int(port_str), index=beacon_config.server_index),
        encryption_key=encryption_key,
        device_id=device_id,
        state_file_path=state_file_path,
        logger_handle=logger_handle
    )

def start_beacon_monitor(
    handle: BeaconHandle,
    on_mail_received: Callable[[List[TellNotification]], None]
) -> bool:
    """
    Starts the background thread to monitor the beacon server.

    Args:
        handle: The BeaconHandle from init_beacon.
        on_mail_received: A callback function to be invoked when new mail is detected.
                          The callback will receive a list of TellNotification objects.

    Returns:
        True if the monitor started successfully, False otherwise.
    """
    if handle is None:
        log_error(None, "Beacon", "Cannot start monitor with an invalid handle.")
        return False

    if handle.is_running:
        log_warning(handle.logger_handle, "Beacon", "Monitor is already running.")
        return False

    handle.on_mail_received = on_mail_received
    handle.shutdown_event.clear()
    
    # A non-daemon thread is safer as it allows for graceful shutdown
    # and state saving, even if the main application exits unexpectedly.
    handle.monitor_thread = threading.Thread(
        target=_monitor_loop,
        args=(handle,),
        name="GeminiBeaconMonitor",
        daemon=False 
    )
    
    handle.is_running = True
    handle.monitor_thread.start()
    log_info(handle.logger_handle, "Beacon", "Beacon monitor thread started.")
    return True


def stop_beacon_monitor(handle: BeaconHandle, timeout: float = 10.0) -> bool:
    """
    Stops the background beacon monitoring thread gracefully.
    FIXED: Added check to prevent 'cannot join current thread' error.
    """
    if handle is None or not handle.is_running:
        log_info(handle.logger_handle, "Beacon", "Monitor is not running or handle is invalid.")
        return True

    log_info(handle.logger_handle, "Beacon", "Attempting to stop beacon monitor thread...")
    
    # 1. Signal the thread to stop via the Event object
    handle.shutdown_event.set()

    # 2. Prevent self-joining deadlock
    # Check if the thread calling this function IS the monitor thread itself
    if threading.current_thread() == handle.monitor_thread:
        log_debug(handle.logger_handle, "Beacon", "Stop called from within the monitor thread. Signaling only.")
        handle.is_running = False
        # We don't join here; we let the loop finish naturally
        return True

    # 3. If called from an external thread (like app.py shutdown), we join normally
    if handle.monitor_thread:
        handle.monitor_thread.join(timeout)
        if handle.monitor_thread.is_alive():
            log_error(handle.logger_handle, "Beacon", "Beacon monitor thread failed to stop within timeout.")
            return False

    handle.is_running = False
    log_info(handle.logger_handle, "Beacon", "Beacon monitor stopped successfully.")
    return True

def do_peek(handle: BeaconHandle, since_timestamp: Optional[int] = None) -> Tuple[NetworkErrorCode, List[TellNotification]]:
    """
    Performs a single, non-blocking PEEK request.
    FIXED: Halt loop immediately and trigger healing on ERR_INVALID_AN.
    """
    if handle is None:
        return NetworkErrorCode.ERR_INVALID_PARAM, []
 
    from src.protocol import custom_sn_to_int 
    from src.logger import log_error, log_warning
    # 1. Resolve Identity to Numeric (e.g., C25 -> 2843)
    numeric_sn = custom_sn_to_int(handle.identity.serial_number)
    timestamp_to_check = since_timestamp if since_timestamp is not None else handle.last_tell_timestamp
 
    conn = None
    try:
        # 2. Network Connection logic
        err, conn = network.connect_to_server(
            server_info=handle.beacon_server_info,
            encryption_key=handle.encryption_key,
            denomination=handle.identity.denomination,
            serial_number=numeric_sn,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            return err, []
 
        # 3. Request Building
        err_proto, peek_req, _, _ = protocol.build_complete_peek_request(
            raida_id=handle.beacon_server_info.index,
            denomination=handle.identity.denomination,
            serial_number=numeric_sn,
            device_id=handle.device_id,
            an=handle.encryption_key,
            since_timestamp=timestamp_to_check,
            encryption_type=0, 
            logger_handle=handle.logger_handle
        )
        if err_proto != protocol.ProtocolErrorCode.SUCCESS:
            return NetworkErrorCode.ERR_INVALID_PARAM, []
 
        err, resp_header, resp_body = network.send_raw_request(
            connection=conn,
            raw_packet=peek_req,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )
 
        if err != NetworkErrorCode.SUCCESS:
            return err, []
 
        # --- THE CRITICAL FIX: TRIGGER HEALING & STOP LOOP ---
        if resp_header.status == 200: # Status 200 = Invalid AN
            log_error(handle.logger_handle, "Beacon", f"CRITICAL: Invalid AN for SN {numeric_sn}. Halting monitor.")
            # 1. FORCE STOP: 
            handle.is_running = False 
            # 2. TRIGGER HEALING: Check if callback exists
            if hasattr(handle, 'on_an_invalid') and handle.on_an_invalid:
                log_warning(handle.logger_handle, "Beacon", "Initializing identity healing sequence...")
                handle.on_an_invalid(handle.identity)
            else:
                # Fallback: if callback is not registered log manual intervention
                log_error(handle.logger_handle, "Beacon", "Healing callback not registered on handle! Moving to Fracked manually.")
                # 
            return NetworkErrorCode.ERR_INVALID_AN, []
 
        # Standard Success logic
        if resp_header.status != 241: # Standard PEEK success is often 241 or 0
            return NetworkErrorCode.SUCCESS, []
 
        parse_err, tells = protocol.parse_tell_response(resp_body, handle.logger_handle)
        return NetworkErrorCode.SUCCESS, tells
    finally:
        if conn:
            network.disconnect(conn, handle.logger_handle)
# ============================================================================
# INTERNAL STATE AND MONITORING LOGIC
# ============================================================================

def _load_state(handle: BeaconHandle):
    """Loads the last tell timestamp from the state file into the handle."""
    try:
        if os.path.exists(handle.state_file_path):
            with open(handle.state_file_path, 'r') as f:
                data = json.load(f)
                handle.last_tell_timestamp = data.get('last_tell_timestamp', 0)
                log_info(handle.logger_handle, "Beacon", f"Loaded last_tell_timestamp: {handle.last_tell_timestamp}")
    except (IOError, json.JSONDecodeError) as e:
        log_warning(handle.logger_handle, "Beacon", f"Could not load state file: {e}. Starting fresh.")
        handle.last_tell_timestamp = 0

def _save_state(handle: BeaconHandle):
    """Saves the current last tell timestamp from the handle to the state file."""
    try:
        # Read existing data to preserve other values like device_id
        data = {}
        if os.path.exists(handle.state_file_path):
            with open(handle.state_file_path, 'r') as f:
                data = json.load(f)
        
        data['last_tell_timestamp'] = handle.last_tell_timestamp
        data['device_id'] = handle.device_id
        
        temp_path = handle.state_file_path + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, handle.state_file_path)
    except (IOError, json.JSONDecodeError) as e:
        log_error(handle.logger_handle, "Beacon", f"Failed to save beacon state: {e}")

def _monitor_loop(handle: BeaconHandle):
    """
    The main loop for the background thread.
    FIXED: Uses PEEK-Flush to clear RAIDA notification queue and prevent infinite loops.
    """
    import time
    from src.logger import log_info, log_error, log_warning, log_debug
    from src.network import NetworkErrorCode
    from src.database import get_contact_by_id

    log_info(handle.logger_handle, "BeaconLoop", "Monitoring loop started.")
    
    # Load last known timestamp from disk
    _load_state(handle)
    
    # =========================================================================
    # PHASE 1: INITIAL CATCHUP (Using PEEK)
    # =========================================================================
    log_info(handle.logger_handle, "BeaconLoop", "Phase 1: Catching up with new mail...")
    catchup_complete = False
    
    while not catchup_complete and not handle.shutdown_event.is_set():
        # do_peek clears the queue as it reads
        err, tells = do_peek(handle, since_timestamp=handle.last_tell_timestamp)
        
        if err == NetworkErrorCode.SUCCESS:
            if tells:
                log_info(handle.logger_handle, "BeaconLoop", f"Catchup: Received {len(tells)} pending notifications")
                
                # Advance timestamp to the latest notification found
                latest_ts = max(t.timestamp for t in tells)
                handle.last_tell_timestamp = latest_ts
                _save_state(handle)
                
                # Process via callback in app.py
                if handle.on_mail_received:
                    try:
                        handle.on_mail_received(tells)
                    except Exception as e:
                        log_error(handle.logger_handle, "BeaconLoop", f"Catchup callback failed: {e}")
            else:
                log_info(handle.logger_handle, "BeaconLoop", "Catchup complete.")
                catchup_complete = True
        else:
            log_warning(handle.logger_handle, "BeaconLoop", f"Catchup failed: {err.name}. Retrying...")
            handle.shutdown_event.wait(timeout=2.0)

    # =========================================================================
    # PHASE 2: ACTIVE LONG-POLLING (Using PING)
    # =========================================================================
    log_info(handle.logger_handle, "BeaconLoop", "Phase 2: Active long-poll monitoring...")
    
    retry_delay_sec = 1.0

    while not handle.shutdown_event.is_set():
        try:
            # Execute one long-poll cycle
            err, tells = _do_one_ping_cycle(handle)
            
            if handle.shutdown_event.is_set(): 
                break

            if err == NetworkErrorCode.SUCCESS:
                retry_delay_sec = 1.0 # Reset backoff
                
                if tells:
                    # Determine if mail is actually new or a re-send from server buffer
                    latest_ts = max(t.timestamp for t in tells)
                    is_old_mail = latest_ts <= handle.last_tell_timestamp
                    
                    if not is_old_mail:
                        # CASE A: Genuine new mail
                        handle.last_tell_timestamp = latest_ts
                        _save_state(handle)
                        
                        if handle.on_mail_received:
                            handle.on_mail_received(tells)
                    else:
                        # CASE B: THE INFINITE LOOP FIX (Old mail detected)
                        current_time = int(time.time())
                        log_warning(handle.logger_handle, "BeaconLoop", 
                                    f"Old mail detected ({len(tells)}). Flushing RAIDA queue with PEEK...")
                        
                        # Calling do_peek (Command 63) forcerfully acknowledges/clears notifications on RAIDA
                        do_peek(handle, since_timestamp=current_time)
                        
                        # Advance local timestamp to 'Now' to ensure we never see these again
                        handle.last_tell_timestamp = current_time
                        _save_state(handle)
                        
                        # Cooldown to prevent tight-looping
                        handle.shutdown_event.wait(timeout=5.0)
                else:
                    log_debug(handle.logger_handle, "BeaconLoop", "Long-poll timeout - no mail.")
                
            elif err == NetworkErrorCode.ERR_INVALID_AN:
                log_error(handle.logger_handle, "BeaconLoop", "Identity fracked. Stopping monitor.")
                break
                
            else:
                # Network error backoff
                handle.shutdown_event.wait(timeout=retry_delay_sec)
                retry_delay_sec = min(retry_delay_sec * 2, 60.0)
                
        except Exception as e:
            log_error(handle.logger_handle, "BeaconLoop", f"Unhandled exception: {e}")
            handle.shutdown_event.wait(timeout=5.0)

    log_info(handle.logger_handle, "BeaconLoop", "Monitoring loop stopped.")
def _do_one_ping_cycle(handle: BeaconHandle) -> Tuple[NetworkErrorCode, List[TellNotification]]:
    """
    Executes a single, complete long-poll PING cycle.
    FIXED: Passes since_timestamp to clear the notification queue on RAIDA.
    """
    from src.protocol import custom_sn_to_int
    numeric_sn = custom_sn_to_int(handle.identity.serial_number)
    
    conn = None
    try:
        # Connect using strict integer SN
        err, conn = network.connect_to_server(
            server_info=handle.beacon_server_info,
            encryption_key=handle.encryption_key,
            denomination=handle.identity.denomination,
            serial_number=numeric_sn,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            return err, []

        # FIXED: Forwarding last_tell_timestamp to RAIDA
        err_proto, ping_req, challenge, nonce = protocol.build_complete_ping_request(
            raida_id=handle.beacon_server_info.index,
            denomination=handle.identity.denomination,
            serial_number=numeric_sn,
            device_id=handle.device_id,
            an=handle.encryption_key,
            since_timestamp=handle.last_tell_timestamp, # <--- CRITICAL FIX
            encryption_type=0, 
            logger_handle=handle.logger_handle
        )
        
        if err_proto != protocol.ProtocolErrorCode.SUCCESS:
            return NetworkErrorCode.ERR_INVALID_PARAM, []

        err, resp_header, resp_body = network.send_raw_request(
            connection=conn,
            raw_packet=ping_req,
            timeout_ms=handle.beacon_config.timeout_sec * 1000,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )

        if err != NetworkErrorCode.SUCCESS:
            return err, []

        # Success check
        if resp_header.status in [StatusCode.STATUS_YOU_GOT_MAIL, StatusCode.STATUS_SUCCESS, 0]:
            pass 
        elif resp_header.status == StatusCode.ERROR_UDP_FRAME_TIMEOUT: 
            return NetworkErrorCode.SUCCESS, []
        elif resp_header.status == 200:
            log_error(handle.logger_handle, "Beacon", f"INVALID AN (200) for SN {numeric_sn}")
            return NetworkErrorCode.ERR_INVALID_AN, []
        else:
            return NetworkErrorCode.ERR_SERVER_ERROR, []

        parse_err, tells = protocol.parse_tell_response(resp_body, handle.logger_handle)
        if parse_err != protocol.ProtocolErrorCode.SUCCESS:
            return NetworkErrorCode.ERR_INVALID_RESPONSE, []

        return NetworkErrorCode.SUCCESS, tells

    finally:
        if conn:
            network.disconnect(conn, handle.logger_handle)