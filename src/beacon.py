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



def init_beacon(
    identity_config: IdentityConfig,
    beacon_config: BeaconConfig,
    network_config: NetworkConfig,
    key_file_path: str,
    state_file_path: str,
    logger_handle: Optional[object] = None
) -> Optional[BeaconHandle]:
    """
    Initializes the Beacon Manager handle. Supports .key files and keys.txt.
    Initializes the Beacon Manager handle.

    Args:
        identity_config: User's identity information.
        beacon_config: Beacon server configuration.
        network_config: Network timeout settings.
        key_file_path: Path to the user's key file.
        state_file_path: Path to store persistent state (e.g., last_check).
        logger_handle: Handle to the logger.

    Returns:
        A BeaconHandle for use with other functions, or None on failure.

    """
    log_debug(logger_handle, "Beacon", f"Initializing beacon from {key_file_path}...")
    
    encryption_key = None
    try:
        if key_file_path.lower().endswith('.key'):
            # Logic for binary CloudCoin .key files
            ans = []
            with open(key_file_path, 'r') as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and len(clean_line) == 32:
                        ans.append(bytes.fromhex(clean_line))
            
            if len(ans) >= 25:
                # Get the AN for the specific RAIDA server index
                encryption_key = ans[beacon_config.server_index]
            else:
                log_error(logger_handle, "Beacon", f"Key file {key_file_path} has only {len(ans)} keys; need 25.")
                return None
        else:
            # Fallback for legacy keys.txt
            with open(key_file_path, 'r') as f:
                keys = [line.strip() for line in f.readlines() if line.strip()]
            
            if len(keys) <= beacon_config.server_index:
                log_error(logger_handle, "Beacon", f"Key file has too few lines for index {beacon_config.server_index}.")
                return None
            
            encryption_key = bytes.fromhex(keys[beacon_config.server_index])

    except (IOError, ValueError) as e:
        log_error(logger_handle, "Beacon", f"Failed to read or parse beacon key: {e}")
        return None

    # Get or generate a persistent Device ID
    device_id, is_new = device_id_manager.get_or_create_device_id(state_file_path, logger_handle)

    # Parse beacon server host and port
    try:
        if not beacon_config.url.startswith("tcp://"):
            raise ValueError("Beacon URL must start with 'tcp://'")
        host, port_str = beacon_config.url.replace("tcp://", "").split(":")
        port = int(port_str)
    except (ValueError, IndexError) as e:
        log_error(logger_handle, "Beacon", f"Invalid beacon URL format '{beacon_config.url}': {e}")
        return None

    return BeaconHandle(
        identity=identity_config,
        beacon_config=beacon_config,
        network_config=network_config,
        beacon_server_info=ServerConfig(address=host, port=port, index=beacon_config.server_index),
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

    Args:
        handle: The BeaconHandle to stop.
        timeout: How many seconds to wait for the thread to shut down.

    Returns:
        True if the monitor stopped cleanly, False if it timed out.
    """
    if handle is None or not handle.is_running:
        log_info(handle.logger_handle, "Beacon", "Monitor is not running or handle is invalid.")
        return True

    log_info(handle.logger_handle, "Beacon", "Attempting to stop beacon monitor thread...")
    handle.shutdown_event.set()

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
    Performs a single, non-blocking PEEK request to check for tells
    since a specific timestamp.

    Args:
        handle: The initialized BeaconHandle.
        since_timestamp: Unix timestamp. If None, uses the last timestamp from state.

    Returns:
        A tuple of (NetworkErrorCode, List of TellNotification objects).
    """
    if handle is None:
        return NetworkErrorCode.ERR_INVALID_PARAM, []

    timestamp_to_check = since_timestamp if since_timestamp is not None else handle.last_tell_timestamp
    log_debug(handle.logger_handle, "Beacon", f"Performing PEEK for tells since timestamp {timestamp_to_check}.")

    conn = None
    try:
        err, conn = network.connect_to_server(
            server_info=handle.beacon_server_info,
            encryption_key=handle.encryption_key,
            denomination=handle.identity.denomination,
            serial_number=handle.identity.serial_number,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            return err, []

        peek_body = protocol.build_peek_body(
            denomination=handle.identity.denomination,
            serial_number=handle.identity.serial_number,
            device_id=handle.device_id,
            an=handle.encryption_key,
            since_timestamp=timestamp_to_check
        )

        err, resp_header, resp_body = network.send_request(
            connection=conn,
            command_group=protocol.CMD_GROUP_QMAIL,
            command_code=protocol.CMD_PEEK,
            body_data=peek_body,
            encrypt=True,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )

        if err != NetworkErrorCode.SUCCESS:
            return err, []

        if resp_header.status != StatusCode.STATUS_SUCCESS:
            log_debug(handle.logger_handle, "Beacon", f"PEEK returned status {resp_header.status}, no new tells.")
            return NetworkErrorCode.SUCCESS, []

        parse_err, tells = protocol.parse_tell_response(resp_body, handle.logger_handle)
        if parse_err != protocol.ProtocolErrorCode.SUCCESS:
            return NetworkErrorCode.ERR_INVALID_RESPONSE, []

        if tells:
            # Update the in-memory state of the handle
            latest_ts = max(t.timestamp for t in tells)
            if latest_ts > handle.last_tell_timestamp:
                handle.last_tell_timestamp = latest_ts
                _save_state(handle) # Persist the new latest timestamp
        
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
    Continuously polls the beacon server for new mail notifications.
    """
    log_info(handle.logger_handle, "BeaconLoop", "Monitoring loop started.")
    
    # On first run, load state and perform a PEEK to catch up on missed messages
    _load_state(handle)
    if handle.last_tell_timestamp > 0:
        log_info(handle.logger_handle, "BeaconLoop", "Performing initial PEEK to catch up on missed messages...")
        err, tells = do_peek(handle)
        if err == NetworkErrorCode.SUCCESS and tells and handle.on_mail_received:
            log_info(handle.logger_handle, "BeaconLoop", f"PEEK found {len(tells)} new messages.")
            try:
                handle.on_mail_received(tells)
            except Exception as e:
                log_error(handle.logger_handle, "BeaconLoop", f"Initial PEEK callback failed: {e}")

    retry_delay_sec = 1.0
    max_retry_delay_sec = 60.0

    while not handle.shutdown_event.is_set():
        try:
            err, tells = _do_one_ping_cycle(handle)
            
            if err == NetworkErrorCode.SUCCESS:
                retry_delay_sec = 1.0  
                
                if tells and handle.on_mail_received:
                    log_info(handle.logger_handle, "BeaconLoop", f"Received {len(tells)} new mail notifications via PING.")
                    try:
                        # Update state with the latest timestamp from the new tells
                        latest_ts = max(t.timestamp for t in tells)
                        if latest_ts > handle.last_tell_timestamp:
                            handle.last_tell_timestamp = latest_ts
                            _save_state(handle)

                        # Asynchronously invoke callback to avoid blocking the loop
                        cb_thread = threading.Thread(target=handle.on_mail_received, args=(tells,))
                        cb_thread.start()
                    except Exception as e:
                        log_error(handle.logger_handle, "BeaconLoop", f"Mail callback failed: {e}")
                else:
                    log_debug(handle.logger_handle, "BeaconLoop", "Ping successful, no new mail.")
                
                continue

            else:
                log_warning(handle.logger_handle, "BeaconLoop", f"Ping cycle failed with error '{err.name}'. Retrying in {retry_delay_sec:.1f}s.")
                
        except Exception as e:
            log_error(handle.logger_handle, "BeaconLoop", f"Unhandled exception in monitor loop: {e}. Retrying in {retry_delay_sec:.1f}s.")

        wait_start_time = time.time()
        while time.time() - wait_start_time < retry_delay_sec:
            if handle.shutdown_event.wait(timeout=0.5):
                break
        
        retry_delay_sec = min(retry_delay_sec * 2, max_retry_delay_sec)

    log_info(handle.logger_handle, "BeaconLoop", "Monitoring loop has been shut down.")


def _do_one_ping_cycle(handle: BeaconHandle) -> (NetworkErrorCode, List[TellNotification]):
    """
    Executes a single, complete long-poll PING cycle.
    Connects, sends, waits, receives, parses, and disconnects.
    This function demonstrates the clean abstraction provided by other modules.
    """
    conn = None
    try:
        # Connect to the beacon server, passing the user's full identity
        # and encryption key. This is critical for the server to find the
        # correct coin and decrypt the request body.
        err, conn = network.connect_to_server(
            server_info=handle.beacon_server_info,
            encryption_key=handle.encryption_key,
            denomination=handle.identity.denomination,
            serial_number=handle.identity.serial_number,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )
        if err != NetworkErrorCode.SUCCESS:
            return err, []

        # 2. Build the PING request body using a protocol helper
        # This keeps the byte-packing logic out of the beacon module.
        ping_body = protocol.build_ping_body(
            denomination=handle.identity.denomination,
            serial_number=handle.identity.serial_number,
            device_id=handle.device_id,
            an=handle.encryption_key
        )

        # 3. Send the request via the network module
        # The network module handles header creation, encryption, and sending.
        err, resp_header, resp_body = network.send_request(
            connection=conn,
            command_group=protocol.CMD_GROUP_QMAIL,
            command_code=protocol.CMD_PING,
            body_data=ping_body,
            encrypt=True, # Explicitly use encryption
            timeout_ms=handle.beacon_config.timeout_sec * 1000,
            config=handle.network_config,
            logger_handle=handle.logger_handle
        )

        if err != NetworkErrorCode.SUCCESS:
            return err, []

        # 4. Handle server status codes
        if resp_header.status == StatusCode.STATUS_YOU_GOT_MAIL or resp_header.status == StatusCode.STATUS_SUCCESS:
             # STATUS_SUCCESS (250) is used in the doc for new mail
            pass # Continue to parse the body
        elif resp_header.status == StatusCode.ERROR_UDP_FRAME_TIMEOUT: # Status 17
            # This is the expected "no new mail" response for a long-poll
            return NetworkErrorCode.SUCCESS, []
        else:
            log_warning(handle.logger_handle, "Beacon", f"Beacon server returned an unexpected status: {resp_header.status}")
            return NetworkErrorCode.ERR_SERVER_ERROR, []

        # 5. Parse the response body using a protocol helper
        # This keeps the complex byte-parsing logic out of the beacon module.
        parse_err, tells = protocol.parse_tell_response(resp_body, handle.logger_handle)
        if parse_err != protocol.ProtocolErrorCode.SUCCESS:
            return NetworkErrorCode.ERR_INVALID_RESPONSE, []

        return NetworkErrorCode.SUCCESS, tells

    finally:
        # 6. Ensure disconnection
        if conn:
            network.disconnect(conn, handle.logger_handle)
