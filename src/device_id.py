"""
gemini_device_id.py - Portable Device ID Manager

This module provides a cross-platform, persistent device ID for the client.
It avoids platform-specific hardware queries (like MAC addresses) to ensure
the code is easily portable to C.

Author: Gemini
"""

import os
import json
import uuid
from typing import Optional, Tuple

def get_or_create_device_id(
    state_file_path: str,
    logger_handle: Optional[object] = None
) -> (int, bool):
    """
    Gets a persistent 8-bit device ID from a state file.

    If the state file or the ID within it does not exist, a new random ID is
    generated, saved to the file, and returned. This ensures the device ID
    is stable across application restarts.

    Per protocol specification, Device ID is an 8-bit field (0-255).

    Args:
        state_file_path: The path to the JSON file for storing state.
        logger_handle: Optional logger handle.

    Returns:
        A tuple containing:
        - The 8-bit integer device ID (0-255).
        - A boolean indicating if the ID was newly created.
    """
    from logger import log_warning, log_debug

    device_id: Optional[int] = None
    is_new = False
    data = {}

    try:
        if os.path.exists(state_file_path):
            with open(state_file_path, 'r') as f:
                data = json.load(f)
                device_id = data.get('device_id')
                # Ensure existing device IDs are also 8-bit
                if device_id is not None:
                    device_id = device_id & 0xFF
    except (IOError, json.JSONDecodeError) as e:
        log_warning(logger_handle, "DeviceID", f"Could not read or parse state file '{state_file_path}': {e}. A new one will be created.")
        data = {}

    if device_id is None:
        is_new = True
        # Generate a new random 8-bit ID from a UUID.
        # This is more portable than using MAC addresses.
        # Protocol spec defines Device ID as 8-bit (1 byte).
        device_id = uuid.uuid4().int & 0xFF
        data['device_id'] = device_id
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(state_file_path), exist_ok=True)
            # Atomically write the new state file
            temp_path = state_file_path + ".tmp"
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(temp_path, state_file_path)
            log_debug(logger_handle, "DeviceID", f"Saved new device ID {device_id} to '{state_file_path}'.")
        except IOError as e:
            log_warning(logger_handle, "DeviceID", f"Failed to save new device ID to state file: {e}")
            # Continue with the generated ID in memory for this session
    
    return device_id, is_new
