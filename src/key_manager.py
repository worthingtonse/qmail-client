import hashlib
import threading
import os
import glob
from typing import List, Union

# A lock to ensure thread-safe access to locker key files
_locker_file_lock = threading.Lock()


def get_keys_from_locker_code(locker_code: Union[str, bytes]) -> List[bytes]:
    """
    Generates 25 128-bit (16-byte) keys from a given locker code.

    Key derivation: key[i] = MD5(str(i) + locker_code) for i in 0..24

    The server ID is prepended to the locker code before hashing.
    Server ID is determined by port number: port 50011 -> server ID 11.

    The locker code can be either:
    - A string (any string from locker_keys.txt file)
    - 8 bytes (e.g., from tell notification, converted to hex)

    For bytes input, the locker code is converted to hex string before
    key derivation to ensure consistent key generation.

    Args:
        locker_code: The locker code as string or 8 bytes.

    Returns:
        A list of 25 128-bit keys as bytes.

    Raises:
        ValueError: If locker code is empty or None.
    """
    if not locker_code:
        raise ValueError("Locker code cannot be empty.")

    # Convert bytes to hex string for consistent key derivation
    if isinstance(locker_code, bytes):
        locker_code_str = locker_code.hex()
    else:
        locker_code_str = str(locker_code)

    keys = []
    for i in range(25):
        h = hashlib.md5()
        h.update(str(i).encode('utf-8'))           # Server ID FIRST
        h.update(locker_code_str.encode('utf-8'))  # Locker code SECOND
        keys.append(h.digest())
    return keys


def get_decryption_key(locker_code: Union[str, bytes], server_id: int) -> bytes:
    """
    Get the decryption key for a specific server.

    The key is derived from the locker code using MD5. Each server
    has its own key based on its ID (0-24).

    Args:
        locker_code: The locker code as string or 8 bytes.
        server_id: Server ID (0-24), corresponds to RAIDA ID.

    Returns:
        16-byte decryption key for the specified server.

    Raises:
        ValueError: If server_id is out of range (0-24).
    """
    if server_id < 0 or server_id > 24:
        raise ValueError(f"Server ID must be 0-24, got {server_id}")

    keys = get_keys_from_locker_code(locker_code)
    return keys[server_id]

def get_next_locker_code(data_dir: str = "Data") -> str:
    """
    Reads a single locker code from a .locker_keys.txt file, removes it,
    and returns it. This function is thread-safe.

    It will search for any '*.locker_keys.txt' file in the specified directory,
    read the first line, and rewrite the file without that line.

    Args:
        data_dir: The directory where the locker key files are stored.

    Returns:
        The first locker code found.

    Raises:
        FileNotFoundError: If no locker key files are found or all are empty.
        IOError: If there are issues reading or writing the file.
    """
    with _locker_file_lock:
        locker_files = glob.glob(os.path.join(data_dir, '*.locker_keys.txt'))
        if not locker_files:
            raise FileNotFoundError("No locker key files ('*.locker_keys.txt') found.")

        for file_path in locker_files:
            try:
                with open(file_path, 'r+') as f:
                    lines = f.readlines()
                    if not lines:
                        # File is empty, try the next one
                        continue

                    # Get the first line (the locker code)
                    locker_code = lines[0].strip()
                    if not locker_code:
                        # Line is empty, try next file
                        continue

                    # Write the rest of the lines back to the file
                    f.seek(0)
                    f.writelines(lines[1:])
                    f.truncate()

                    return locker_code

            except IOError as e:
                # Log this error, but try the next file
                print(f"Error processing locker file {file_path}: {e}")
                continue

    # If we get here, no files had any usable keys
    raise FileNotFoundError("All locker key files are empty or could not be read.")
