# gemini_config.py
"""
This module handles loading, managing, and validating the qmail.toml configuration.
It uses strongly-typed dataclasses to represent the configuration structure,
ensuring type safety and providing a clear, self-documenting interface.
"""

import sys
from pathlib import Path
from typing import Any, Optional

# Use the standard library tomllib if available (Python 3.11+)
# Otherwise, fall back to the third-party 'tomli' library for reading.
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# For writing TOML files, a third-party library is required.
try:
    import tomli_w
except ImportError:
    tomli_w = None

# Import the dataclass structures
from types import (
    QMailConfig, ValidationResult, ServerConfig, PathsConfig, IdentityConfig,
    EncryptionConfig, BeaconConfig, RaidConfig, NetworkConfig, ThreadingConfig,
    ApiConfig, LoggingConfig
)

DEFAULT_CONFIG_FILENAME = "gemini_qmail.toml"

def _get_from_dict(data: dict, key: str, default: Any = None) -> Any:
    """Safely gets a value from a nested dictionary using dot notation."""
    keys = key.split('.')
    value = data
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            return default
    return value if value is not None else default


def load_config(config_path: str = DEFAULT_CONFIG_FILENAME) -> QMailConfig:
    """
    Loads, parses, and validates the configuration from a TOML file.

    Args:
        config_path: The path to the configuration file.

    Returns:
        A QMailConfig object populated with the settings.

    Raises:
        RuntimeError: If a TOML parsing library is not installed.
        FileNotFoundError: If the specified config file does not exist.
        ValueError: If the TOML file is malformed or fails validation.
    """
    if tomllib is None:
        raise RuntimeError("TOML library not found. Please run 'pip install tomli'.")

    config_file = Path(config_path)
    if not config_file.is_file():
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Error decoding TOML file '{config_path}': {e}") from e

    # Populate the dataclasses from the parsed dictionary
    config = QMailConfig(
        paths=PathsConfig(
            db_path=_get_from_dict(data, "paths.db_path", "Data/qmail.db"),
            log_path=_get_from_dict(data, "paths.log_path", "Data/mail.mlog"),
            attachments_path=_get_from_dict(data, "paths.attachments_path", "Data/attachments")
        ),
        identity=IdentityConfig(
            coin_type=_get_from_dict(data, "identity.coin_type", 6),
            denomination=_get_from_dict(data, "identity.denomination", 1),
            serial_number=_get_from_dict(data, "identity.serial_number", 0),
            device_id=_get_from_dict(data, "identity.device_id", 1)
        ),
        encryption=EncryptionConfig(
            enabled=_get_from_dict(data, "encryption.enabled", True),
            mode=_get_from_dict(data, "encryption.mode", 1)
        ),
        beacon=BeaconConfig(
            url=_get_from_dict(data, "beacon.url", "tcp://168.220.219.199:50014"),
            interval_sec=_get_from_dict(data, "beacon.interval_sec", 600),
            timeout_sec=_get_from_dict(data, "beacon.timeout_sec", 600)
        ),
        raid=RaidConfig(
            data_stripe_count=_get_from_dict(data, "raid.data_stripe_count", 4),
            parity_stripe_count=_get_from_dict(data, "raid.parity_stripe_count", 1)
        ),
        network=NetworkConfig(
            connection_timeout_ms=_get_from_dict(data, "network.connection_timeout_ms", 5000),
            read_timeout_ms=_get_from_dict(data, "network.read_timeout_ms", 30000),
            max_retries=_get_from_dict(data, "network.max_retries", 3)
        ),
        threading=ThreadingConfig(
            pool_size=_get_from_dict(data, "threading.pool_size", 5)
        ),
        api=ApiConfig(
            enabled=_get_from_dict(data, "api.enabled", True),
            host=_get_from_dict(data, "api.host", "127.0.0.1")
        ),
        logging=LoggingConfig(
            level=_get_from_dict(data, "logging.level", "info"),
            max_size_mb=_get_from_dict(data, "logging.max_size_mb", 10),
            backup_count=_get_from_dict(data, "logging.backup_count", 3)
        ),
        qmail_servers=[ServerConfig(**s) for s in data.get("qmail_servers", [])],
        raida_servers=[ServerConfig(**s) for s in data.get("raida_servers", [])]
    )
    
    # Automatically validate after loading
    validation_result = validate_config(config)
    if not validation_result.is_valid:
        errors = "\n".join(f"  - {e}" for e in validation_result.errors)
        raise ValueError(f"Configuration failed validation:\n{errors}")

    if validation_result.warnings:
        print("Configuration warnings:", file=sys.stderr)
        for warning in validation_result.warnings:
            print(f"  - {warning}", file=sys.stderr)
            
    return config

def save_config(config: QMailConfig, path: str = DEFAULT_CONFIG_FILENAME) -> bool:
    """
    Saves a configuration object to a TOML file.

    Args:
        config: The QMailConfig object to save.
        path: The destination file path.

    Returns:
        True if saving was successful, False otherwise.
    """
    if tomli_w is None:
        print("Error: 'tomli-w' library is required to save configs. Please run 'pip install tomli-w'", file=sys.stderr)
        return False
        
    # This is a simplified conversion. A real implementation would be more robust.
    data = {
        "paths": config.paths.__dict__,
        "identity": config.identity.__dict__,
        "encryption": config.encryption.__dict__,
        "beacon": config.beacon.__dict__,
        "raid": config.raid.__dict__,
        "network": config.network.__dict__,
        "threading": config.threading.__dict__,
        "api": config.api.__dict__,
        "logging": config.logging.__dict__,
        "qmail_servers": [s.__dict__ for s in config.qmail_servers],
        "raida_servers": [s.__dict__ for s in config.raida_servers]
    }

    try:
        with open(path, "wb") as f:
            tomli_w.dump(data, f)
        return True
    except IOError as e:
        print(f"Error: Failed to save configuration to '{path}': {e}", file=sys.stderr)
        return False

def get_config_value(config: QMailConfig, key: str) -> Any:
    """
    Retrieves a value from the config using a dot-separated key.

    Args:
        config: The QMailConfig object.
        key: The dot-separated key (e.g., "network.beacon.url").

    Returns:
        The value if found, otherwise None.
    """
    try:
        parts = key.split('.')
        value = config
        for part in parts:
            value = getattr(value, part)
        return value
    except AttributeError:
        return None

def set_config_value(config: QMailConfig, key: str, value: Any) -> None:
    """
    Sets a value in the config using a dot-separated key.

    Args:
        config: The QMailConfig object to modify.
        key: The dot-separated key to set.
        value: The new value to assign.
        
    Raises:
        AttributeError: If the key path is invalid.
    """
    parts = key.split('.')
    obj = config
    for part in parts[:-1]:
        obj = getattr(obj, part)
    setattr(obj, parts[-1], value)

def validate_config(config: QMailConfig) -> ValidationResult:
    """
    Validates the provided QMailConfig object.

    Args:
        config: The configuration object to validate.

    Returns:
        A ValidationResult object containing the outcome.
    """
    result = ValidationResult()

    # Identity
    if config.identity.serial_number == 0:
        result.add_error("identity.serial_number must be set by the user and cannot be 0.")

    # API
    if config.api.port is not None:
        result.add_warning("api.port should not be set in the config file; use the --port CLI argument.")

    # Server Counts
    if len(config.qmail_servers) != 5:
        result.add_error(f"Expected 5 qmail_servers, but found {len(config.qmail_servers)}.")
    
    if len(config.raida_servers) != 25:
        result.add_error(f"Expected 25 raida_servers, but found {len(config.raida_servers)}.")

    # Threading
    if config.threading.pool_size < (config.raid.data_stripe_count + config.raid.parity_stripe_count):
        result.add_warning("threading.pool_size is less than the total number of stripe servers.")

    return result

# Example Usage
if __name__ == "__main__":
    try:
        print(f"--- Loading configuration from '{DEFAULT_CONFIG_FILENAME}' ---")
        cfg = load_config()
        print("Configuration loaded successfully.")
        
        print("\n--- Testing get_config_value ---")
        print(f'Beacon URL: {get_config_value(cfg, "beacon.url")}')
        print(f'Original Log Level: {get_config_value(cfg, "logging.level")}')

        print("\n--- Testing set_config_value ---")
        set_config_value(cfg, "logging.level", "debug")
        print(f'New Log Level: {get_config_value(cfg, "logging.level")}')
        
        print("\n--- Re-validating after change ---")
        validation = validate_config(cfg)
        if validation.is_valid:
            print("Configuration is still valid.")
        
        print("\n--- Testing save_config ---")
        test_save_path = "gemini_qmail.test.toml"
        if save_config(cfg, test_save_path):
            print(f"Configuration saved to '{test_save_path}'.")

    except (RuntimeError, FileNotFoundError, ValueError) as e:
        print(f"\n--- An error occurred ---", file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(1)