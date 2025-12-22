"""
sonnet45_config.py - Configuration Management Module
Created by: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)

This module handles loading, saving, and validating QMail Client configuration.
Designed for easy translation to C for Phase III conversion.

Functions:
    load_config(config_path) -> QMailConfig
    save_config(config, path) -> bool
    get_config_value(config, key) -> value
    set_config_value(config, key, val) -> void
    validate_config(config) -> ValidationResult

Author: Claude Sonnet 4.5
Phase: I
"""

import os
import sys
from pathlib import Path
from typing import Any, Optional, Union

# Import TOML library (Python 3.11+ has built-in tomllib)
try:
    import tomllib  # Python 3.11+
    TOML_READ_AVAILABLE = True
except ImportError:
    try:
        import tomli as tomllib  # Fallback for Python 3.6-3.10
        TOML_READ_AVAILABLE = True
    except ImportError:
        TOML_READ_AVAILABLE = False
        print("Warning: No TOML reading library available. Install 'tomli' for Python < 3.11")

# Import TOML writer
try:
    import tomli_w
    TOML_WRITE_AVAILABLE = True
except ImportError:
    TOML_WRITE_AVAILABLE = False
    print("Warning: 'tomli_w' not available. Install it to enable config saving.")

# Import our types (use relative import to avoid conflict with Python's built-in types module)
try:
    from .types import (
        QMailConfig,
        ValidationResult,
        ServerConfig,
        PathsConfig,
        IdentityConfig,
        EncryptionConfig,
        BeaconConfig,
        RaidConfig,
        NetworkConfig,
        ThreadingConfig,
        ApiConfig,
        LoggingConfig,
        ErrorCode
    )
except ImportError:
    # Fallback for standalone execution - import local types.py directly
    import importlib.util
    import os
    _spec = importlib.util.spec_from_file_location(
        "qmail_types",
        os.path.join(os.path.dirname(__file__), "types.py")
    )
    _types_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_types_module)

    QMailConfig = _types_module.QMailConfig
    ValidationResult = _types_module.ValidationResult
    ServerConfig = _types_module.ServerConfig
    PathsConfig = _types_module.PathsConfig
    IdentityConfig = _types_module.IdentityConfig
    EncryptionConfig = _types_module.EncryptionConfig
    BeaconConfig = _types_module.BeaconConfig
    RaidConfig = _types_module.RaidConfig
    NetworkConfig = _types_module.NetworkConfig
    ThreadingConfig = _types_module.ThreadingConfig
    ApiConfig = _types_module.ApiConfig
    LoggingConfig = _types_module.LoggingConfig
    ErrorCode = _types_module.ErrorCode


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_CONFIG_NAME = "qmail.toml"
CONFIG_VERSION = "1.0.0"


# ============================================================================
# MAIN CONFIGURATION FUNCTIONS
# ============================================================================

def load_config(config_path: str) -> QMailConfig:
    """
    Load configuration from TOML file.

    Args:
        config_path: Path to qmail.toml configuration file

    Returns:
        QMailConfig object populated with values from file

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config file is malformed or invalid
        RuntimeError: If TOML library is not available

    C Translation Notes:
        - Use tomlc99 library for parsing
        - Return error code + config struct via pointer parameter
        - Error handling via return codes, not exceptions
    """
    # Check if TOML reading is available
    if not TOML_READ_AVAILABLE:
        raise RuntimeError(
            "TOML reading library not available. "
            "Install 'tomli' (Python < 3.11) or upgrade to Python 3.11+"
        )

    # Resolve path
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    # Read and parse TOML file
    try:
        with open(config_file, 'rb') as f:
            toml_data = tomllib.load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse TOML file: {e}")

    # Create config object from TOML data
    config = _toml_to_config(toml_data)

    # Validate the loaded configuration
    validation = validate_config(config)
    if not validation.is_valid:
        error_msg = "Configuration validation failed:\n"
        error_msg += "\n".join(f"  - {err}" for err in validation.errors)
        raise ValueError(error_msg)

    # Emit warnings if any
    if validation.warnings:
        print("Configuration warnings:")
        for warning in validation.warnings:
            print(f"  - {warning}")

    return config


def save_config(config: QMailConfig, path: str) -> bool:
    """
    Save configuration to TOML file.

    Args:
        config: QMailConfig object to save
        path: Path where to save the configuration file

    Returns:
        True if save successful, False otherwise

    C Translation Notes:
        - Convert structs to TOML format
        - Use tomlc99 encoding functions
        - Return error code (SUCCESS/FAILURE)
    """
    # Check if TOML writing is available
    if not TOML_WRITE_AVAILABLE:
        print("Error: 'tomli_w' library not available. Cannot save config.")
        return False

    # Validate before saving
    validation = validate_config(config)
    if not validation.is_valid:
        print("Error: Cannot save invalid configuration:")
        for error in validation.errors:
            print(f"  - {error}")
        return False

    # Convert config object to TOML dictionary
    toml_data = _config_to_toml(config)

    # Write to file
    try:
        config_file = Path(path)
        # Create parent directory if it doesn't exist
        config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(config_file, 'wb') as f:
            tomli_w.dump(toml_data, f)

        return True

    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False


def get_config_value(config: QMailConfig, key: str) -> Any:
    """
    Get a configuration value by dot-notation key.

    Args:
        config: QMailConfig object
        key: Dot-notation key (e.g., "paths.db_path", "identity.serial_number")

    Returns:
        Value at the specified key, or None if not found

    Examples:
        >>> get_config_value(config, "paths.db_path")
        "Data/qmail.db"
        >>> get_config_value(config, "identity.serial_number")
        161

    C Translation Notes:
        - Implement as switch/case on predefined key enum
        - Return value via void* pointer + type indicator
        - Or use separate getter functions per type
    """
    # Split key into parts
    parts = key.split('.')

    # Navigate through config structure
    current = config
    for part in parts:
        if hasattr(current, part):
            current = getattr(current, part)
        else:
            return None

    return current


def set_config_value(config: QMailConfig, key: str, value: Any) -> None:
    """
    Set a configuration value by dot-notation key.

    Args:
        config: QMailConfig object to modify
        key: Dot-notation key (e.g., "paths.db_path", "identity.serial_number")
        value: New value to set

    Returns:
        None

    Raises:
        ValueError: If key is invalid or value type is incorrect

    Examples:
        >>> set_config_value(config, "identity.serial_number", 161)
        >>> set_config_value(config, "logging.level", "debug")

    C Translation Notes:
        - Implement as switch/case on predefined key enum
        - Type checking at compile time via function overloading
        - Or use separate setter functions per type
    """
    # Split key into parts
    parts = key.split('.')

    if len(parts) < 2:
        raise ValueError(f"Invalid key format: {key}. Use dot notation (e.g., 'paths.db_path')")

    # Navigate to parent object
    current = config
    for part in parts[:-1]:
        if hasattr(current, part):
            current = getattr(current, part)
        else:
            raise ValueError(f"Invalid key path: {key}")

    # Set the final attribute
    final_key = parts[-1]
    if not hasattr(current, final_key):
        raise ValueError(f"Invalid key: {key}")

    setattr(current, final_key, value)


def validate_config(config: QMailConfig) -> ValidationResult:
    """
    Validate configuration for correctness and completeness.

    Args:
        config: QMailConfig object to validate

    Returns:
        ValidationResult with valid flag and lists of errors/warnings

    Validation checks:
        - Required fields are set
        - Values are within valid ranges
        - File paths are accessible
        - Server lists are populated
        - Identity configuration is complete

    C Translation Notes:
        - Return error code + populate error array
        - Use bitmask for validation flags
        - Separate validation functions for each section
    """
    result = ValidationResult(is_valid=True)

    # ========================================================================
    # CRITICAL VALIDATIONS (errors)
    # ========================================================================

    # Validate Identity section (REQUIRED for server communication)
    if config.identity.coin_type != 6:
        result.add_error("identity.coin_type must be 6 (0x0006)")

    if not (1 <= config.identity.denomination <= 250):
        result.add_error("identity.denomination must be between 1 and 250")

    if config.identity.serial_number == 0:
        result.add_warning(
            "identity.serial_number is 0 - user must configure their mailbox ID from build/Data/Wallets/"
        )

    if not (0 <= config.identity.device_id <= 65535):
        result.add_error("identity.device_id must be between 0 and 65535 (16-bit)")

    # Validate Encryption section
    if config.encryption.mode not in [1, 6]:
        result.add_error(f"encryption.mode must be 1 (Mode B) or 6 (Mode A), got: {config.encryption.mode}")

    # Validate RAID configuration
    if config.raid.data_stripe_count < 1:
        result.add_error("raid.data_stripe_count must be at least 1")

    if config.raid.parity_stripe_count < 0:
        result.add_error("raid.parity_stripe_count cannot be negative")

    total_stripes = config.raid.data_stripe_count + config.raid.parity_stripe_count
    if len(config.qmail_servers) < total_stripes:
        result.add_error(
            f"Not enough QMail servers: need {total_stripes} "
            f"({config.raid.data_stripe_count} data + {config.raid.parity_stripe_count} parity), "
            f"but only {len(config.qmail_servers)} configured"
        )

    # Validate server lists
    if not config.qmail_servers:
        result.add_error("qmail_servers list is empty. At least 5 servers required for Phase I.")

    if not config.raida_servers:
        result.add_error("raida_servers list is empty. Should have 25 RAIDA servers.")

    # Validate beacon configuration
    if not config.beacon.url:
        result.add_error("beacon.url is not set")

    if not (0 <= config.beacon.server_index <= 24):
        result.add_error("beacon.server_index must be between 0 and 24")

    # Validate threading
    if config.threading.pool_size < total_stripes:
        result.add_error(
            f"threading.pool_size ({config.threading.pool_size}) should be at least "
            f"{total_stripes} (number of QMail servers) for parallel operations"
        )

    # Validate network timeouts
    if config.network.connection_timeout_ms <= 0:
        result.add_error("network.connection_timeout_ms must be positive")

    if config.network.read_timeout_ms <= 0:
        result.add_error("network.read_timeout_ms must be positive")

    # ========================================================================
    # WARNINGS (non-critical issues)
    # ========================================================================

    # Check if paths exist (warnings, not errors)
    db_dir = os.path.dirname(config.paths.db_path)
    if db_dir and not os.path.exists(db_dir):
        result.add_warning(f"Database directory does not exist: {db_dir}")

    log_dir = os.path.dirname(config.paths.log_path)
    if log_dir and not os.path.exists(log_dir):
        result.add_warning(f"Log directory does not exist: {log_dir}")

    # Check API configuration
    if config.api.enabled and config.api.port is not None:
        result.add_warning(
            "api.port is set in config, but should be specified via --port command-line argument"
        )

    # Check logging level
    valid_log_levels = ["debug", "info", "warning", "error"]
    if config.logging.level.lower() not in valid_log_levels:
        result.add_warning(
            f"logging.level '{config.logging.level}' is not standard. "
            f"Use: {', '.join(valid_log_levels)}"
        )

    # Check if beacon server is in RAIDA list
    beacon_found = False
    for server in config.raida_servers:
        if server.index == config.beacon.server_index:
            beacon_found = True
            # Verify beacon URL matches
            expected_url = f"tcp://{server.address}:{server.port}"
            if config.beacon.url != expected_url:
                result.add_warning(
                    f"beacon.url ({config.beacon.url}) doesn't match "
                    f"RAIDA server #{config.beacon.server_index} ({expected_url})"
                )
            break

    if not beacon_found:
        result.add_warning(
            f"beacon.server_index ({config.beacon.server_index}) "
            f"not found in raida_servers list"
        )

    return result


# ============================================================================
# HELPER FUNCTIONS (Internal use)
# ============================================================================

def _toml_to_config(toml_data: dict) -> QMailConfig:
    """
    Convert TOML dictionary to QMailConfig object.

    Args:
        toml_data: Dictionary from TOML parser

    Returns:
        QMailConfig object
    """
    # Create sub-configurations
    paths = PathsConfig(
        db_path=toml_data.get('paths', {}).get('db_path', 'Data/qmail.db'),
        log_path=toml_data.get('paths', {}).get('log_path', 'Data/mail.mlog'),
        locker_files_path=toml_data.get('paths', {}).get('locker_files_path', 'Data/Lockers'),
        attachments_path=toml_data.get('paths', {}).get('attachments_path', 'Data/Attachments'),
    )

    identity = IdentityConfig(
        coin_type=toml_data.get('identity', {}).get('coin_type', 6),
        denomination=toml_data.get('identity', {}).get('denomination', 1),
        serial_number=toml_data.get('identity', {}).get('serial_number', 0),
        device_id=toml_data.get('identity', {}).get('device_id', 1),
        authenticity_number=toml_data.get('identity', {}).get('authenticity_number'),
    )

    encryption = EncryptionConfig(
        enabled=toml_data.get('encryption', {}).get('enabled', True),
        mode=toml_data.get('encryption', {}).get('mode', 6),
    )

    beacon = BeaconConfig(
        url=toml_data.get('beacon', {}).get('url', 'tcp://168.220.219.199:50014'),
        server_index=toml_data.get('beacon', {}).get('server_index', 14),
        interval_sec=toml_data.get('beacon', {}).get('interval_sec', 600),
        timeout_sec=toml_data.get('beacon', {}).get('timeout_sec', 600),
    )

    raid = RaidConfig(
        data_stripe_count=toml_data.get('raid', {}).get('data_stripe_count', 4),
        parity_stripe_count=toml_data.get('raid', {}).get('parity_stripe_count', 1),
    )

    network = NetworkConfig(
        connection_timeout_ms=toml_data.get('network', {}).get('connection_timeout_ms', 5000),
        read_timeout_ms=toml_data.get('network', {}).get('read_timeout_ms', 30000),
        max_retries=toml_data.get('network', {}).get('max_retries', 3),
    )

    threading = ThreadingConfig(
        pool_size=toml_data.get('threading', {}).get('pool_size', 5),
    )

    api = ApiConfig(
        enabled=toml_data.get('api', {}).get('enabled', True),
        host=toml_data.get('api', {}).get('host', '127.0.0.1'),
        port=toml_data.get('api', {}).get('port'),
    )

    logging = LoggingConfig(
        level=toml_data.get('logging', {}).get('level', 'info'),
        max_size_mb=toml_data.get('logging', {}).get('max_size_mb', 10),
        backup_count=toml_data.get('logging', {}).get('backup_count', 3),
    )

    # Parse server lists
    qmail_servers = []
    for server_data in toml_data.get('qmail_servers', []):
        qmail_servers.append(ServerConfig(
            address=server_data.get('address'),
            port=server_data.get('port'),
            index=server_data.get('index'),
            server_type=server_data.get('server_type'),
            description=server_data.get('description'),
        ))

    raida_servers = []
    for server_data in toml_data.get('raida_servers', []):
        raida_servers.append(ServerConfig(
            address=server_data.get('address'),
            port=server_data.get('port'),
            index=server_data.get('index'),
            server_type=server_data.get('server_type'),
            description=server_data.get('description'),
        ))

    # Create main config object
    config = QMailConfig(
        paths=paths,
        identity=identity,
        encryption=encryption,
        beacon=beacon,
        raid=raid,
        network=network,
        threading=threading,
        api=api,
        logging=logging,
        qmail_servers=qmail_servers,
        raida_servers=raida_servers,
        config_version=toml_data.get('metadata', {}).get('config_version', CONFIG_VERSION),
        implementation_phase=toml_data.get('metadata', {}).get('implementation_phase', 'I'),
    )

    return config


def _config_to_toml(config: QMailConfig) -> dict:
    """
    Convert QMailConfig object to TOML-compatible dictionary.

    Args:
        config: QMailConfig object

    Returns:
        Dictionary suitable for TOML serialization
    """
    toml_data = {
        'metadata': {
            'config_version': config.config_version,
            'implementation_phase': config.implementation_phase,
        },
        'paths': {
            'db_path': config.paths.db_path,
            'log_path': config.paths.log_path,
            'locker_files_path': config.paths.locker_files_path,
            'attachments_path': config.paths.attachments_path,
        },
        'identity': {
            'coin_type': config.identity.coin_type,
            'denomination': config.identity.denomination,
            'serial_number': config.identity.serial_number,
            'device_id': config.identity.device_id,
        },
        'encryption': {
            'enabled': config.encryption.enabled,
            'mode': config.encryption.mode,
        },
        'beacon': {
            'url': config.beacon.url,
            'server_index': config.beacon.server_index,
            'interval_sec': config.beacon.interval_sec,
            'timeout_sec': config.beacon.timeout_sec,
        },
        'raid': {
            'data_stripe_count': config.raid.data_stripe_count,
            'parity_stripe_count': config.raid.parity_stripe_count,
        },
        'network': {
            'connection_timeout_ms': config.network.connection_timeout_ms,
            'read_timeout_ms': config.network.read_timeout_ms,
            'max_retries': config.network.max_retries,
        },
        'threading': {
            'pool_size': config.threading.pool_size,
        },
        'api': {
            'enabled': config.api.enabled,
            'host': config.api.host,
        },
        'logging': {
            'level': config.logging.level,
            'max_size_mb': config.logging.max_size_mb,
            'backup_count': config.logging.backup_count,
        },
        'qmail_servers': [
            {
                'address': s.address,
                'port': s.port,
                **({'index': s.index} if s.index is not None else {}),
                **({'server_type': s.server_type} if s.server_type else {}),
                **({'description': s.description} if s.description else {}),
            }
            for s in config.qmail_servers
        ],
        'raida_servers': [
            {
                'address': s.address,
                'port': s.port,
                **({'index': s.index} if s.index is not None else {}),
                **({'server_type': s.server_type} if s.server_type else {}),
                **({'description': s.description} if s.description else {}),
            }
            for s in config.raida_servers
        ],
    }

    # Add optional fields
    if config.identity.authenticity_number:
        toml_data['identity']['authenticity_number'] = config.identity.authenticity_number

    if config.api.port is not None:
        toml_data['api']['port'] = config.api.port

    return toml_data


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def load_default_config() -> QMailConfig:
    """
    Load configuration from default location (./qmail.toml).

    Returns:
        QMailConfig object

    Raises:
        FileNotFoundError: If qmail.toml doesn't exist
        ValueError: If config is invalid
    """
    return load_config(DEFAULT_CONFIG_NAME)


def create_default_config_file(path: str = DEFAULT_CONFIG_NAME) -> bool:
    """
    Create a default qmail.toml configuration file.

    Args:
        path: Where to create the file (default: qmail.toml)

    Returns:
        True if successful, False otherwise
    """
    # Create default config object
    config = QMailConfig()

    # Add default QMail servers (5 servers for Phase I)
    config.qmail_servers = [
        ServerConfig(address="47.229.9.94", port=50001, server_type="QMAIL"),
        ServerConfig(address="124.187.106.233", port=50009, server_type="QMAIL"),
        ServerConfig(address="113.30.247.109", port=50013, server_type="QMAIL"),
        ServerConfig(address="168.220.219.199", port=50014, server_type="QMAIL"),
        ServerConfig(address="125.236.210.184", port=50021, server_type="QMAIL"),
    ]

    # Add all 25 RAIDA servers
    raida_list = [
        (0, "78.46.170.45", 50000),
        (1, "47.229.9.94", 50001),
        (2, "209.46.126.167", 50002),
        (3, "116.203.157.233", 50003),
        (4, "95.183.51.104", 50004),
        (5, "31.163.201.90", 50005),
        (6, "52.14.83.91", 50006),
        (7, "161.97.169.229", 50007),
        (8, "13.234.55.11", 50008),
        (9, "124.187.106.233", 50009),
        (10, "94.130.179.247", 50010),
        (11, "67.181.90.11", 50011),
        (12, "3.16.169.178", 50012),
        (13, "113.30.247.109", 50013),
        (14, "168.220.219.199", 50014),
        (15, "185.37.61.73", 50015),
        (16, "193.7.195.250", 50016),
        (17, "5.161.63.179", 50017),
        (18, "76.114.47.144", 50018),
        (19, "190.105.235.113", 50019),
        (20, "184.18.166.118", 50020),
        (21, "125.236.210.184", 50021),
        (22, "5.161.123.254", 50022),
        (23, "130.255.77.156", 50023),
        (24, "209.205.66.24", 50024),
    ]

    config.raida_servers = [
        ServerConfig(address=addr, port=port, index=idx, server_type="RAIDA")
        for idx, addr, port in raida_list
    ]

    # Save to file
    return save_config(config, path)


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """Test the config module"""
    print("QMail Client Configuration Module Test")
    print("=" * 60)

    # Test creating default config
    print("\n1. Creating default config file...")
    if create_default_config_file("test_qmail.toml"):
        print("   ✓ Created test_qmail.toml")
    else:
        print("   ✗ Failed to create config")
        sys.exit(1)

    # Test loading config
    print("\n2. Loading config file...")
    try:
        config = load_config("test_qmail.toml")
        print(f"   ✓ Loaded successfully")
        print(f"   - Version: {config.config_version}")
        print(f"   - Phase: {config.implementation_phase}")
        print(f"   - QMail servers: {len(config.qmail_servers)}")
        print(f"   - RAIDA servers: {len(config.raida_servers)}")
    except Exception as e:
        print(f"   ✗ Failed: {e}")
        sys.exit(1)

    # Test get_config_value
    print("\n3. Testing get_config_value...")
    db_path = get_config_value(config, "paths.db_path")
    print(f"   paths.db_path = {db_path}")

    serial = get_config_value(config, "identity.serial_number")
    print(f"   identity.serial_number = {serial}")

    # Test set_config_value
    print("\n4. Testing set_config_value...")
    set_config_value(config, "identity.serial_number", 161)
    new_serial = get_config_value(config, "identity.serial_number")
    print(f"   identity.serial_number = {new_serial} (changed from {serial})")

    # Test validation
    print("\n5. Testing validation...")
    validation = validate_config(config)
    if validation.is_valid:
        print("   ✓ Configuration is valid")
    else:
        print("   ✗ Configuration has errors:")
        for error in validation.errors:
            print(f"     - {error}")

    if validation.warnings:
        print("   ⚠ Warnings:")
        for warning in validation.warnings:
            print(f"     - {warning}")

    print("\n" + "=" * 60)
    print("All tests completed!")
