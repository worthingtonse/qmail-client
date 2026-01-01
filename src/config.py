"""
opus45_config.py - Configuration Management for QMail Client Core

This module handles loading, saving, and validating configuration from qmail.toml.
Designed for easy translation to C (config.c/config.h) in Phase III.

Author: Claude Opus 4.5 (opus45)
Phase: I

Functions:
    load_config(config_path)             -> QMailConfig
    save_config(config, path)            -> bool
    get_config_value(config, key)        -> value
    set_config_value(config, key, val)   -> None
    validate_config(config)              -> ValidationResult
"""
from __future__ import annotations
import os
import sys
from typing import Any, Optional ,List, TYPE_CHECKING

if TYPE_CHECKING:
    from qmail_types import QMailConfig, ServerConfig, ValidationResult, IdentityConfig

# Python 3.11+ has tomllib built-in, earlier versions need tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# For writing TOML (tomllib/tomli are read-only)
try:
    import tomli_w
except ImportError:
    tomli_w = None

# Import from qmail_types module (renamed from 'types' to avoid Python built-in conflict)
try:
    from .qmail_types import (
        QMailConfig,
        PathsConfig,
        IdentityConfig,
        EncryptionConfig,
        BeaconConfig,
        RaidConfig,
        NetworkConfig,
        ThreadingConfig,
        ApiConfig,
        LoggingConfig,
        SyncConfig,
        ServerConfig,
        ValidationResult,
    )
except ImportError:
    # Fallback for running standalone - import qmail_types.py directly
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "qmail_types",
        os.path.join(os.path.dirname(__file__), "qmail_types.py")
    )
    _types_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_types_module)

    QMailConfig = _types_module.QMailConfig
    PathsConfig = _types_module.PathsConfig
    IdentityConfig = _types_module.IdentityConfig
    EncryptionConfig = _types_module.EncryptionConfig
    BeaconConfig = _types_module.BeaconConfig
    RaidConfig = _types_module.RaidConfig
    NetworkConfig = _types_module.NetworkConfig
    ThreadingConfig = _types_module.ThreadingConfig
    ApiConfig = _types_module.ApiConfig
    LoggingConfig = _types_module.LoggingConfig
    SyncConfig = _types_module.SyncConfig
    ServerConfig = _types_module.ServerConfig
    ValidationResult = _types_module.ValidationResult


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_CONFIG_FILENAME = "config/qmail.toml"
CONFIG_VERSION = "1.0.0"

# Required fields that must be present in config
REQUIRED_SECTIONS = ["paths", "identity", "encryption", "beacon", "raid",
                     "network", "threading", "api", "logging"]

# Minimum server counts
MIN_QMAIL_SERVERS = 5
MIN_RAIDA_SERVERS = 25


# ============================================================================
# LOAD CONFIG
# ============================================================================

def load_config(config_path: str) -> Optional[QMailConfig]:
    """
    Load configuration from a TOML file.

    Args:
        config_path: Path to the qmail.toml configuration file

    Returns:
        QMailConfig object if successful, None if failed

    C signature: QMailConfig* load_config(const char* config_path);
    """
    if tomllib is None:
        print("Error: TOML parsing library not available. Install tomli or use Python 3.11+")
        return None

    # Check file exists
    if not os.path.isfile(config_path):
        print(f"Error: Config file not found: {config_path}")
        return None

    # Read and parse TOML
    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        print(f"Error: Invalid TOML syntax in {config_path}: {e}")
        return None
    except IOError as e:
        print(f"Error: Could not read {config_path}: {e}")
        return None

    # Build QMailConfig from parsed data
    config = QMailConfig()

    # Parse paths section
    if "paths" in data:
        p = data["paths"]
        config.paths = PathsConfig(
            db_path=p.get("db_path", "Data/qmail.db"),
            log_path=p.get("log_path", "Data/mail.mlog"),
            locker_files_path=p.get("locker_files_path", "Data/Lockers"),
            attachments_path=p.get("attachments_path", "Data/Attachments"),
        )

    # Parse identity section
    if "identity" in data:
        i = data["identity"]
        config.identity = IdentityConfig(
            coin_type=i.get("coin_type", 6),
            denomination=i.get("denomination", 1),
            serial_number=i.get("serial_number", 0),
            device_id=i.get("device_id", 1),
            authenticity_number=i.get("authenticity_number"),
        )

    # Parse encryption section
    if "encryption" in data:
        e = data["encryption"]
        config.encryption = EncryptionConfig(
            enabled=e.get("enabled", True),
            mode=e.get("mode", 6),  # Default to Mode A (6) - more secure than Mode B (1)
        )

    # Parse beacon section
    if "beacon" in data:
        b = data["beacon"]
        config.beacon = BeaconConfig(
            url=b.get("url", "tcp://168.220.219.199:50014"),
            server_index=b.get("server_index", 14),
            interval_sec=b.get("interval_sec", 600),
            timeout_sec=b.get("timeout_sec", 600),
        )

    # Parse raid section
    if "raid" in data:
        r = data["raid"]
        config.raid = RaidConfig(
            data_stripe_count=r.get("data_stripe_count", 4),
            parity_stripe_count=r.get("parity_stripe_count", 1),
        )

    # Parse network section
    if "network" in data:
        n = data["network"]
        config.network = NetworkConfig(
            connect_timeout_ms=n.get("connection_timeout_ms", 5000),
            read_timeout_ms=n.get("read_timeout_ms", 30000),
            max_retries=n.get("max_retries", 3),
        )

    # Parse threading section
    if "threading" in data:
        t = data["threading"]
        config.threading = ThreadingConfig(
            pool_size=t.get("pool_size", 5),
        )

    # Parse api section
    if "api" in data:
        a = data["api"]
        config.api = ApiConfig(
            enabled=a.get("enabled", True),
            host=a.get("host", "127.0.0.1"),
            port=a.get("port"),  # None if not specified (CLI arg)
        )

    # Parse logging section
    if "logging" in data:
        lg = data["logging"]
        config.logging = LoggingConfig(
            level=lg.get("level", "info"),
            max_size_mb=lg.get("max_size_mb", 10),
            backup_count=lg.get("backup_count", 3),
        )

    # Parse sync section
    if "sync" in data:
        s = data["sync"]
        config.sync = SyncConfig(
            users_url=s.get("users_url", "https://raida11.cloudcoin.global/service/users"),
            servers_url=s.get("servers_url", "https://raida11.cloudcoin.global/service/qmail_servers"),
            timeout_sec=s.get("timeout_sec", 30),
        )

    # Parse qmail_servers array
    if "qmail_servers" in data:
        for srv in data["qmail_servers"]:
            config.qmail_servers.append(ServerConfig(
                address=srv.get("address", ""),
                port=srv.get("port", 0),
                index=srv.get("index"),
                server_type=srv.get("server_type"),
                description=srv.get("description"),
            ))

    # Parse raida_servers array
    if "raida_servers" in data:
        for srv in data["raida_servers"]:
            config.raida_servers.append(ServerConfig(
                address=srv.get("address", ""),
                port=srv.get("port", 0),
                index=srv.get("index"),
                server_type=srv.get("server_type"),
                description=srv.get("description"),
            ))

    return config


# ============================================================================
# SAVE CONFIG
# ============================================================================

def save_config(config: QMailConfig, path: str) -> bool:
    """
    Save configuration to a TOML file.

    Args:
        config: QMailConfig object to save
        path: Path to write the configuration file

    Returns:
        True if successful, False if failed

    C signature: bool save_config(const QMailConfig* config, const char* path);
    """
    if tomli_w is None:
        print("Error: TOML writing library not available. Install tomli-w")
        return False

    # Build TOML-compatible dictionary
    data = _config_to_dict(config)

    try:
        with open(path, "wb") as f:
            tomli_w.dump(data, f)
        return True
    except IOError as e:
        print(f"Error: Could not write to {path}: {e}")
        return False


def _config_to_dict(config: QMailConfig) -> dict:
    """Convert QMailConfig to a dictionary suitable for TOML serialization."""
    return {
        "paths": {
            "db_path": config.paths.db_path,
            "log_path": config.paths.log_path,
            "locker_files_path": config.paths.locker_files_path,
            "attachments_path": config.paths.attachments_path,
        },
        "identity": {
            "coin_type": config.identity.coin_type,
            "denomination": config.identity.denomination,
            "serial_number": config.identity.serial_number,
            "device_id": config.identity.device_id,
        },
        "encryption": {
            "enabled": config.encryption.enabled,
            "mode": config.encryption.mode,
        },
        "beacon": {
            "url": config.beacon.url,
            "server_index": config.beacon.server_index,
            "interval_sec": config.beacon.interval_sec,
            "timeout_sec": config.beacon.timeout_sec,
        },
        "raid": {
            "data_stripe_count": config.raid.data_stripe_count,
            "parity_stripe_count": config.raid.parity_stripe_count,
        },
        "network": {
            "connection_timeout_ms": config.network.connect_timeout_ms,
            "read_timeout_ms": config.network.read_timeout_ms,
            "max_retries": config.network.max_retries,
        },
        "threading": {
            "pool_size": config.threading.pool_size,
        },
        "api": {
            "enabled": config.api.enabled,
            "host": config.api.host,
        },
        "logging": {
            "level": config.logging.level,
            "max_size_mb": config.logging.max_size_mb,
            "backup_count": config.logging.backup_count,
        },
        "sync": {
            "users_url": config.sync.users_url,
            "servers_url": config.sync.servers_url,
            "timeout_sec": config.sync.timeout_sec,
        },
        "qmail_servers": [
            {"address": s.address, "port": s.port}
            for s in config.qmail_servers
        ],
        "raida_servers": [
            {"index": s.index, "address": s.address, "port": s.port}
            for s in config.raida_servers
        ],
    }


# ============================================================================
# GET CONFIG VALUE
# ============================================================================

def get_config_value(config: QMailConfig, key: str) -> Any:
    """
    Get a configuration value by dot-notation key.

    Args:
        config: QMailConfig object
        key: Dot-notation key (e.g., "paths.db_path", "beacon.url")

    Returns:
        The configuration value, or None if not found

    Examples:
        get_config_value(config, "paths.db_path")      -> "Data/qmail.db"
        get_config_value(config, "beacon.interval_sec") -> 600
        get_config_value(config, "identity.serial_number") -> 12345

    C signature: void* get_config_value(const QMailConfig* config, const char* key);
    """
    parts = key.split(".")
    current = config

    for part in parts:
        if hasattr(current, part):
            current = getattr(current, part)
        else:
            return None

    return current


# ============================================================================
# SET CONFIG VALUE
# ============================================================================

def set_config_value(config: QMailConfig, key: str, value: Any) -> None:
    """
    Set a configuration value by dot-notation key.

    Args:
        config: QMailConfig object to modify
        key: Dot-notation key (e.g., "paths.db_path", "beacon.url")
        value: New value to set

    Examples:
        set_config_value(config, "identity.serial_number", 12345)
        set_config_value(config, "logging.level", "debug")

    C signature: void set_config_value(QMailConfig* config, const char* key, void* value);
    """
    parts = key.split(".")

    if len(parts) < 1:
        return

    # Navigate to the parent object
    current = config
    for part in parts[:-1]:
        if hasattr(current, part):
            current = getattr(current, part)
        else:
            return  # Invalid path, do nothing

    # Set the final attribute if it exists
    final_key = parts[-1]
    if hasattr(current, final_key):
        setattr(current, final_key, value)


# ============================================================================
# VALIDATE CONFIG
# ============================================================================

def validate_config(config: QMailConfig) -> ValidationResult:
    """
    Validate a configuration object for completeness and correctness.

    Args:
        config: QMailConfig object to validate

    Returns:
        ValidationResult with valid=True/False and lists of errors/warnings

    C signature: ValidationResult validate_config(const QMailConfig* config);
    """
    result = ValidationResult(is_valid=True)

    # --- Paths validation ---
    if not config.paths.db_path:
        result.add_error("paths.db_path is required")
    if not config.paths.log_path:
        result.add_error("paths.log_path is required")

    # --- Identity validation ---
    if config.identity.coin_type != 6:
        result.add_warning(f"identity.coin_type is {config.identity.coin_type}, expected 6 (CloudCoin)")

    if config.identity.denomination < 0 or config.identity.denomination > 250:
        result.add_error(f"identity.denomination must be 1-250, got {config.identity.denomination}")

    if config.identity.serial_number == 0:
        result.add_warning("identity.serial_number is 0 - user must configure their mailbox ID")

    if config.identity.serial_number < 0 or config.identity.serial_number > 0xFFFFFFFF:
        result.add_error("identity.serial_number must be a 4-byte unsigned integer (0-4294967295)")

    if config.identity.device_id < 0 or config.identity.device_id > 0xFFFF:
        result.add_error("identity.device_id must be a 16-bit unsigned integer (0-65535)")

    # --- Encryption validation ---
    if config.encryption.mode not in (1, 6):
        result.add_error(f"encryption.mode must be 1 (Mode B) or 6 (Mode A), got {config.encryption.mode}")

    # --- Beacon validation ---
    if not config.beacon.url:
        result.add_error("beacon.url is required")
    elif not config.beacon.url.startswith("tcp://"):
        result.add_warning("beacon.url should start with 'tcp://'")

    if config.beacon.interval_sec < 60:
        result.add_warning("beacon.interval_sec is very low (< 60 seconds)")

    if config.beacon.server_index < 0 or config.beacon.server_index > 24:
        result.add_error("beacon.server_index must be 0-24")

    # --- RAID validation ---
    if config.raid.data_stripe_count < 1:
        result.add_error("raid.data_stripe_count must be at least 1")

    if config.raid.parity_stripe_count < 0:
        result.add_error("raid.parity_stripe_count cannot be negative")

    total_stripes = config.raid.data_stripe_count + config.raid.parity_stripe_count
    if total_stripes != 5:
        result.add_warning(f"Total stripe count is {total_stripes}, expected 5 (4 data + 1 parity)")

    # --- Network validation ---
    if config.network.connect_timeout_ms < 1000:
        result.add_warning("network.connect_timeout_ms is very low (< 1000ms)")

    if config.network.max_retries < 0:
        result.add_error("network.max_retries cannot be negative")

    # --- Threading validation ---
    if config.threading.pool_size < MIN_QMAIL_SERVERS:
        result.add_error(f"threading.pool_size must be at least {MIN_QMAIL_SERVERS}")

    # --- API validation ---
    if config.api.enabled:
        if not config.api.host:
            result.add_error("api.host is required when api.enabled is true")
        # Note: port is intentionally not validated here (CLI argument)

    # --- Logging validation ---
    valid_levels = ("debug", "info", "warning", "error")
    if config.logging.level.lower() not in valid_levels:
        result.add_error(f"logging.level must be one of {valid_levels}")

    if config.logging.max_size_mb < 1:
        result.add_error("logging.max_size_mb must be at least 1")

    if config.logging.backup_count < 0:
        result.add_error("logging.backup_count cannot be negative")

    # --- Server lists validation ---
    if len(config.qmail_servers) < MIN_QMAIL_SERVERS:
        result.add_error(f"Need at least {MIN_QMAIL_SERVERS} QMail servers, got {len(config.qmail_servers)}")

    if len(config.raida_servers) < MIN_RAIDA_SERVERS:
        result.add_warning(f"Expected {MIN_RAIDA_SERVERS} RAIDA servers, got {len(config.raida_servers)}")

    # Validate each server entry
    for i, srv in enumerate(config.qmail_servers):
        if not srv.address:
            result.add_error(f"qmail_servers[{i}].address is empty")
        if srv.port < 1 or srv.port > 65535:
            result.add_error(f"qmail_servers[{i}].port must be 1-65535")

    for i, srv in enumerate(config.raida_servers):
        if not srv.address:
            result.add_error(f"raida_servers[{i}].address is empty")
        if srv.port < 1 or srv.port > 65535:
            result.add_error(f"raida_servers[{i}].port must be 1-65535")

    return result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_default_config_path() -> str:
    """
    Get the default configuration file path.
    Looks in current directory, then parent directory.

    Returns:
        Path to qmail.toml if found, or default filename if not found
    """
    # Check current directory
    if os.path.isfile(DEFAULT_CONFIG_FILENAME):
        return DEFAULT_CONFIG_FILENAME

    # Check parent directory (for when running from src/)
    parent_path = os.path.join("..", DEFAULT_CONFIG_FILENAME)
    if os.path.isfile(parent_path):
        return parent_path

    # Return default name (caller will handle file-not-found)
    return DEFAULT_CONFIG_FILENAME


def get_raida_server_config(raida_index: int, servers: List[ServerConfig]) -> Optional[ServerConfig]:
    """
    Finds a RAIDA server configuration by its index (0-24).
    Required for beacon-only notifications in Phase I.
    """
    for srv in servers:
        # Some configs might store index as a string or int; we check both
        if srv.index == raida_index or str(srv.index) == str(raida_index):
            return srv
    return None


def create_default_config_file(path: str = DEFAULT_CONFIG_FILENAME) -> bool:
    """
    Create a default qmail.toml configuration file with all required values.

    Args:
        path: Where to create the file (default: qmail.toml)

    Returns:
        True if successful, False otherwise

    C signature: bool create_default_config_file(const char* path);
    """
    # Create default config object
    config = QMailConfig()

    # Add default QMail servers (5 servers for Phase I RAID-4+1)
    config.qmail_servers = [
        ServerConfig(address="47.229.9.94", port=50001),
        ServerConfig(address="124.187.106.233", port=50009),
        ServerConfig(address="113.30.247.109", port=50013),
        ServerConfig(address="168.220.219.199", port=50014),
        ServerConfig(address="125.236.210.184", port=50021),
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
        (14, "168.220.219.199", 50014),  # Beacon server
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
        ServerConfig(address=addr, port=port, index=idx)
        for idx, addr, port in raida_list
    ]

    # Save to file
    return save_config(config, path)


def print_config_summary(config: QMailConfig) -> None:
    """Print a human-readable summary of the configuration."""
    print("=" * 60)
    print("QMail Client Configuration Summary")
    print("=" * 60)
    print(f"Database:     {config.paths.db_path}")
    print(f"Log file:     {config.paths.log_path}")
    print(f"Identity:     {config.identity.coin_type:04X}."
          f"{config.identity.denomination}."
          f"{config.identity.serial_number}")
    print(f"Device ID:    {config.identity.device_id}")
    print(f"Encryption:   {'Enabled' if config.encryption.enabled else 'Disabled'} "
          f"(Mode {'A' if config.encryption.mode == 6 else 'B'})")
    print(f"Beacon:       {config.beacon.url}")
    print(f"RAID:         {config.raid.data_stripe_count}+{config.raid.parity_stripe_count} stripes")
    print(f"Thread pool:  {config.threading.pool_size} workers")
    print(f"API:          {'Enabled' if config.api.enabled else 'Disabled'} "
          f"on {config.api.host}")
    print(f"Log level:    {config.logging.level}")
    print(f"Sync URLs:    users={config.sync.users_url[:40]}...")
    print(f"              servers={config.sync.servers_url[:40]}...")
    print(f"QMail servers: {len(config.qmail_servers)}")
    print(f"RAIDA servers: {len(config.raida_servers)}")
    print("=" * 60)


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    # Test the config module
    config_path = get_default_config_path()
    print(f"Loading config from: {config_path}")

    config = load_config(config_path)
    if config is None:
        print("Failed to load configuration")
        sys.exit(1)

    print_config_summary(config)

    # Validate
    result = validate_config(config)
    print(f"\nValidation: {'PASSED' if result.is_valid else 'FAILED'}")

    if result.errors:
        print("\nErrors:")
        for err in result.errors:
            print(f"  - {err}")

    if result.warnings:
        print("\nWarnings:")
        for warn in result.warnings:
            print(f"  - {warn}")

    # Test get/set
    print(f"\nTest get_config_value('beacon.url'): {get_config_value(config, 'beacon.url')}")
    print(f"Test get_config_value('identity.serial_number'): {get_config_value(config, 'identity.serial_number')}")

    set_config_value(config, "identity.serial_number", 999)
    print(f"After set_config_value('identity.serial_number', 999): {get_config_value(config, 'identity.serial_number')}")


    
