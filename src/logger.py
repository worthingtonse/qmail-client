"""
logger.py - Logging Module for QMail Client Core

This module provides thread-safe logging with buffered writes, gzip compression,
and numbered archive rotation. Designed for easy translation to C (logger.c/logger.h).

Author: Claude Opus 4.5
Phase: I
Version: 1.0.0

Log Format:
    [2025-12-11 16:30:45.123] INFO  | NetworkMod   | Message here
    [2025-12-11 16:30:45.456] ERROR | CryptoMod    | Failed | REASON: details

C Notes:
    - LoggerHandle maps to a C struct with file handle, buffer, and mutex
    - Byte-counted buffer maps to fixed char buffer in C
    - threading.Lock maps to pthread_mutex_t or CRITICAL_SECTION
    - gzip compression maps to zlib in C

Functions (from plan.txt section 4.13):
    init_logger(log_path)                -> logger_handle
    log_debug(handle, context, message)  -> void
    log_info(handle, context, message)   -> void
    log_warning(handle, context, message)-> void
    log_error(handle, context, message, reason=None) -> void
    flush_log(handle)                    -> void
    close_logger(handle)                 -> void
"""

import os
import gzip
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Optional, TextIO


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_ARCHIVES = 5
DEFAULT_BUFFER_SIZE = 8192  # 8 KB buffer (maps to fixed char[8192] in C)
CONTEXT_WIDTH = 12  # Characters for context/module name column
LOG_FILE_EXTENSION = ".mlog"


# ============================================================================
# LOG LEVELS (C-style enum)
# ============================================================================

class LogLevel(IntEnum):
    """
    Log level codes.
    C: typedef enum { LOG_DEBUG = 0, LOG_INFO = 1, ... } LogLevel;
    """
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3


# Map level to 5-char padded string for consistent column alignment
LEVEL_NAMES = {
    LogLevel.DEBUG: "DEBUG",
    LogLevel.INFO: "INFO ",
    LogLevel.WARNING: "WARN ",
    LogLevel.ERROR: "ERROR",
}


# ============================================================================
# LOGGER HANDLE (Opaque handle for C conversion)
# ============================================================================

@dataclass
class LoggerHandle:
    """
    Opaque handle for logger state.

    C struct equivalent:
        typedef struct LoggerHandle {
            FILE* file;
            char* path;
            char buffer[8192];
            size_t buffer_used;
            size_t max_file_size;
            int max_archives;
            pthread_mutex_t mutex;
            LogLevel min_level;
        } LoggerHandle;
    """
    path: str
    file: Optional[TextIO] = None
    buffer: bytearray = field(default_factory=lambda: bytearray())
    buffer_size: int = DEFAULT_BUFFER_SIZE
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_archives: int = DEFAULT_MAX_ARCHIVES
    mutex: threading.Lock = field(default_factory=threading.Lock)
    min_level: LogLevel = LogLevel.DEBUG


# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

def _format_timestamp() -> str:
    """
    Generate timestamp string in format: YYYY-MM-DD HH:MM:SS.mmm

    Returns:
        Formatted timestamp string

    C signature: static void _format_timestamp(char* buffer, size_t buffer_size);
    """
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"


def _format_context(context: str) -> str:
    """
    Pad or truncate context to exactly CONTEXT_WIDTH characters.

    Args:
        context: Raw context string

    Returns:
        String of exactly 12 characters, left-justified, space-padded

    C signature: static void _format_context(const char* input, char* output);
    """
    if len(context) > CONTEXT_WIDTH:
        return context[:CONTEXT_WIDTH]
    return context.ljust(CONTEXT_WIDTH)


def _write_log_entry(
    handle: LoggerHandle,
    level: LogLevel,
    context: str,
    message: str,
    reason: Optional[str] = None
) -> None:
    """
    Internal function to format and write a log entry.

    Thread-safe: acquires handle.mutex before any operations.

    Log Format:
        [YYYY-MM-DD HH:MM:SS.mmm] LEVEL | Context      | Message
        [YYYY-MM-DD HH:MM:SS.mmm] ERROR | Context      | Message | REASON: details

    C signature: static void _write_log_entry(LoggerHandle* handle, LogLevel level,
                                               const char* context, const char* message,
                                               const char* reason);
    """
    if handle is None or handle.file is None:
        return

    # Check if level meets minimum threshold
    if level < handle.min_level:
        return

    # Format the log entry
    timestamp = _format_timestamp()
    level_str = LEVEL_NAMES.get(level, "?????")
    context_str = _format_context(context)

    if reason and level == LogLevel.ERROR:
        entry = f"[{timestamp}] {level_str} | {context_str} | {message} | REASON: {reason}\n"
    else:
        entry = f"[{timestamp}] {level_str} | {context_str} | {message}\n"

    entry_bytes = entry.encode('utf-8')

    with handle.mutex:
        # Add to buffer
        handle.buffer.extend(entry_bytes)

        # Auto-flush on ERROR (critical errors captured immediately)
        if level == LogLevel.ERROR:
            _flush_buffer(handle)
        # Flush if buffer is full
        elif len(handle.buffer) >= handle.buffer_size:
            _flush_buffer(handle)


def _flush_buffer(handle: LoggerHandle) -> None:
    """
    Internal function to write buffer to file.
    MUST be called with handle.mutex held.

    C signature: static void _flush_buffer(LoggerHandle* handle);
    """
    if handle.file is None or len(handle.buffer) == 0:
        return

    try:
        handle.file.write(handle.buffer.decode('utf-8'))
        handle.file.flush()
        handle.buffer.clear()

        # Check if rotation is needed after write
        _check_rotation(handle)
    except IOError as e:
        # Print to stderr on error, but don't crash
        import sys
        print(f"Logger write error: {e}", file=sys.stderr)


def _check_rotation(handle: LoggerHandle) -> None:
    """
    Check if log file needs rotation and perform if necessary.
    MUST be called with handle.mutex held.

    C signature: static void _check_rotation(LoggerHandle* handle);
    """
    try:
        current_size = os.path.getsize(handle.path)
        if current_size >= handle.max_file_size:
            _rotate_logs(handle)
    except OSError:
        pass  # File may not exist yet, which is fine


def _rotate_logs(handle: LoggerHandle) -> None:
    """
    Perform log rotation with gzip compression.
    MUST be called with handle.mutex held.

    Rotation scheme: mail.mlog -> mail.mlog.1.gz -> mail.mlog.2.gz -> ...

    C signature: static void _rotate_logs(LoggerHandle* handle);
    """
    import sys

    try:
        # Close current file
        if handle.file:
            handle.file.close()
            handle.file = None

        # Shift existing archives (N.gz -> N+1.gz), starting from highest
        for i in range(handle.max_archives - 1, 0, -1):
            old_path = f"{handle.path}.{i}.gz"
            new_path = f"{handle.path}.{i + 1}.gz"
            if os.path.exists(old_path):
                if os.path.exists(new_path):
                    os.remove(new_path)
                os.rename(old_path, new_path)

        # Delete oldest archive if it exceeds max_archives
        oldest_archive = f"{handle.path}.{handle.max_archives}.gz"
        if os.path.exists(oldest_archive):
            os.remove(oldest_archive)

        # Compress current log to .1.gz
        archive_path = f"{handle.path}.1.gz"
        if os.path.exists(handle.path):
            _compress_file(handle.path, archive_path)
            os.remove(handle.path)

        # Reopen log file for appending
        handle.file = open(handle.path, 'a', encoding='utf-8')

    except (IOError, OSError) as e:
        print(f"Logger rotation error: {e}", file=sys.stderr)
        # Try to reopen the file anyway
        try:
            handle.file = open(handle.path, 'a', encoding='utf-8')
        except IOError:
            pass


def _compress_file(source_path: str, dest_path: str) -> bool:
    """
    Compress a file using gzip.

    Args:
        source_path: Path to uncompressed file
        dest_path: Path for compressed output (.gz)

    Returns:
        True if successful, False on error

    C signature: static bool _compress_file(const char* source, const char* dest);
    """
    try:
        with open(source_path, 'rb') as f_in:
            with gzip.open(dest_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except (IOError, OSError):
        return False


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def init_logger(
    log_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
    min_level: LogLevel = LogLevel.DEBUG
) -> Optional[LoggerHandle]:
    """
    Initialize logger and return handle.

    Creates the log file if it doesn't exist and initializes the buffered
    writer with thread-safe mutex protection.

    Args:
        log_path: Path to the log file (e.g., "Data/mail.mlog")
        max_file_size: Maximum file size in bytes before rotation (default 10MB)
        max_archives: Number of compressed archives to keep (default 5)
        buffer_size: Size of write buffer in bytes (default 8KB)
        min_level: Minimum log level to record (default DEBUG)

    Returns:
        LoggerHandle if successful, None on error

    C signature:
        LoggerHandle* init_logger(const char* log_path, size_t max_file_size,
                                   int max_archives, size_t buffer_size, LogLevel min_level);

    Example:
        handle = init_logger("Data/mail.mlog")
        if handle is None:
            print("Failed to initialize logger")
            sys.exit(1)
    """
    import sys

    try:
        # Ensure parent directory exists
        parent_dir = os.path.dirname(log_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)

        # Open file in append mode
        file_handle = open(log_path, 'a', encoding='utf-8')

        # Create handle
        handle = LoggerHandle(
            path=log_path,
            file=file_handle,
            buffer=bytearray(),
            buffer_size=buffer_size,
            max_file_size=max_file_size,
            max_archives=max_archives,
            min_level=min_level
        )

        # Write session start marker
        timestamp = _format_timestamp()
        session_marker = f"=== Logger initialized: {timestamp} ===\n"
        file_handle.write(session_marker)
        file_handle.flush()

        return handle

    except (IOError, OSError) as e:
        print(f"Failed to initialize logger: {e}", file=sys.stderr)
        return None


def log_debug(handle: LoggerHandle, context: str, message: str) -> None:
    """
    Log a debug-level message.

    Args:
        handle: Logger handle from init_logger()
        context: Module/source identifier (max 12 chars, e.g., "NetworkMod")
        message: The log message

    C signature: void log_debug(LoggerHandle* handle, const char* context, const char* message);
    """
    _write_log_entry(handle, LogLevel.DEBUG, context, message)


def log_info(handle: LoggerHandle, context: str, message: str) -> None:
    """
    Log an info-level message.

    Args:
        handle: Logger handle from init_logger()
        context: Module/source identifier (max 12 chars)
        message: The log message

    C signature: void log_info(LoggerHandle* handle, const char* context, const char* message);
    """
    _write_log_entry(handle, LogLevel.INFO, context, message)


def log_warning(handle: LoggerHandle, context: str, message: str) -> None:
    """
    Log a warning-level message.

    Args:
        handle: Logger handle from init_logger()
        context: Module/source identifier (max 12 chars)
        message: The log message

    C signature: void log_warning(LoggerHandle* handle, const char* context, const char* message);
    """
    _write_log_entry(handle, LogLevel.WARNING, context, message)


def log_error(
    handle: LoggerHandle,
    context: str,
    message: str,
    reason: Optional[str] = None
) -> None:
    """
    Log an error-level message with optional REASON field.

    ERROR logs are auto-flushed immediately to ensure critical errors
    are captured even if the application crashes.

    Args:
        handle: Logger handle from init_logger()
        context: Module/source identifier (max 12 chars)
        message: The error message
        reason: Optional diagnostic reason (appended as "| REASON: {reason}")

    Output format:
        Without reason: [timestamp] ERROR | Context      | Message here
        With reason:    [timestamp] ERROR | Context      | Message | REASON: details

    C signature: void log_error(LoggerHandle* handle, const char* context,
                                 const char* message, const char* reason);

    Example:
        log_error(handle, "CryptoMod", "Decryption failed", "key mismatch")
        # Output: [2025-12-11 16:30:45.123] ERROR | CryptoMod    | Decryption failed | REASON: key mismatch
    """
    _write_log_entry(handle, LogLevel.ERROR, context, message, reason)


def flush_log(handle: LoggerHandle) -> None:
    """
    Flush buffered log entries to disk.

    Thread-safe: acquires mutex before writing.

    Args:
        handle: Logger handle from init_logger()

    C signature: void flush_log(LoggerHandle* handle);
    """
    if handle is None:
        return

    with handle.mutex:
        _flush_buffer(handle)


def close_logger(handle: LoggerHandle) -> None:
    """
    Close logger and release all resources.

    Flushes any remaining buffered data, writes a session end marker,
    closes the file handle, and releases the mutex.

    Args:
        handle: Logger handle from init_logger()

    C signature: void close_logger(LoggerHandle* handle);
    """
    if handle is None:
        return

    with handle.mutex:
        # Flush remaining buffer
        _flush_buffer(handle)

        # Write session end marker
        if handle.file:
            timestamp = _format_timestamp()
            session_marker = f"=== Logger closed: {timestamp} ===\n"
            try:
                handle.file.write(session_marker)
                handle.file.flush()
                handle.file.close()
            except IOError:
                pass

        handle.file = None


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the logger module with realistic QMail scenarios.
    """
    print("=" * 60)
    print("logger.py - Test Suite")
    print("=" * 60)

    # Determine log path
    # When running from src/, go up one level to find Data/
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir) == 'src':
        data_dir = os.path.join(os.path.dirname(script_dir), 'Data')
    else:
        data_dir = os.path.join(script_dir, 'Data')

    log_path = os.path.join(data_dir, 'mail.mlog')
    print(f"\nLog file: {log_path}")

    # Test 1: Initialization
    print("\n1. Testing init_logger()...")
    handle = init_logger(log_path)
    assert handle is not None, "Logger initialization failed"
    print(f"   SUCCESS: Logger initialized")

    # Test 2: Various log levels
    print("\n2. Testing log levels...")
    log_info(handle, "MainModule", "QMail Client starting up")
    log_debug(handle, "ConfigMod", "Loading configuration from qmail.toml")
    log_warning(handle, "NetworkMod", "Server s7 response slow - latency: 156ms")
    log_error(handle, "CryptoMod", "Decryption failed", "key mismatch on server 3")
    print("   SUCCESS: All log levels work")

    # Test 3: Context truncation/padding
    print("\n3. Testing context formatting...")
    log_info(handle, "Short", "Short context test")
    log_info(handle, "VeryLongContextName", "Long context truncation test")
    log_info(handle, "ExactlyTwelv", "Exact 12 char context test")
    print("   SUCCESS: Context formatting works")

    # Test 4: Error without reason
    print("\n4. Testing error without reason...")
    log_error(handle, "TestMod", "Simple error without reason")
    print("   SUCCESS: Error without reason works")

    # Test 5: Manual flush
    print("\n5. Testing flush_log()...")
    log_info(handle, "FlushTest", "This message will be flushed manually")
    flush_log(handle)
    print("   SUCCESS: Manual flush works")

    # Test 6: Multiple rapid writes (buffer test)
    print("\n6. Testing buffered writes...")
    for i in range(10):
        log_debug(handle, "BufferTest", f"Buffered message {i + 1}")
    flush_log(handle)
    print("   SUCCESS: Buffered writes work")

    # Cleanup
    print("\n7. Testing close_logger()...")
    close_logger(handle)
    print("   SUCCESS: Logger closed")

    # Verify log file exists and has content
    print("\n8. Verifying log file...")
    assert os.path.exists(log_path), "Log file not created"
    with open(log_path, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "Logger initialized" in content, "Session start marker missing"
        assert "Logger closed" in content, "Session end marker missing"
        assert "MainModule" in content, "Log entry missing"
        assert "REASON: key mismatch" in content, "REASON field missing"
    print(f"   SUCCESS: Log file verified ({len(content)} bytes)")

    print("\n" + "=" * 60)
    print("All logger tests passed!")
    print("=" * 60)

    # Show sample of log content
    print("\nSample log entries:")
    print("-" * 60)
    lines = content.strip().split('\n')
    for line in lines[:10]:
        print(line)
    if len(lines) > 10:
        print(f"... ({len(lines) - 10} more lines)")
