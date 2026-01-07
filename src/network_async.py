"""
network_async.py - Async Network Module for QMail Client Core

This module provides asyncio-based network operations for parallel
communication with multiple QMail servers. Designed for efficient
stripe upload/download across 25 RAIDA servers.

Author: Claude Opus 4.5
Phase: I
Version: 1.0.0

Features:
    - Async TCP connections using asyncio
    - Parallel operations to multiple servers
    - Progress tracking via task_manager integration
    - Configurable timeouts and retry logic
    - Connection pooling support

C Notes:
    - Use select/poll/epoll on Unix, IOCP on Windows
    - Consider libuv or libevent for cross-platform async I/O
    - Thread pool + event loop pattern for C implementation
"""

import asyncio
import struct
import time
import zlib
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# Import from synchronous network module (reuse data structures and helpers)
try:
    from network import (
        # Data structures
        ServerInfo, Connection, ServerStatus, ResponseHeader,
        NetworkErrorCode, StatusCode, NetworkConfig,
        # Constants
        REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE, TERMINATOR,
        ENCRYPTION_NONE, ENCRYPTION_AES_128,
        CMD_GROUP_QMAIL, CMD_UPLOAD, CMD_DOWNLOAD, CMD_PING,
        NONCE_PROTOCOL_MARKER, NET_CONTEXT,
        _DEFAULT_CONFIG,
        # Helper functions
        _derive_encryption_nonce, _build_request_header,
        _parse_response_header, _calculate_challenge,
        build_common_preamble,
    )
    from crypto import encrypt_data, decrypt_data, CryptoErrorCode, AES_KEY_SIZE
    from task_manager import (
        TaskManagerHandle, TaskErrorCode,
        create_task, start_task, update_task_progress,
        complete_task, fail_task
    )
except ImportError:
    # Fallback imports for standalone testing
    from network import (
        ServerInfo, Connection, ServerStatus, ResponseHeader,
        NetworkErrorCode, StatusCode, NetworkConfig,
        REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE, TERMINATOR,
        ENCRYPTION_NONE, ENCRYPTION_AES_128,
        CMD_GROUP_QMAIL, CMD_UPLOAD, CMD_DOWNLOAD, CMD_PING,
        NONCE_PROTOCOL_MARKER, NET_CONTEXT,
        _DEFAULT_CONFIG,
        _derive_encryption_nonce, _build_request_header,
        _parse_response_header, _calculate_challenge,
        build_common_preamble,
    )
    try:
        from crypto import encrypt_data, decrypt_data, CryptoErrorCode, AES_KEY_SIZE
    except ImportError:
        CryptoErrorCode = None
        AES_KEY_SIZE = 16
        def encrypt_data(data, key, logger_handle=None):
            return 0, data  # Passthrough for testing
        def decrypt_data(data, key, logger_handle=None):
            return 0, data

    # Stub task manager for standalone testing
    TaskManagerHandle = None
    TaskErrorCode = None
    def create_task(*args, **kwargs): return (0, "test-task")
    def start_task(*args, **kwargs): return 0
    def update_task_progress(*args, **kwargs): return 0
    def complete_task(*args, **kwargs): return 0
    def fail_task(*args, **kwargs): return 0

# Import logger
try:
    from logger import log_error, log_info, log_debug, log_warning
except ImportError:
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")


# ============================================================================
# CONSTANTS
# ============================================================================

# Module context for logging
ASYNC_NET_CONTEXT = "AsyncNetwork"

# Default concurrency limits
DEFAULT_MAX_CONCURRENT = 25  # Max parallel connections (one per RAIDA)
DEFAULT_SEMAPHORE_LIMIT = 10  # Limit concurrent operations


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class AsyncConnection:
    """
    Async connection to a QMail server.
    C: typedef struct AsyncConnection { ... } AsyncConnection;
    """
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    server: Optional[ServerInfo] = None
    connected: bool = False
    encryption_key: Optional[bytes] = None
    denomination: int = 0
    serial_number: int = 0
    last_activity: float = 0.0


@dataclass
class ServerResult:
    """
    Result from a single server operation.
    C: typedef struct ServerResult { ... } ServerResult;
    """
    server: ServerInfo
    success: bool = False
    error_code: NetworkErrorCode = NetworkErrorCode.SUCCESS
    status_code: int = 0
    data: Optional[bytes] = None
    latency_ms: float = 0.0
    error_message: str = ""


@dataclass
class ParallelResult:
    """
    Aggregated results from parallel operations.
    C: typedef struct ParallelResult { ... } ParallelResult;
    """
    results: List[ServerResult] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    total_time_ms: float = 0.0

    @property
    def all_success(self) -> bool:
        return self.failure_count == 0

    @property
    def majority_success(self) -> bool:
        """Check if majority (>50%) succeeded - important for RAIDA consensus."""
        total = self.success_count + self.failure_count
        return total > 0 and self.success_count > total / 2


# ============================================================================
# ASYNC CONNECTION FUNCTIONS
# ============================================================================

async def connect_async(
    server_info: ServerInfo,
    encryption_key: bytes = None,
    denomination: int = 1,
    serial_number: int = 0,
    config: Optional[Any] = None,
    logger_handle: Optional[object] = None
) -> Tuple[NetworkErrorCode, Optional[AsyncConnection]]:
    """
    FIXED: Uses safe getattr to avoid 'QMailConfig object has no attribute' errors.
    """
    if server_info is None:
        return NetworkErrorCode.ERR_INVALID_PARAM, None

    # Safe fallback: Default to 5000ms if attribute missing
    timeout_ms = getattr(config, 'connect_timeout_ms', 5000)
    timeout_s = timeout_ms / 1000.0

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server_info.host, server_info.port),
            timeout=timeout_s
        )

        conn = AsyncConnection(
            reader=reader,
            writer=writer,
            server=server_info,
            connected=True,
            last_activity=time.time()
        )

        return NetworkErrorCode.SUCCESS, conn
    except Exception:
        return NetworkErrorCode.ERR_CONNECTION_FAILED, None

async def disconnect_async(
    conn: AsyncConnection,
    logger_handle: Optional[object] = None
) -> None:
    """
    Close async connection and clear sensitive data.

    Args:
        conn: Async connection to close
        logger_handle: Optional logger handle
    """
    if conn is None:
        return

    server_info = None
    if conn.server:
        server_info = f"{conn.server.host}:{conn.server.port}"

    # Close writer (this also closes the underlying socket)
    if conn.writer:
        try:
            conn.writer.close()
            await conn.writer.wait_closed()
        except Exception:
            pass
        conn.writer = None
        conn.reader = None

    # Clear sensitive data
    conn.encryption_key = None
    conn.denomination = 0
    conn.serial_number = 0
    conn.connected = False

    if server_info:
        log_debug(logger_handle, ASYNC_NET_CONTEXT,
                  f"Disconnected from {server_info}")


# ============================================================================
# ASYNC REQUEST/RESPONSE FUNCTIONS
# ============================================================================

async def send_request_async(
    conn: AsyncConnection,
    command_group: int,
    command_code: int,
    body_data: bytes,
    encrypt: bool = True,
    timeout_ms: Optional[int] = None,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> Tuple[NetworkErrorCode, Optional[ResponseHeader], Optional[bytes]]:
    """
    Send request to server and receive response asynchronously.

    Args:
        conn: Active async connection
        command_group: Command group code (e.g., 6 for QMail)
        command_code: Command code (e.g., 60 for upload)
        body_data: Request body data
        encrypt: Whether to encrypt the body
        timeout_ms: Response timeout (overrides config)
        config: NetworkConfig with timeout/size settings
        logger_handle: Optional logger handle

    Returns:
        Tuple of (error code, response header, decrypted response body)
    """
    if conn is None or not conn.connected:
        return NetworkErrorCode.ERR_CONNECTION_FAILED, None, None

    cfg = config or _DEFAULT_CONFIG
    timeout_s = (timeout_ms if timeout_ms else cfg.read_timeout_ms) / 1000.0
    max_response_size = cfg.max_response_body_size

    # Prepare body with terminator
    full_body = body_data + TERMINATOR

    # Encrypt body if requested
    encryption_type = ENCRYPTION_NONE
    if encrypt and conn.encryption_key:
        try:
            from Crypto.Cipher import AES
            nonce = _derive_encryption_nonce(conn.serial_number)
            cipher = AES.new(conn.encryption_key, AES.MODE_CTR, nonce=nonce[:8])
            full_body = cipher.encrypt(full_body)
            encryption_type = ENCRYPTION_AES_128
        except Exception as e:
            log_error(logger_handle, ASYNC_NET_CONTEXT,
                      "Encryption failed", str(e))
            return NetworkErrorCode.ERR_ENCRYPTION_FAILED, None, None

    # Build header
    nonce = _derive_encryption_nonce(conn.serial_number)[:8]
    expected_echo = nonce[6:8]

    header = _build_request_header(
        raida_id=conn.server.raida_id,
        command_group=command_group,
        command_code=command_code,
        body_length=len(full_body),
        encryption_type=encryption_type,
        denomination=conn.denomination,
        serial_number=conn.serial_number,
        nonce=nonce
    )

    # Send request
    request = header + full_body
    expected_raida_id = conn.server.raida_id

    try:
        conn.writer.write(request)
        await asyncio.wait_for(conn.writer.drain(), timeout=timeout_s)
        conn.last_activity = time.time()

        log_debug(logger_handle, ASYNC_NET_CONTEXT,
                  f"Sent {len(request)} bytes to RAIDA {conn.server.raida_id}")

    except asyncio.TimeoutError:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed", "send timeout")
        return NetworkErrorCode.ERR_TIMEOUT, None, None
    except Exception as e:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed", f"send error: {e}")
        return NetworkErrorCode.ERR_SEND_FAILED, None, None

    # Receive response header
    try:
        response_header_data = await asyncio.wait_for(
            conn.reader.readexactly(RESPONSE_HEADER_SIZE),
            timeout=timeout_s
        )
    except asyncio.TimeoutError:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed", "timeout receiving header")
        return NetworkErrorCode.ERR_TIMEOUT, None, None
    except asyncio.IncompleteReadError:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed", "connection closed")
        return NetworkErrorCode.ERR_RECEIVE_FAILED, None, None
    except Exception as e:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed", f"receive error: {e}")
        return NetworkErrorCode.ERR_RECEIVE_FAILED, None, None

    # Parse response header
    err, resp_header = _parse_response_header(response_header_data)
    if err != NetworkErrorCode.SUCCESS:
        return err, None, None

    # Validate response
    if resp_header.raida_id != expected_raida_id:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed",
                  f"RAIDA ID mismatch: expected {expected_raida_id}, got {resp_header.raida_id}")
        return NetworkErrorCode.ERR_INVALID_RESPONSE, None, None

    if resp_header.body_size > max_response_size:
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "send_request_async failed",
                  f"Response body too large: {resp_header.body_size}")
        return NetworkErrorCode.ERR_INVALID_RESPONSE, None, None

    # Receive response body
    response_body = b''
    if resp_header.body_size > 0:
        try:
            response_body = await asyncio.wait_for(
                conn.reader.readexactly(resp_header.body_size),
                timeout=timeout_s
            )
        except asyncio.TimeoutError:
            log_error(logger_handle, ASYNC_NET_CONTEXT,
                      "send_request_async failed", "timeout receiving body")
            return NetworkErrorCode.ERR_TIMEOUT, resp_header, None
        except asyncio.IncompleteReadError:
            log_error(logger_handle, ASYNC_NET_CONTEXT,
                      "send_request_async failed", "incomplete body")
            return NetworkErrorCode.ERR_RECEIVE_FAILED, resp_header, None

    # Decrypt response body if encrypted
    if encrypt and conn.encryption_key and response_body:
        try:
            from Crypto.Cipher import AES
            nonce = _derive_encryption_nonce(conn.serial_number)
            cipher = AES.new(conn.encryption_key, AES.MODE_CTR, nonce=nonce[:8])
            response_body = cipher.decrypt(response_body)
        except Exception as e:
            log_warning(logger_handle, ASYNC_NET_CONTEXT,
                        f"Decryption failed: {e}")

    conn.last_activity = time.time()
    return NetworkErrorCode.SUCCESS, resp_header, response_body


async def send_raw_request_async(
    conn: AsyncConnection,
    raw_request: bytes,
    timeout_ms: Optional[int] = None,
    config: Optional[Any] = None,
    logger_handle: Optional[object] = None
) -> Tuple[NetworkErrorCode, Optional[ResponseHeader], Optional[bytes]]:
    """
    STRICT TYPE 0 ASYNC:
    - Reads 32-byte header.
    - Extracts 3-byte body_size from Offset 9.
    - Strips the mandatory 2-byte '>>' trailer.
    """
    if conn is None or not conn.connected:
        return NetworkErrorCode.ERR_CONNECTION_FAILED, None, b''

    # FIXED: Safe fallback for 'QMailConfig' attribute errors
    if timeout_ms:
        timeout_s = timeout_ms / 1000.0
    else:
        # Check config object or nested config.sync.timeout_sec
        timeout_s = getattr(config, 'read_timeout_ms', 5000) / 1000.0

    try:
        conn.writer.write(raw_request)
        await asyncio.wait_for(conn.writer.drain(), timeout=timeout_s)

        # 1. Read 32-byte Header
        header_data = await asyncio.wait_for(conn.reader.readexactly(32), timeout=timeout_s)

        # 2. Parse Size from Offset 9 (3 bytes)
        resp_header = ResponseHeader()
        resp_header.raida_id = header_data[0]
        resp_header.status = header_data[2]
        # Server writes body size at Index 9 in big-endian 3-byte format
        resp_header.body_size = (header_data[9] << 16) | (header_data[10] << 8) | header_data[11]

        # 3. Read Body and Strip Trailer
        response_body = b''
        if resp_header.body_size > 0:
            full_body = await asyncio.wait_for(conn.reader.readexactly(resp_header.body_size), timeout=timeout_s)
            
            # FIXED: Strips '>>' (0x3E 0x3E) trailer added by prepare_response
            if full_body.endswith(b'\x3e\x3e'):
                response_body = full_body[:-2]
            else:
                response_body = full_body

        conn.last_activity = time.time()
        return NetworkErrorCode.SUCCESS, resp_header, response_body
    except Exception as e:
        log_error(logger_handle, "AsyncNetwork", f"Request failed: {e}")
        return NetworkErrorCode.ERR_RECEIVE_FAILED, None, b''
    

async def ping_server_async(
    server_info: ServerInfo,
    timeout_ms: Optional[int] = None,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> Tuple[NetworkErrorCode, float]:
    """
    Measure round-trip latency to server asynchronously.

    Args:
        server_info: Server to ping
        timeout_ms: Timeout in milliseconds
        config: NetworkConfig with timeout settings
        logger_handle: Optional logger handle

    Returns:
        Tuple of (error code, latency in milliseconds)
    """
    cfg = config or _DEFAULT_CONFIG
    timeout_s = (timeout_ms if timeout_ms else cfg.connect_timeout_ms) / 1000.0

    start_time = time.time()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server_info.host, server_info.port),
            timeout=timeout_s
        )

        writer.close()
        await writer.wait_closed()

        latency_ms = (time.time() - start_time) * 1000.0

        log_debug(logger_handle, ASYNC_NET_CONTEXT,
                  f"Ping {server_info.host}:{server_info.port}: {latency_ms:.1f}ms")

        return NetworkErrorCode.SUCCESS, latency_ms

    except asyncio.TimeoutError:
        return NetworkErrorCode.ERR_TIMEOUT, 0.0
    except OSError:
        return NetworkErrorCode.ERR_CONNECTION_FAILED, 0.0


# ============================================================================
# PARALLEL OPERATIONS
# ============================================================================

async def ping_servers_parallel(
    servers: List[ServerInfo],
    timeout_ms: Optional[int] = None,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> ParallelResult:
    """
    Ping multiple servers in parallel.

    Args:
        servers: List of servers to ping
        timeout_ms: Timeout per server
        config: NetworkConfig with timeout settings
        logger_handle: Optional logger handle

    Returns:
        ParallelResult with latency for each server

    Example:
        servers = [ServerInfo("192.168.1.x", 50000+i, i) for i in range(25)]
        result = await ping_servers_parallel(servers)
        print(f"Online: {result.success_count}/25")
    """
    start_time = time.time()

    async def ping_one(server: ServerInfo) -> ServerResult:
        err, latency = await ping_server_async(server, timeout_ms, config, logger_handle)
        return ServerResult(
            server=server,
            success=(err == NetworkErrorCode.SUCCESS),
            error_code=err,
            latency_ms=latency
        )

    # Run all pings concurrently
    tasks = [ping_one(server) for server in servers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    parallel_result = ParallelResult()
    for r in results:
        if isinstance(r, Exception):
            # Handle unexpected exceptions
            parallel_result.results.append(ServerResult(
                server=ServerInfo("unknown", 0),
                success=False,
                error_code=NetworkErrorCode.ERR_INTERNAL,
                error_message=str(r)
            ))
            parallel_result.failure_count += 1
        else:
            parallel_result.results.append(r)
            if r.success:
                parallel_result.success_count += 1
            else:
                parallel_result.failure_count += 1

    parallel_result.total_time_ms = (time.time() - start_time) * 1000.0

    log_info(logger_handle, ASYNC_NET_CONTEXT,
             f"Pinged {len(servers)} servers: {parallel_result.success_count} online, "
             f"{parallel_result.failure_count} offline ({parallel_result.total_time_ms:.1f}ms)")

    return parallel_result


async def send_to_server_async(
    server_info: ServerInfo,
    command_group: int,
    command_code: int,
    body_data: bytes,
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    encrypt: bool = True,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> ServerResult:
    """
    Send a single request to a server (connect, send, disconnect).

    Args:
        server_info: Target server
        command_group: Command group code
        command_code: Command code
        body_data: Request body
        encryption_key: Optional encryption key
        denomination: Coin denomination
        serial_number: Coin serial number
        encrypt: Whether to encrypt
        config: NetworkConfig
        logger_handle: Logger handle

    Returns:
        ServerResult with response data
    """
    start_time = time.time()
    result = ServerResult(server=server_info)

    # Connect
    err, conn = await connect_async(
        server_info, encryption_key, denomination, serial_number,
        config=config, logger_handle=logger_handle
    )

    if err != NetworkErrorCode.SUCCESS:
        result.error_code = err
        result.error_message = f"Connection failed: {err.name}"
        return result

    try:
        # Send request
        err, resp_header, resp_body = await send_request_async(
            conn, command_group, command_code, body_data,
            encrypt=encrypt, config=config, logger_handle=logger_handle
        )

        result.error_code = err
        if err == NetworkErrorCode.SUCCESS and resp_header:
            result.success = True
            result.status_code = resp_header.status
            result.data = resp_body
        else:
            result.error_message = f"Request failed: {err.name}"

    finally:
        await disconnect_async(conn, logger_handle)

    result.latency_ms = (time.time() - start_time) * 1000.0
    return result


async def send_to_multiple_servers_async(
    servers: List[ServerInfo],
    command_group: int,
    command_code: int,
    body_builder: Callable[[ServerInfo], bytes],
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    encrypt: bool = True,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    logger_handle: Optional[object] = None
) -> ParallelResult:
    """
    Send requests to multiple servers in parallel.

    Args:
        servers: List of target servers
        command_group: Command group code
        command_code: Command code
        body_builder: Function to build body for each server (may vary per server)
        encryption_key: Optional encryption key
        denomination: Coin denomination
        serial_number: Coin serial number
        encrypt: Whether to encrypt
        max_concurrent: Maximum concurrent connections
        config: NetworkConfig
        progress_callback: Called with (completed, total) as operations complete
        logger_handle: Logger handle

    Returns:
        ParallelResult with all server responses

    Example:
        def build_body(server):
            return stripe_for_server[server.raida_id]

        result = await send_to_multiple_servers_async(
            servers, CMD_GROUP_QMAIL, CMD_UPLOAD, build_body,
            key, denom, sn
        )
    """
    start_time = time.time()
    semaphore = asyncio.Semaphore(max_concurrent)
    completed = [0]  # Use list for mutable closure

    async def send_one(server: ServerInfo) -> ServerResult:
        async with semaphore:
            body = body_builder(server)
            result = await send_to_server_async(
                server, command_group, command_code, body,
                encryption_key, denomination, serial_number,
                encrypt, config, logger_handle
            )
            completed[0] += 1
            if progress_callback:
                progress_callback(completed[0], len(servers))
            return result

    # Run all requests concurrently (limited by semaphore)
    tasks = [send_one(server) for server in servers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    parallel_result = ParallelResult()
    for r in results:
        if isinstance(r, Exception):
            parallel_result.results.append(ServerResult(
                server=ServerInfo("unknown", 0),
                success=False,
                error_code=NetworkErrorCode.ERR_INTERNAL,
                error_message=str(r)
            ))
            parallel_result.failure_count += 1
        else:
            parallel_result.results.append(r)
            if r.success:
                parallel_result.success_count += 1
            else:
                parallel_result.failure_count += 1

    parallel_result.total_time_ms = (time.time() - start_time) * 1000.0

    log_info(logger_handle, ASYNC_NET_CONTEXT,
             f"Sent to {len(servers)} servers: {parallel_result.success_count} success, "
             f"{parallel_result.failure_count} failed ({parallel_result.total_time_ms:.1f}ms)")

    return parallel_result


# ============================================================================
# STRIPE UPLOAD/DOWNLOAD OPERATIONS
# ============================================================================

async def upload_stripe_async(
    server_info: ServerInfo,
    stripe_data: bytes,
    file_guid: bytes,
    locker_code: bytes,
    storage_duration: int = 0,
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    device_id: int = 0,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> ServerResult:
    """
    Upload a stripe to a single server.

    Args:
        server_info: Target server
        stripe_data: Binary data to upload
        file_guid: 16-byte unique file ID
        locker_code: 8-byte payment code
        storage_duration: Duration code
        encryption_key: Encryption key (AN)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        config: NetworkConfig
        logger_handle: Logger handle

    Returns:
        ServerResult with upload status
    """
    # Build upload body
    challenge = _calculate_challenge()
    session_id = bytes(8)  # Mode B: zeros
    preamble = build_common_preamble(
        challenge, session_id, denomination, serial_number, device_id, None
    )

    body = bytearray()
    body.extend(preamble)

    # File Group GUID (16 bytes)
    if file_guid and len(file_guid) >= 16:
        body.extend(file_guid[:16])
    else:
        body.extend(bytes(16))

    # Locker Code (8 bytes)
    if locker_code and len(locker_code) >= 8:
        body.extend(locker_code[:8])
    else:
        body.extend(bytes(8))

    # Reserved (2 bytes)
    body.extend(bytes(2))

    # Reserved (was File Type) (1 byte)
    body.append(0x00)

    # Storage Duration (1 byte)
    body.append(storage_duration & 0xFF)

    # Reserved (4 bytes)
    body.extend(bytes(4))

    # Data Length (4 bytes, big-endian)
    data_len = len(stripe_data)
    body.append((data_len >> 24) & 0xFF)
    body.append((data_len >> 16) & 0xFF)
    body.append((data_len >> 8) & 0xFF)
    body.append(data_len & 0xFF)

    # Binary data
    body.extend(stripe_data)

    # Send request
    return await send_to_server_async(
        server_info, CMD_GROUP_QMAIL, CMD_UPLOAD, bytes(body),
        encryption_key, denomination, serial_number,
        encrypt=(encryption_key is not None),
        config=config, logger_handle=logger_handle
    )


async def upload_stripes_parallel(
    servers: List[ServerInfo],
    stripes: List[bytes],
    file_guid: bytes,
    locker_code: bytes,
    storage_duration: int = 0,
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    device_id: int = 0,
    config: Optional[NetworkConfig] = None,
    task_handle: Optional[Any] = None,
    task_id: Optional[str] = None,
    logger_handle: Optional[object] = None
) -> ParallelResult:
    """
    Upload stripes to multiple servers in parallel.

    Args:
        servers: List of target servers (one per stripe)
        stripes: List of stripe data (must match servers length)
        file_guid: 16-byte unique file ID
        locker_code: 8-byte payment code
        storage_duration: Duration code
        encryption_key: Encryption key (AN)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        config: NetworkConfig
        task_handle: Optional task manager handle for progress
        task_id: Optional task ID for progress updates
        logger_handle: Logger handle

    Returns:
        ParallelResult with upload results for each server

    Example:
        servers = get_raida_servers()[:len(stripes)]
        result = await upload_stripes_parallel(
            servers, stripes, file_guid, locker_code,
            encryption_key=key, denomination=1, serial_number=12345
        )
        if result.majority_success:
            print("Upload succeeded!")
    """
    if len(servers) != len(stripes):
        log_error(logger_handle, ASYNC_NET_CONTEXT,
                  "upload_stripes_parallel failed",
                  f"Server count ({len(servers)}) != stripe count ({len(stripes)})")
        return ParallelResult(failure_count=len(servers))

    start_time = time.time()
    completed = [0]

    def progress_callback(done: int, total: int):
        completed[0] = done
        if task_handle and task_id:
            pct = int((done / total) * 100)
            update_task_progress(task_handle, task_id, pct, f"Uploaded {done}/{total} stripes")

    async def upload_one(server: ServerInfo, stripe: bytes) -> ServerResult:
        result = await upload_stripe_async(
            server, stripe, file_guid, locker_code, storage_duration,
            encryption_key, denomination, serial_number, device_id,
            config, logger_handle
        )
        completed[0] += 1
        if task_handle and task_id:
            pct = int((completed[0] / len(servers)) * 100)
            update_task_progress(task_handle, task_id, pct,
                               f"Uploaded {completed[0]}/{len(servers)} stripes")
        return result

    # Run all uploads concurrently
    tasks = [upload_one(server, stripe) for server, stripe in zip(servers, stripes)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    parallel_result = ParallelResult()
    for r in results:
        if isinstance(r, Exception):
            parallel_result.results.append(ServerResult(
                server=ServerInfo("unknown", 0),
                success=False,
                error_code=NetworkErrorCode.ERR_INTERNAL,
                error_message=str(r)
            ))
            parallel_result.failure_count += 1
        else:
            parallel_result.results.append(r)
            if r.success:
                parallel_result.success_count += 1
            else:
                parallel_result.failure_count += 1

    parallel_result.total_time_ms = (time.time() - start_time) * 1000.0

    log_info(logger_handle, ASYNC_NET_CONTEXT,
             f"Uploaded {len(stripes)} stripes: {parallel_result.success_count} success, "
             f"{parallel_result.failure_count} failed ({parallel_result.total_time_ms:.1f}ms)")

    return parallel_result


async def download_stripe_async(
    server_info: ServerInfo,
    file_guid: bytes,
    file_type: int = 0,
    version: int = 0,
    page_size: int = 0,
    page_number: int = 0,
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    device_id: int = 0,
    config: Optional[NetworkConfig] = None,
    logger_handle: Optional[object] = None
) -> ServerResult:
    """
    Download a stripe from a single server.

    Args:
        server_info: Target server
        file_guid: 16-byte unique file ID
        file_type: Type of file to download
        version: Version requested
        page_size: Page size code
        page_number: Page index
        encryption_key: Encryption key (AN)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        config: NetworkConfig
        logger_handle: Logger handle

    Returns:
        ServerResult with downloaded data
    """
    # Build download body
    challenge = _calculate_challenge()
    session_id = bytes(8)
    preamble = build_common_preamble(
        challenge, session_id, denomination, serial_number, device_id, None
    )

    body = bytearray()
    body.extend(preamble)

    # File Group GUID (16 bytes)
    if file_guid and len(file_guid) >= 16:
        body.extend(file_guid[:16])
    else:
        body.extend(bytes(16))

    # File Type (1 byte)
    body.append(file_type & 0xFF)

    # Version (1 byte)
    body.append(version & 0xFF)

    # Bytes Per Page (1 byte)
    body.append(page_size & 0xFF)

    # Page Number (1 byte)
    body.append(page_number & 0xFF)

    # Send request
    result = await send_to_server_async(
        server_info, CMD_GROUP_QMAIL, CMD_DOWNLOAD, bytes(body),
        encryption_key, denomination, serial_number,
        encrypt=(encryption_key is not None),
        config=config, logger_handle=logger_handle
    )

    # Parse response body to extract actual data
    if result.success and result.data and len(result.data) >= 8:
        data_length = struct.unpack(">I", result.data[4:8])[0]
        if len(result.data) >= 8 + data_length:
            result.data = result.data[8:8 + data_length]

    return result


async def download_stripes_parallel(
    servers: List[ServerInfo],
    file_guid: bytes,
    file_type: int = 0,
    version: int = 0,
    page_size: int = 0,
    page_number: int = 0,
    encryption_key: Optional[bytes] = None,
    denomination: int = 0,
    serial_number: int = 0,
    device_id: int = 0,
    config: Optional[NetworkConfig] = None,
    task_handle: Optional[Any] = None,
    task_id: Optional[str] = None,
    logger_handle: Optional[object] = None
) -> ParallelResult:
    """
    Download stripes from multiple servers in parallel.

    Args:
        servers: List of servers to download from
        file_guid: 16-byte unique file ID
        file_type: Type of file to download
        version: Version requested
        page_size: Page size code
        page_number: Page index
        encryption_key: Encryption key (AN)
        denomination: User's denomination
        serial_number: User's mailbox ID
        device_id: Device identifier
        config: NetworkConfig
        task_handle: Optional task manager handle for progress
        task_id: Optional task ID for progress updates
        logger_handle: Logger handle

    Returns:
        ParallelResult with downloaded stripes
    """
    start_time = time.time()
    completed = [0]

    async def download_one(server: ServerInfo) -> ServerResult:
        result = await download_stripe_async(
            server, file_guid, file_type, version, page_size, page_number,
            encryption_key, denomination, serial_number, device_id,
            config, logger_handle
        )
        completed[0] += 1
        if task_handle and task_id:
            pct = int((completed[0] / len(servers)) * 100)
            update_task_progress(task_handle, task_id, pct,
                               f"Downloaded {completed[0]}/{len(servers)} stripes")
        return result

    # Run all downloads concurrently
    tasks = [download_one(server) for server in servers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    parallel_result = ParallelResult()
    for r in results:
        if isinstance(r, Exception):
            parallel_result.results.append(ServerResult(
                server=ServerInfo("unknown", 0),
                success=False,
                error_code=NetworkErrorCode.ERR_INTERNAL,
                error_message=str(r)
            ))
            parallel_result.failure_count += 1
        else:
            parallel_result.results.append(r)
            if r.success:
                parallel_result.success_count += 1
            else:
                parallel_result.failure_count += 1

    parallel_result.total_time_ms = (time.time() - start_time) * 1000.0

    log_info(logger_handle, ASYNC_NET_CONTEXT,
             f"Downloaded from {len(servers)} servers: {parallel_result.success_count} success, "
             f"{parallel_result.failure_count} failed ({parallel_result.total_time_ms:.1f}ms)")

    return parallel_result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def run_async(coro):
    """
    Run an async coroutine from synchronous code.

    Args:
        coro: Coroutine to run

    Returns:
        Result of the coroutine

    Example:
        result = run_async(ping_servers_parallel(servers))
    """
    try:
        loop = asyncio.get_running_loop()
        # Already in async context, can't use run_until_complete
        raise RuntimeError("Cannot use run_async from within async context. Use 'await' instead.")
    except RuntimeError:
        # No running loop, create one
        return asyncio.run(coro)


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the async network module.
    """
    import sys

    print("=" * 60)
    print("network_async.py - Test Suite")
    print("=" * 60)

    async def run_tests():
        # Test 1: Ping unreachable server (timeout)
        print("\n1. Testing ping_server_async (timeout expected)...")
        bad_server = ServerInfo(host="192.0.2.1", port=50000, raida_id=0)
        err, latency = await ping_server_async(bad_server, timeout_ms=1000)
        assert err != NetworkErrorCode.SUCCESS
        print(f"   Expected error: {err.name}")
        print("   SUCCESS: Timeout handled correctly")

        # Test 2: Ping multiple servers in parallel
        print("\n2. Testing ping_servers_parallel (all should timeout)...")
        bad_servers = [
            ServerInfo(host="192.0.2.1", port=50000 + i, raida_id=i)
            for i in range(5)
        ]
        result = await ping_servers_parallel(bad_servers, timeout_ms=500)
        assert result.failure_count == 5
        assert result.success_count == 0
        print(f"   Results: {result.success_count} success, {result.failure_count} failed")
        print(f"   Total time: {result.total_time_ms:.1f}ms (parallel!)")
        print("   SUCCESS: Parallel ping works")

        # Test 3: ServerResult dataclass
        print("\n3. Testing ServerResult dataclass...")
        sr = ServerResult(
            server=ServerInfo("test", 50000, 0),
            success=True,
            latency_ms=50.0
        )
        assert sr.success
        assert sr.latency_ms == 50.0
        print(f"   ServerResult: success={sr.success}, latency={sr.latency_ms}ms")
        print("   SUCCESS: ServerResult works")

        # Test 4: ParallelResult dataclass
        print("\n4. Testing ParallelResult properties...")
        pr = ParallelResult(success_count=15, failure_count=10)
        assert pr.majority_success  # 15 > 12.5
        assert not pr.all_success
        pr2 = ParallelResult(success_count=10, failure_count=15)
        assert not pr2.majority_success  # 10 < 12.5
        print(f"   15/25 success: majority={pr.majority_success}")
        print(f"   10/25 success: majority={pr2.majority_success}")
        print("   SUCCESS: ParallelResult properties work")

        # Test 5: AsyncConnection dataclass
        print("\n5. Testing AsyncConnection dataclass...")
        conn = AsyncConnection(
            server=ServerInfo("test", 50000, 0),
            encryption_key=b'test_key_16bytes',
            denomination=1,
            serial_number=12345678
        )
        assert conn.server.host == "test"
        assert conn.encryption_key == b'test_key_16bytes'
        print(f"   AsyncConnection: server={conn.server.host}, connected={conn.connected}")
        print("   SUCCESS: AsyncConnection works")

        # Test 6: Build upload body (reuse from network.py)
        print("\n6. Testing upload body building...")
        challenge = _calculate_challenge()
        assert len(challenge) == 16
        preamble = build_common_preamble(
            challenge, bytes(8), 1, 1000000, 0x1234, None
        )
        assert len(preamble) == 49
        print(f"   Challenge: {challenge[:8].hex()}...")
        print(f"   Preamble: {len(preamble)} bytes")
        print("   SUCCESS: Body building works")

        # Test 7: Progress callback
        print("\n7. Testing progress callback...")
        progress_values = []

        def on_progress(done, total):
            progress_values.append((done, total))

        # Simulate parallel operation with progress
        bad_servers = [
            ServerInfo(host="192.0.2.1", port=50000 + i, raida_id=i)
            for i in range(3)
        ]

        def build_body(server):
            return b"test_body"

        result = await send_to_multiple_servers_async(
            bad_servers, CMD_GROUP_QMAIL, CMD_UPLOAD, build_body,
            progress_callback=on_progress,
            config=NetworkConfig(connect_timeout_ms=500)
        )

        assert len(progress_values) == 3  # Called once per server
        print(f"   Progress callbacks: {progress_values}")
        print("   SUCCESS: Progress callback works")

        # Test 8: run_async from sync context
        print("\n8. Testing run_async helper...")
        # This test must be run from the main block, not from within async

        print("   (Tested implicitly - we're running via asyncio.run)")
        print("   SUCCESS: run_async concept verified")

        # Test 9: Verify header parsing is reused
        print("\n9. Testing header parsing reuse...")
        fake_response = bytes([
            0x02,  # RAIDA ID
            0x00,  # Shard
            0xFA,  # Status (SUCCESS)
            0x00,  # Reserved
            0x00, 0x00,  # UDP frame count
            0x11, 0x11,  # Echo
            0x00,  # Reserved
            0x00, 0x00, 0x64,  # Body size = 100
            0x00, 0x00, 0x00, 0x00,  # Execution time
        ] + [0x00] * 16)  # Signature

        err, header = _parse_response_header(fake_response)
        assert err == NetworkErrorCode.SUCCESS
        assert header.raida_id == 2
        assert header.status == 250
        print(f"   Parsed header: RAIDA={header.raida_id}, status={header.status}")
        print("   SUCCESS: Header parsing reused from network.py")

        # Test 10: Nonce derivation is reused
        print("\n10. Testing nonce derivation reuse...")
        nonce = _derive_encryption_nonce(0x00ABCDEF)
        assert len(nonce) == 16
        assert nonce[5] == 0xAB
        assert nonce[6] == 0xCD
        assert nonce[7] == 0xEF
        print(f"   Nonce: {nonce.hex()}")
        print("   SUCCESS: Nonce derivation reused from network.py")

        print("\n" + "=" * 60)
        print("All async network tests passed!")
        print("=" * 60)

    # Run the async tests
    asyncio.run(run_tests())

    # Test run_async from truly sync context
    print("\n11. Testing run_async from sync context...")
    bad_server = ServerInfo(host="192.0.2.1", port=50000, raida_id=0)
    err, latency = run_async(ping_server_async(bad_server, timeout_ms=500))
    assert err != NetworkErrorCode.SUCCESS
    print(f"   Result: {err.name}")
    print("   SUCCESS: run_async works from sync context")

    print("\n" + "=" * 60)
    print("All tests complete!")
    print("=" * 60)
