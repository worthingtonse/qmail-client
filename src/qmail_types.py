"""
opus45_types.py - Core Type Definitions for QMail Client Core

This module defines the core data structures used throughout the QMail Client.
Designed for easy translation to C (types.h) in Phase III.

Author: Claude Opus 4.5 (opus45)
Phase: I
Version: 1.2.0

Changes in v1.2.0:
    - Added BeaconHandle, TellNotification, ServerLocation for Gemini's beacon design.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from enum import IntEnum
from threading import Thread, Event
from typing import Callable


# ============================================================================
# 1. ERROR CODES
# ============================================================================

class ErrorCode(IntEnum):
    """
    General error codes used across all modules.
    C: typedef enum { ERR_SUCCESS = 0, ... } ErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_PARAM = 1
    ERR_NOT_FOUND = 2
    ERR_ALREADY_EXISTS = 3
    ERR_IO = 4
    ERR_NETWORK = 5
    ERR_TIMEOUT = 6
    ERR_AUTH = 7
    ERR_PERMISSION = 8
    ERR_INTERNAL = 9
    ERR_NOT_IMPLEMENTED = 10


class DatabaseErrorCode(IntEnum):
    """
    Error codes for database operations.
    C: typedef enum { DB_SUCCESS = 0, ... } DatabaseErrorCode;
    """
    SUCCESS = 0
    ERR_OPEN_FAILED = 1
    ERR_CLOSE_FAILED = 2
    ERR_QUERY_FAILED = 3
    ERR_NOT_FOUND = 4
    ERR_INVALID_PARAM = 5
    ERR_CONSTRAINT = 6
    ERR_SCHEMA = 7
    ERR_IO = 8
    ERR_TRANSACTION = 9
    ERR_LOCKED = 10


class SearchErrorCode(IntEnum):
    """
    Error codes for search operations.
    C: typedef enum { SEARCH_SUCCESS = 0, ... } SearchErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_QUERY = 1
    ERR_DATABASE_ERROR = 2
    ERR_NO_RESULTS = 3
    ERR_INVALID_PARAM = 4
    ERR_INDEX_ERROR = 5


class NetworkErrorCode(IntEnum):
    """
    Error codes for network operations.
    C: typedef enum { NET_SUCCESS = 0, ... } NetworkErrorCode;
    """
    SUCCESS = 0
    ERR_CONNECTION_FAILED = 1
    ERR_TIMEOUT = 2
    ERR_DNS = 3
    ERR_SSL = 4
    ERR_PROTOCOL = 5
    ERR_SERVER_ERROR = 6
    ERR_INVALID_RESPONSE = 7
    ERR_INVALID_AN = 8


class CryptoErrorCode(IntEnum):
    """
    Error codes for cryptographic operations.
    C: typedef enum { CRYPTO_SUCCESS = 0, ... } CryptoErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_KEY = 1
    ERR_ENCRYPTION_FAILED = 2
    ERR_DECRYPTION_FAILED = 3
    ERR_SIGNATURE_FAILED = 4
    ERR_VERIFICATION_FAILED = 5
    ERR_HASH_FAILED = 6


# ============================================================================
# 1b. PROTOCOL ENUMS (from Sonnet's review)
# ============================================================================

class ServerType(IntEnum):
    """
    Server type codes.
    Source: api-client-database.md
    C: typedef enum { SERVER_RAIDA = 0, ... } ServerType;
    """
    RAIDA = 0
    DRD = 1
    DKE = 2
    QMAIL = 3
    QWEB = 4
    QVPN = 5


class RecipientType(IntEnum):
    """
    Recipient type codes for email addressing.
    Source: api-client-database.md
    C: typedef enum { RECIPIENT_TO = 0, ... } RecipientType;
    """
    TO = 0
    CC = 1
    BC = 2      # Blind copy
    MASS = 3
    FROM = 4    # Sender


class StorageMode(IntEnum):
    """
    Attachment storage mode.
    Source: api-client-database.md
    C: typedef enum { STORAGE_INTERNAL = 0, ... } StorageMode;
    """
    INTERNAL = 0    # Stored in data_blob
    EXTERNAL = 1    # Stored in file_path


class FileType(IntEnum):
    """
    File type codes for uploads/downloads.
    Source: QMAIL_UPLOAD_COMMAND.md
    C: typedef enum { FILE_META = 0, ... } FileType;
    """
    META = 0            # Meta data about the email
    QMAIL = 1           # The styling and body
    RESERVED = 2        # Web page, instant message, etc.
    ATTACHMENT_1 = 10   # First attachment
    ATTACHMENT_2 = 11   # Second attachment
    ATTACHMENT_3 = 12
    ATTACHMENT_4 = 13
    ATTACHMENT_5 = 14
    # ... can extend up to 255


class StorageDuration(IntEnum):
    """
    Server storage duration codes.
    Source: QMAIL_UPLOAD_COMMAND.md
    C: typedef enum { DURATION_ONE_DAY = 0, ... } StorageDuration;
    """
    ONE_DAY = 0
    ONE_WEEK = 1
    ONE_MONTH = 2
    THREE_MONTHS = 3
    SIX_MONTHS = 4
    ONE_YEAR = 5
    PERMANENT = 255


class StatusCode(IntEnum):
    """
    Server response status codes.
    Source: QMAIL_UPLOAD_COMMAND.md, QMAIL_DOWNLOAD_COMMAND.md
    C: typedef enum { STATUS_SUCCESS = 250, ... } StatusCode;
    """
    STATUS_SUCCESS = 250
    STATUS_YOU_GOT_MAIL = 11 # From PING response doc, even if it's just an alias for 250 with data
    ERROR_UDP_FRAME_TIMEOUT = 17 # From PING response doc, means no mail on long poll
    ERROR_INVALID_PACKET_LENGTH = 16
    ERROR_WRONG_RAIDA = 18
    ERROR_PAYMENT_REQUIRED = 166
    ERROR_FILESYSTEM = 194
    ERROR_INVALID_PARAMETER = 198
    ERROR_FILE_NOT_EXIST = 202


class EncryptionMode(IntEnum):
    """
    Encryption mode for server communication.
    Source: QMAIL_UPLOAD_COMMAND.md
    C: typedef enum { ENC_MODE_A = 6, ... } EncryptionMode;
    """
    MODE_A = 6  # Session-based (uses Session ID, AN is zeros)
    MODE_B = 1  # AN-based (uses AN, Session ID is zeros)


class PageSize(IntEnum):
    """
    Download page size codes.
    Source: QMAIL_DOWNLOAD_COMMAND.md
    C: typedef enum { PAGE_MAX_SIZE = 0, ... } PageSize;
    """
    MAX_SIZE = 0
    SIZE_1KB = 1
    SIZE_8KB = 2
    SIZE_64KB = 3


class TaskState(IntEnum):
    """
    Task state codes for async operations.
    Source: plan.txt
    C: typedef enum { TASK_PENDING = 0, ... } TaskState;
    """
    PENDING = 0
    RUNNING = 1
    COMPLETED = 2
    FAILED = 3
    CANCELLED = 4


class LockerStatus(IntEnum):
    """
    CloudCoin locker status codes.
    Source: plan.txt
    C: typedef enum { LOCKER_LOCKED = 0, ... } LockerStatus;
    """
    LOCKED = 0
    UNLOCKED = 1
    EMPTY = 2
    ERROR = 3


# ============================================================================
# 2. CORE DATA TYPES
# ============================================================================

@dataclass
class User:
    """
    Represents a user/contact from the 'Users' table.
    C: typedef struct User { ... } User;
    """
    user_id: Optional[int] = None
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    last_name: Optional[str] = None
    auto_address: Optional[str] = None      # QMail address
    description: Optional[str] = None
    avatar: Optional[bytes] = None          # Avatar image data
    streak: int = 0
    sending_fee: Optional[str] = None
    contact_count: int = 0
    last_contacted_timestamp: Optional[str] = None

    def display_name(self) -> str:
        """Get formatted display name."""
        parts = [p for p in [self.first_name, self.middle_name, self.last_name] if p]
        return " ".join(parts) if parts else self.auto_address or "Unknown"


@dataclass
class Attachment:
    """
    Represents a file attachment from the 'Attachments' table.
    C: typedef struct Attachment { ... } Attachment;
    """
    attachment_id: Optional[int] = None
    email_id: Optional[bytes] = None
    name: Optional[str] = None
    file_extension: Optional[str] = None
    storage_mode: str = 'INTERNAL'          # 'INTERNAL' or 'EXTERNAL'
    status: Optional[str] = None
    data_blob: Optional[bytes] = None       # For INTERNAL storage
    file_path: Optional[str] = None         # For EXTERNAL storage
    size_bytes: Optional[int] = None


@dataclass
class Email:
    """
    Represents an email message.
    C: typedef struct Email { ... } Email;
    """
    email_id: Optional[bytes] = None        # 16-byte GUID
    subject: Optional[str] = None
    body: Optional[str] = None
    received_timestamp: Optional[str] = None
    sent_timestamp: Optional[str] = None
    meta: Optional[bytes] = None            # Metadata blob
    style: Optional[bytes] = None           # Style/formatting blob
    is_read: bool = False
    is_starred: bool = False
    is_trashed: bool = False
    folder: str = 'inbox'

    # Related data (populated by retrieve operations)
    sender: Optional[User] = None
    recipients: List[User] = field(default_factory=list)
    cc_recipients: List[User] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)


@dataclass
class ServerConfig:
    """
    Represents a QMail or RAIDA server from the config file.

    Note: 'host' and 'raida_id' are properties for network.py compatibility,
    which uses ServerInfo with those field names.
    """
    address: str = ""
    port: int = 0
    index: int = 0
    server_type: Optional[str] = None
    description: Optional[str] = None

    @property
    def host(self) -> str:
        """Alias for address - compatibility with network.ServerInfo."""
        return self.address

    @property
    def raida_id(self) -> int:
        """Alias for index - compatibility with network.ServerInfo."""
        return self.index


@dataclass
class Session:
    """
    Represents a server session from the 'Session' table.
    C: typedef struct Session { ... } Session;
    """
    session_pk: Optional[int] = None
    session_guid: Optional[bytes] = None
    server_id: Optional[int] = None
    encryption_key: Optional[bytes] = None
    created_timestamp: Optional[str] = None
    expires_timestamp: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_timestamp is None:
            return False
        from datetime import datetime
        try:
            expires = datetime.fromisoformat(self.expires_timestamp.replace('Z', '+00:00'))
            return datetime.now(expires.tzinfo) > expires
        except (ValueError, TypeError):
            return True


@dataclass
class NetworkConfig:
    """
    Network configuration settings for server communication.
    C: typedef struct NetworkConfig { ... } NetworkConfig;
    """
    connect_timeout_ms: int = 5000
    read_timeout_ms: int = 30000
    max_retries: int = 3
    retry_backoff_ms: int = 1000  # Initial backoff between retries (exponential)
    max_response_body_size: int = 10 * 1024 * 1024  # 10 MB max response size
    # Security: Set to True to reject responses with echo mismatch
    # (protects against response spoofing/MITM attacks)
    strict_echo_validation: bool = True


@dataclass
class LockerKey:
    """
    Represents a CloudCoin locker key from the 'Locker_Keys' table.
    C: typedef struct LockerKey { ... } LockerKey;
    """
    key_id: Optional[int] = None
    email_id: Optional[bytes] = None
    key: bytes = b''
    received_from: Optional[int] = None
    received_timestamp: Optional[str] = None
    sent_timestamp: Optional[str] = None
    redeemed_timestamp: Optional[str] = None
    is_authentic: Optional[bool] = None
    amount: Optional[str] = None
    sending_server_id: Optional[int] = None

# Configuration Sub-structures
@dataclass
class PathsConfig:
    db_path: str = ""
    log_path: str = ""
    locker_files_path: str = ""
    attachments_path: str = ""

@dataclass
class IdentityConfig:
    coin_type: int = 0
    denomination: int = 0
    serial_number: int = 0
    device_id: int = 0
    authenticity_number: Optional[str] = None

@dataclass
class EncryptionConfig:
    enabled: bool = True
    mode: int = 6

@dataclass
class BeaconConfig:
    url: str = ""
    server_index: int = 14
    interval_sec: int = 600
    timeout_sec: int = 600

@dataclass
class RaidConfig:
    data_stripe_count: int = 4
    parity_stripe_count: int = 1

@dataclass
class ThreadingConfig:
    pool_size: int = 5

@dataclass
class ApiConfig:
    enabled: bool = True
    host: str = ""
    port: Optional[int] = None

@dataclass
class LoggingConfig:
    level: str = "info"
    max_size_mb: int = 10
    backup_count: int = 3

@dataclass
class SyncConfig:
    """Configuration for data synchronization from RAIDA servers."""
    users_url: str = "https://raida11.cloudcoin.global/service/users"
    servers_url: str = "https://raida11.cloudcoin.global/service/qmail_servers"
    timeout_sec: int = 30

@dataclass
class QMailConfig:
    """
    Top-level configuration object.
    """
    paths: PathsConfig = field(default_factory=PathsConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    beacon: BeaconConfig = field(default_factory=BeaconConfig)
    raid: RaidConfig = field(default_factory=RaidConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    threading: ThreadingConfig = field(default_factory=ThreadingConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)
    qmail_servers: List[ServerConfig] = field(default_factory=list)
    raida_servers: List[ServerConfig] = field(default_factory=list)

# ============================================================================
# 3. RAID TYPES (for striping and parity)
# ============================================================================

@dataclass
class Stripe:
    index: int
    data: bytes = b''
    size: int = 0
    checksum: int = 0

@dataclass
class ParityStripe:
    index: int
    data: bytes = b''
    size: int = 0

@dataclass
class StripeSet:
    stripes: List[Stripe] = field(default_factory=list)
    parity_stripes: List[ParityStripe] = field(default_factory=list)
    total_size: int = 0
    encryption_key: bytes = b''

# ============================================================================
# 4. TASK TYPES (for async operations)
# ============================================================================

@dataclass
class TaskStatus:
    task_id: str = ""
    state: str = "PENDING"
    progress: int = 0
    message: str = ""
    result: Any = None
    error: Optional[str] = None
    created_timestamp: Optional[str] = None
    started_timestamp: Optional[str] = None
    completed_timestamp: Optional[str] = None

    @property
    def is_finished(self) -> bool:
        return self.state in ('COMPLETED', 'FAILED', 'CANCELLED')

    @property
    def is_successful(self) -> bool:
        return self.state == 'COMPLETED'

# ============================================================================
# 5. PAYMENT TYPES (for CloudCoin integration)
# ============================================================================

@dataclass
class CloudCoin:
    denomination: int = 1
    serial: int = 0
    authenticity_number: str = ""
    nn: int = 1

@dataclass
class Locker:
    locker_id: str = ""
    key: bytes = b''
    coins: List[CloudCoin] = field(default_factory=list)
    created_timestamp: Optional[str] = None
    expires_timestamp: Optional[str] = None

    @property
    def total_value(self) -> int:
        return sum(coin.denomination for coin in self.coins)

# ============================================================================
# 6. PROTOCOL TYPES (from Sonnet's review)
# ============================================================================

@dataclass
class UploadRequest:
    challenge_crc: bytes = b''
    session_id: bytes = b''
    coin_type: int = 6
    denomination: int = 1
    serial_number: int = 0
    device_id: int = 1
    authenticity_number: bytes = b''
    file_group_guid: bytes = b''
    locker_code: bytes = b''
    storage_duration: int = StorageDuration.ONE_WEEK
    file_type: int = FileType.QMAIL
    data_length: int = 0
    binary_data: bytes = b''

@dataclass
class DownloadRequest:
    challenge_crc: bytes = b''
    session_id: bytes = b''
    coin_type: int = 6
    denomination: int = 1
    serial_number: int = 0
    device_id: int = 1
    authenticity_number: bytes = b''
    file_group_guid: bytes = b''
    file_type: int = FileType.QMAIL
    version: int = 1
    bytes_per_page: int = PageSize.MAX_SIZE
    page_number: int = 0

@dataclass
class DownloadResponse:
    file_type: int = FileType.QMAIL
    version: int = 1
    bytes_per_page: int = PageSize.MAX_SIZE
    page_number: int = 0
    data_length: int = 0
    binary_data: bytes = b''

@dataclass
class ServerResponse:
    status_code: int = StatusCode.STATUS_SUCCESS
    payload: bytes = b''
    error_message: str = ""

    @property
    def is_success(self) -> bool:
        return self.status_code == StatusCode.STATUS_SUCCESS

@dataclass
class PingRequest:
    challenge: bytes = b''
    session_id: bytes = b''
    coin_type: int = 6
    denomination: int = 1
    serial_number: int = 0
    authenticity_number: bytes = b''

@dataclass
class ServerInfo:
    ip_address: str = ""
    port: int = 0
    server_index: int = 0
    server_type: int = ServerType.QMAIL

@dataclass
class BeaconNotification:
    email_id: bytes = b''
    raid_type: int = 0
    servers: List[ServerInfo] = field(default_factory=list)

# ============================================================================
# 7. META DATA TYPES (from Sonnet's review)
# ============================================================================

@dataclass
class QMailAddress:
    coin_type: int = 6
    denomination: int = 1
    serial_number: int = 0
    avatar_guid: Optional[bytes] = None

@dataclass
class StyleFormat:
    style_start_code: int = 0
    font_family: int = 0
    color: int = 0
    background_color: int = 0
    font_weight: int = 0
    font_style: int = 0
    text_decoration_line: int = 0
    direction: int = 0
    style_end_code: int = 0

@dataclass
class CBDFKey:
    key_id: int = 0
    value_length: int = 0
    value: bytes = b''

@dataclass
class MetaData:
    version: int = 1
    qmail_id: bytes = b''
    subject: Optional[str] = None
    subject_formatting: Optional[StyleFormat] = None
    to_array: List[QMailAddress] = field(default_factory=list)
    cc_array: List[QMailAddress] = field(default_factory=list)
    senders_avatar: bytes = b''
    senders_mailbox: bytes = b''
    timestamp: int = 0
    attachment_guids: List[bytes] = field(default_factory=list)
    embedded_object_table: Optional[bytes] = None

# ============================================================================
# 8. SEARCH TYPES
# ============================================================================

@dataclass
class SearchQuery:
    terms: str = ""
    subject: Optional[str] = None
    body: Optional[str] = None
    sender: Optional[str] = None
    folder: Optional[str] = None
    is_read: Optional[bool] = None
    is_starred: Optional[bool] = None
    is_trashed: Optional[bool] = None
    has_attachments: Optional[bool] = None
    sender_name: Optional[str] = None
    recipient_name: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: int = 50
    offset: int = 0
    order_by: str = "ReceivedTimestamp"
    order_desc: bool = True

@dataclass
class SearchResultItem:
    id: Any = None
    score: float = 0.0
    snippet: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SearchResult:
    items: List[SearchResultItem] = field(default_factory=list)
    total_count: int = 0
    query_time_ms: float = 0.0
    error_code: SearchErrorCode = SearchErrorCode.SUCCESS
    error_message: str = ""

# ============================================================================
# 9. API TYPES
# ============================================================================

@dataclass
class ApiRequest:
    method: str = "GET"
    path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    content_type: str = "application/json"

@dataclass
class ApiResponse:
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    content_type: str = "application/json"
    error_message: str = ""

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

# ============================================================================
# 10. UTILITY TYPES
# ============================================================================

@dataclass
class ValidationResult:
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.is_valid = False
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

@dataclass
class OperationResult:
    success: bool = True
    error_code: ErrorCode = ErrorCode.SUCCESS
    error_message: str = ""
    data: Any = None

    @staticmethod
    def ok(data: Any = None) -> 'OperationResult':
        return OperationResult(success=True, data=data)

    @staticmethod
    def error(code: ErrorCode, message: str = "") -> 'OperationResult':
        return OperationResult(
            success=False,
            error_code=code,
            error_message=message
        )

@dataclass
class PaginatedResult:
    items: List[Any] = field(default_factory=list)
    total_count: int = 0
    limit: int = 50
    offset: int = 0

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total_count

    @property
    def page_count(self) -> int:
        if self.limit <= 0:
            return 1
        return (self.total_count + self.limit - 1) // self.limit

    @property
    def current_page(self) -> int:
        if self.limit <= 0:
            return 1
        return (self.offset // self.limit) + 1

# ============================================================================
# 11. JUNCTION TYPES (for relationships)
# ============================================================================

@dataclass
class EmailUserLink:
    email_id: bytes
    user_id: int
    user_type: str

@dataclass
class EmailServerLink:
    email_id: bytes
    server_id: int
    stripe_index: int

# ============================================================================
# 12. STATISTICS TYPES
# ============================================================================

@dataclass
class DatabaseStats:
    email_count: int = 0
    user_count: int = 0
    attachment_count: int = 0
    server_count: int = 0
    session_count: int = 0
    locker_key_count: int = 0
    database_size_bytes: int = 0

@dataclass
class FolderStats:
    folder_counts: Dict[str, int] = field(default_factory=dict)
    unread_count: int = 0
    starred_count: int = 0
    trash_count: int = 0
    total_count: int = 0

@dataclass
class SearchStats:
    indexed_emails: int = 0
    total_emails: int = 0
    total_contacts: int = 0
    total_servers: int = 0
    index_coverage_percent: float = 100.0

# ============================================================================
# TYPE ALIASES (for convenience)
# ============================================================================

EmailID = bytes
UserID = int
ServerID = int
Timestamp = str


# ============================================================================
# 14. SEND EMAIL TYPES (from opus45's plan)
# ============================================================================

class SendEmailErrorCode(IntEnum):
    """
    Error codes for Send Email operations.
    C: typedef enum { SEND_SUCCESS = 0, ... } SendEmailErrorCode;
    """
    SUCCESS = 0
    # Validation errors
    ERR_NO_EMAIL_FILE = 101
    ERR_NO_RECIPIENTS = 102
    ERR_INVALID_RECIPIENT = 103
    ERR_RECIPIENT_NOT_FOUND = 104
    ERR_ATTACHMENT_NOT_FOUND = 105
    ERR_TOO_MANY_ATTACHMENTS = 106
    ERR_FILE_TOO_LARGE = 107
    ERR_INSUFFICIENT_FUNDS = 108
    # Upload errors
    ERR_SERVER_UNREACHABLE = 201
    ERR_UPLOAD_TIMEOUT = 202
    ERR_PAYMENT_REQUIRED = 203
    ERR_INVALID_PACKET = 204
    ERR_FILESYSTEM = 205
    ERR_WRONG_RAIDA = 206
    ERR_CHALLENGE_FAILED = 207
    ERR_PARTIAL_FAILURE = 208
    ERR_ENCRYPTION_FAILED = 209


@dataclass
class SendEmailRequest:
    """
    Request data for sending an email.
    C: typedef struct SendEmailRequest { ... } SendEmailRequest;
    """
    email_file: bytes = b''                 # CBDF binary data
    searchable_text: str = ""               # For database indexing
    subject: str = ""
    subsubject: Optional[str] = None
    to_recipients: List[str] = field(default_factory=list)    # QMail addresses
    cc_recipients: List[str] = field(default_factory=list)
    bcc_recipients: List[str] = field(default_factory=list)
    attachment_paths: List[str] = field(default_factory=list) # Absolute paths
    storage_weeks: int = 8                  # Default 8 weeks
    index_attachments: bool = False         # Stub, default False


@dataclass
class RecipientInfo:
    """
    Information about an email recipient.
    C: typedef struct RecipientInfo { ... } RecipientInfo;
    """
    qmail_address: str = ""                 # "0006.1.12345678"
    recipient_type: int = RecipientType.TO  # 0=TO, 1=CC, 2=BCC
    beacon_server_id: str = ""              # From database lookup
    receiving_fee: float = 0.0              # Fee to receive (currently 0)


@dataclass
class FileUploadInfo:
    """
    Information about a file being uploaded (email body or attachment).
    C: typedef struct FileUploadInfo { ... } FileUploadInfo;
    """
    file_index: int = 1                     # 1=email body, 10+=attachments
    file_data: bytes = b''                  # Original file content
    file_name: str = ""                     # Original filename
    file_size: int = 0                      # Size in bytes
    encrypted_data: bytes = b''             # After encryption
    stripes: List[bytes] = field(default_factory=list)        # 4 data stripes
    parity_stripe: bytes = b''              # 1 parity stripe
    upload_results: Dict[str, bool] = field(default_factory=dict)  # server_id -> success


@dataclass
class EmailPackage:
    """
    Complete package for sending an email with all files.
    C: typedef struct EmailPackage { ... } EmailPackage;
    """
    file_group_guid: bytes = b''            # 16-byte GUID (shared by all files)
    sender_identity: Optional[IdentityConfig] = None
    recipients: List[RecipientInfo] = field(default_factory=list)
    files: List[FileUploadInfo] = field(default_factory=list)
    storage_duration: int = StorageDuration.ONE_MONTH  # Duration code (0-5, 255)
    locker_code: bytes = b''                # 8-byte payment code
    total_cost: float = 0.0                 # Calculated cost
    created_at: Optional[str] = None


@dataclass
class UploadResult:
    """
    Result of uploading a single stripe to a server.
    C: typedef struct UploadResult { ... } UploadResult;
    """
    server_id: str = ""
    stripe_index: int = 0                   # 0-3 for data, 4 for parity
    success: bool = False
    status_code: int = 0
    error_message: Optional[str] = None
    upload_time_ms: int = 0


@dataclass
class SendEmailResult:
    """
    Result of sending an email.
    C: typedef struct SendEmailResult { ... } SendEmailResult;
    """
    success: bool = False
    error_code: SendEmailErrorCode = SendEmailErrorCode.SUCCESS
    error_message: str = ""
    file_group_guid: bytes = b''
    file_count: int = 0
    total_cost: float = 0.0
    upload_results: List[UploadResult] = field(default_factory=list)


# ============================================================================
# 15. TELL COMMAND TYPES (for sending notifications)
# ============================================================================

@dataclass
class TellRecipient:
    """
    Recipient entry for Tell command (32 bytes when packed).
    Used to notify a recipient's beacon server about new email.
    C: typedef struct TellRecipient { ... } TellRecipient;
    """
    address_type: int = 0           # 0=To, 1=CC, 2=BCC
    coin_id: int = 0x0006           # CloudCoin V3
    denomination: int = 1           # Recipient's denomination
    domain_id: int = 0              # 0 = QMail
    serial_number: int = 0          # Recipient's mailbox SN (3 bytes in protocol)
    locker_payment_key: bytes = b'' # 16-byte payment key from cloudcoin pool


@dataclass
class TellServer:
    """
    Server entry for Tell command.
    Describes where email stripes are stored and how to decrypt them.
    C: typedef struct TellServer { ... } TellServer;
    """
    stripe_index: int = 0           # 0-based index in stripe array
    stripe_type: int = 0            # 0=Data, 1=Parity
    server_id: int = 0              # Server identifier (8 bytes in protocol)
    ip_address: str = ""            # IPv4 address string
    port: int = 0                   # Server port
    locker_code: bytes = b''        # 8-byte locker code for this server's stripe


@dataclass
class TellResult:
    """
    Result of sending a Tell notification to a beacon.
    C: typedef struct TellResult { ... } TellResult;
    """
    recipient_address: str = ""
    beacon_server_id: str = ""
    success: bool = False
    status_code: int = 0
    error_message: str = ""


@dataclass
class PendingTell:
    """
    A Tell notification pending retry after failure.
    Stored in PendingTells database table.
    C: typedef struct PendingTell { ... } PendingTell;
    """
    tell_id: int = 0
    file_group_guid: bytes = b''
    recipient_address: str = ""
    recipient_type: int = 0         # 0=To, 1=CC, 2=BCC
    beacon_server_id: str = ""
    locker_code: bytes = b''        # 8-byte base locker code for re-encryption
    server_list_json: str = ""      # JSON serialized server list
    retry_count: int = 0
    last_attempt_at: Optional[str] = None
    error_message: str = ""
    status: str = "pending"         # pending, sent, failed


# ============================================================================
# 16. BEACON TYPES (from Gemini's design)
# ============================================================================

@dataclass
class ServerLocation:
    """
    Represents the location of a specific stripe on a server.
    Derived from the 32-byte Server List entry in a PING response.
    """
    stripe_index: int = 0
    total_stripes: int = 0
    server_id: int = 0  # RAIDA index of the server
    raw_entry: bytes = b'' # The raw 32-byte entry for debugging

@dataclass
class TellNotification:
    """
    Represents a single, parsed "Tell" notification from the beacon.
    """
    file_guid: bytes = field(default_factory=lambda: bytes(16))
    locker_code: bytes = field(default_factory=lambda: bytes(8))
    timestamp: int = 0
    tell_type: int = 0
    server_count: int = 0
    server_list: List[ServerLocation] = field(default_factory=list)

@dataclass
class BeaconHandle:
    """
    A handle containing the state and configuration for a beacon monitor instance.
    """
    # Configuration
    identity: 'IdentityConfig'
    beacon_config: 'BeaconConfig'
    network_config: 'NetworkConfig'
    
    # Static Info
    beacon_server_info: 'ServerConfig'
    encryption_key: bytes
    device_id: int
    state_file_path: str
    logger_handle: Optional[object] = None
    
    # State
    is_running: bool = False
    shutdown_event: Event = field(default_factory=Event)
    monitor_thread: Optional[Thread] = None
    on_mail_received: Optional[Callable[[List[TellNotification]], None]] = None
    last_tell_timestamp: int = 0

# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("This is a type definition file and is not meant to be run directly.")