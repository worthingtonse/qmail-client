# src/types.py
"""
This module defines the dataclass structures for the QMail Client configuration.
These classes provide type safety and a clear structure for the config object.
"""

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class PathsConfig:
    """Configuration for file system paths."""
    db_path: str = "Data/qmail.db"
    log_path: str = "Data/mail.mlog"
    locker_files_path: str = "Data/Lockers"
    attachments_path: str = "Data/Attachments"

@dataclass
class IdentityConfig:
    """Configuration for the user's identity."""
    coin_type: int = 6
    denomination: int = 1
    serial_number: int = 0
    device_id: int = 1
    authenticity_number: Optional[str] = None

@dataclass
class EncryptionConfig:
    """Configuration for encryption settings."""
    enabled: bool = True
    mode: int = 1  # 1 for Mode B (AN-based), 6 for Mode A (Session-based)

@dataclass
class BeaconConfig:
    """Configuration for the beacon server connection."""
    url: str = "tcp://168.220.219.199:50014"
    server_index: int = 14
    interval_sec: int = 600
    timeout_sec: int = 600

@dataclass
class RaidConfig:
    """Configuration for data striping (RAID)."""
    data_stripe_count: int = 4
    parity_stripe_count: int = 1

@dataclass
class NetworkConfig:
    """Configuration for general network settings."""
    connection_timeout_ms: int = 5000
    read_timeout_ms: int = 30000
    max_retries: int = 3

@dataclass
class ThreadingConfig:
    """Configuration for the worker thread pool."""
    pool_size: int = 5

@dataclass
class ApiConfig:
    """Configuration for the local REST API server."""
    enabled: bool = True
    host: str = "127.0.0.1"
    port: Optional[int] = None # Port is set via CLI argument

@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: str = "info"
    max_size_mb: int = 10
    backup_count: int = 3

@dataclass
class ServerConfig:
    """Represents a single server (either QMail or RAIDA)."""
    address: str
    port: int
    index: Optional[int] = None
    server_type: Optional[str] = None
    description: Optional[str] = None

@dataclass
class ValidationResult:
    """Represents the outcome of a configuration validation."""
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str):
        self.is_valid = False
        self.errors.append(message)

    def add_warning(self, message: str):
        self.warnings.append(message)

@dataclass

class QMailConfig:

    """The root configuration object."""

    paths: PathsConfig = field(default_factory=PathsConfig)

    identity: IdentityConfig = field(default_factory=IdentityConfig)

    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)

    beacon: BeaconConfig = field(default_factory=BeaconConfig)

    raid: RaidConfig = field(default_factory=RaidConfig)

    network: NetworkConfig = field(default_factory=NetworkConfig)

    threading: ThreadingConfig = field(default_factory=ThreadingConfig)

    api: ApiConfig = field(default_factory=ApiConfig)

    logging: LoggingConfig = field(default_factory=LoggingConfig)

    qmail_servers: List[ServerConfig] = field(default_factory=list)

    raida_servers: List[ServerConfig] = field(default_factory=list)



# ============================================================================

# Data Structures from plan.txt / database schema

# ============================================================================



@dataclass



class User:



    """Represents a user/contact from the 'Users' table."""



    UserID: int



    FirstName: Optional[str] = None



    MiddleName: Optional[str] = None



    LastName: Optional[str] = None



    Avatar: Optional[bytes] = None



    streak: int = 0



    sending_fee: Optional[str] = None



    Description: Optional[str] = None



    # Fields inspired by opus45_database for better popularity tracking



    auto_address: Optional[str] = None



    last_contacted_timestamp: Optional[str] = None



    contact_count: int = 0







@dataclass



class Attachment:



    """Represents a file attachment from the 'Attachments' table."""



    Attachment_id: Optional[int] = None



    EmailID: Optional[bytes] = None



    name: Optional[str] = None



    file_extension: Optional[str] = None



    storage_mode: str = 'INTERNAL'  # 'INTERNAL' or 'EXTERNAL'



    status: Optional[str] = None



    data_blob: Optional[bytes] = None



    file_path: Optional[str] = None







@dataclass







class Email:







    """Represents an email, combining data from multiple tables."""







    EmailID: bytes







    Subject: Optional[str] = None







    Body: Optional[str] = None







    ReceivedTimestamp: Optional[str] = None







    SentTimestamp: Optional[str] = None







    Meta: Optional[bytes] = None







    Style: Optional[bytes] = None







    is_read: bool = False







    is_starred: bool = False







    is_trashed: bool = False







    folder: str = 'inbox'







    recipients: List[User] = field(default_factory=list)







    attachments: List[Attachment] = field(default_factory=list)















# ============================================================================















# Data Structures for Search Engine Module (v2)















# ============================================================================































@dataclass















class SearchQuery:















    """















    Represents a detailed search query.















    Inspired by opus45_search_engine's more detailed query structure.















    """















    terms: str = ""































    # Field-specific full-text searches















    subject: Optional[str] = None















    body: Optional[str] = None















    















    # Filters















    folder: Optional[str] = None















    is_read: Optional[bool] = None















    is_starred: Optional[bool] = None















    has_attachments: Optional[bool] = None















    date_from: Optional[str] = None  # ISO format: YYYY-MM-DD















    date_to: Optional[str] = None    # ISO format: YYYY-MM-DD































    # Pagination and sorting















    limit: int = 25















    offset: int = 0















    sort_by: str = 'rank'  # 'rank', 'ReceivedTimestamp', etc.















    sort_desc: bool = True































@dataclass















class SearchResultItem:















    """















    Represents a single item in a search result set, including relevance info.















    """















    id: Any  # EmailID (bytes) or UserID (int)















    score: float = 0.0  # Relevance score from FTS5















    snippet: str = ""   # Highlighted snippet from the search















    data: Dict[str, Any] = field(default_factory=dict)































@dataclass















class SearchResult:















    """Represents the result of a search operation."""















    items: List[SearchResultItem] = field(default_factory=list)















    total_count: int = 0















    elapsed_time: float = 0.0
























