# gemini_core/types.py
# This file contains all shared data types, enums, and dataclasses,
# designed to be easily translatable to C structs and enums.

from enum import IntEnum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

# ============================================================================
# ENUMERATIONS (translate to C enums)
# ============================================================================

class ErrorCode(IntEnum):
    """Error codes returned by functions, similar to C-style error handling."""
    SUCCESS = 0
    FAILURE = 1
    ERR_INVALID_PARAM = 2
    ERR_NOT_FOUND = 3
    ERR_IO = 4
    ERR_NETWORK = 5
    ERR_ENCRYPTION = 6
    ERR_DECRYPTION = 7
    ERR_DATABASE = 8
    ERR_INSUFFICIENT_FUNDS = 9
    ERR_TASK_NOT_FOUND = 10

class TaskState(IntEnum):
    """Represents the state of an asynchronous task."""
    PENDING = 0
    IN_PROGRESS = 1
    COMPLETED = 2
    FAILED = 3

# ============================================================================
# DATA STRUCTURES (translate to C structs)
# ============================================================================

@dataclass
class Stripe:
    """A single stripe of data for the RAID-style system."""
    index: int
    data: bytes
    checksum: int

@dataclass
class CloudCoinLocker:
    """Represents a wallet holding CloudCoins."""
    key_path: str
    balance: int = 0

@dataclass
class Task:
    """Represents an asynchronous task being tracked by the TaskManager."""
    id: str
    description: str
    state: TaskState = TaskState.PENDING
    progress: int = 0
    result: Optional[Any] = None
    error_message: str = ""

@dataclass
class Email:
    """Represents the metadata and content of an email."""
    subject: str
    sender: str
    recipients: List[str]
    body: str
    attachments: Optional[List[bytes]] = None

@dataclass
class DatabaseHandle:
    """Opaque handle for the database connection, C-style."""
    connection: Optional[Any] = None # Represents sqlite3.Connection

