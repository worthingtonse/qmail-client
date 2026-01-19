"""
task_manager.py - Task Manager Module for QMail Client Core

This module provides a thread-safe task registry for tracking asynchronous
operations. Tasks can be created, monitored, updated, and cancelled.

Author: Claude Opus 4.5
Phase: I
Version: 1.1.0

Changes in v1.1.0:
    - Added _copy_status() helper to reduce code duplication
    - Added cancellation token (threading.Event) for worker signaling
    - Added result size validation with warning
    - Improved callback exception handling with stack traces
    - Added timezone-aware timestamps (UTC)
    - Documented auto-start behavior in update_task_progress

Features:
    - Thread-safe task registry with mutex protection
    - UUID-based task identification
    - Progress tracking (0-100%)
    - Task lifecycle management (create, run, complete, fail, cancel)
    - Timestamp tracking for all state transitions (UTC)
    - Optional callback support for task completion
    - Cancellation tokens for cooperative task cancellation

State Machine:
    PENDING → RUNNING → COMPLETED
                     ↘ FAILED
    PENDING → CANCELLED
    RUNNING → CANCELLED

Thread Safety:
    - All public functions are thread-safe via mutex protection
    - Status copies returned to prevent external modification
    - Callbacks invoked outside lock (prevents deadlocks)
    - Callbacks may be invoked concurrently

C Notes:
    - Use pthread_mutex_t on Unix, CRITICAL_SECTION on Win32
    - Task registry: hash table (recommend uthash library)
    - UUID generation: platform-specific or counter + timestamp
    - Callbacks: function pointers with void* user_data
    - Cancellation: use pthread_cond_t or Win32 Event
"""

import threading
import uuid
import hashlib
import time
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import IntEnum
import os
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import from qmail_types
try:
    from qmail_types import TaskStatus, TaskState, ErrorCode
except ImportError:
    # Fallback for standalone testing
    class TaskState(IntEnum):
        PENDING = 0
        RUNNING = 1
        COMPLETED = 2
        FAILED = 3
        CANCELLED = 4

    class ErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_PARAM = 1
        ERR_NOT_FOUND = 2
        ERR_ALREADY_EXISTS = 3
        ERR_INTERNAL = 9

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
TASK_CONTEXT = "TaskManager"

# Task state strings (match TaskStatus.state field)
STATE_PENDING = "PENDING"
STATE_RUNNING = "RUNNING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
STATE_CANCELLED = "CANCELLED"

# Maximum tasks to keep in history (prevents memory leak)
MAX_TASK_HISTORY = 1000

# Default cleanup age for completed tasks (seconds)
DEFAULT_CLEANUP_AGE_SECONDS = 3600  # 1 hour

# Progress range constants
PROGRESS_MIN = 0
PROGRESS_MAX = 100

# Result size warning threshold (bytes)
# Results larger than this will trigger a warning log
MAX_RESULT_SIZE_WARNING = 1 * 1024 * 1024  # 1 MB


# ============================================================================
# ERROR CODES
# ============================================================================

class TaskErrorCode(IntEnum):
    """
    Error codes for task manager operations.
    C: typedef enum { TASK_SUCCESS = 0, ... } TaskErrorCode;
    """
    SUCCESS = 0
    ERR_NOT_FOUND = 1
    ERR_INVALID_STATE = 2
    ERR_ALREADY_FINISHED = 3
    ERR_INVALID_PARAM = 4
    ERR_REGISTRY_FULL = 5


# ============================================================================
# DATA STRUCTURES
# ============================================================================

# Callback type for task completion notifications
# C: typedef void (*TaskCallback)(const char* task_id, TaskStatus* status, void* user_data);
TaskCallback = Callable[[str, TaskStatus], None]


@dataclass
class TaskEntry:
    """
    Internal task entry with additional metadata.
    C: typedef struct TaskEntry { ... } TaskEntry;

    The cancel_event can be used by workers to check if cancellation was requested:
        if entry.cancel_event.is_set():
            return  # Stop work immediately
    """
    status: TaskStatus
    task_type: str = ""                     # Type identifier (e.g., "upload", "download")
    params: Dict[str, Any] = field(default_factory=dict)
    callback: Optional[TaskCallback] = None
    callback_on_error: bool = True          # Call callback on failure too
    cancel_event: threading.Event = field(default_factory=threading.Event)  # Cancellation signal


@dataclass
class TaskManagerHandle:
    """
    Task manager instance handle.
    C: typedef struct TaskManagerHandle { ... } TaskManagerHandle;
    """
    tasks: Dict[str, TaskEntry] = field(default_factory=dict)
    mutex: threading.Lock = field(default_factory=threading.Lock)
    max_history: int = MAX_TASK_HISTORY
    cleanup_age_seconds: int = DEFAULT_CLEANUP_AGE_SECONDS
    logger_handle: Optional[object] = None


# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

def _get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO format.

    Uses UTC for consistency across timezones and DST transitions.

    C signature: void get_timestamp(char* buffer, size_t buffer_size);
    """
    return datetime.now(timezone.utc).isoformat()


def _generate_task_id() -> str:
    """
    Generate unique task ID.

    C signature: void generate_task_id(char* buffer, size_t buffer_size);
    """
    return str(uuid.uuid4())


def _state_to_string(state: TaskState) -> str:
    """
    Convert TaskState enum to string.

    C signature: const char* state_to_string(TaskState state);
    """
    mapping = {
        TaskState.PENDING: STATE_PENDING,
        TaskState.RUNNING: STATE_RUNNING,
        TaskState.COMPLETED: STATE_COMPLETED,
        TaskState.FAILED: STATE_FAILED,
        TaskState.CANCELLED: STATE_CANCELLED,
    }
    return mapping.get(state, STATE_PENDING)


def _is_terminal_state(state: str) -> bool:
    """
    Check if state is terminal (no further transitions allowed).

    C signature: bool is_terminal_state(const char* state);
    """
    return state in (STATE_COMPLETED, STATE_FAILED, STATE_CANCELLED)


def _copy_status(status: TaskStatus) -> TaskStatus:
    """
    Create a copy of TaskStatus to prevent external modification.

    C signature: void copy_task_status(const TaskStatus* src, TaskStatus* dst);

    Args:
        status: Source TaskStatus to copy

    Returns:
        New TaskStatus with same values
    """
    return TaskStatus(
        task_id=status.task_id,
        state=status.state,
        progress=status.progress,
        message=status.message,
        result=status.result,
        error=status.error,
        created_timestamp=status.created_timestamp,
        started_timestamp=status.started_timestamp,
        completed_timestamp=status.completed_timestamp
    )


def _check_result_size(result: Any, logger_handle: Optional[object] = None) -> None:
    """
    Check if result is larger than recommended and log warning.

    C signature: void check_result_size(const void* result, size_t size);

    Args:
        result: Result object to check
        logger_handle: Optional logger handle
    """
    if result is None:
        return

    try:
        result_size = sys.getsizeof(result)
        if result_size > MAX_RESULT_SIZE_WARNING:
            log_warning(logger_handle, TASK_CONTEXT,
                       f"Large task result ({result_size} bytes) - consider storing externally")
    except (TypeError, AttributeError):
        # Can't determine size, skip check
        pass


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def init_task_manager(
    max_history: Any = MAX_TASK_HISTORY,
    cleanup_age_seconds: int = DEFAULT_CLEANUP_AGE_SECONDS,
    logger_handle: Optional[object] = None
) -> TaskManagerHandle:
    """
    Initialize task manager with auto-detection for argument order.
    """
    # FIX: If max_history is NOT an integer, it means the logger was passed first.
    # We swap them automatically to prevent the crash.
    if not isinstance(max_history, int):
        # We assume the first argument was actually the logger
        real_logger = max_history
        real_max_history = MAX_TASK_HISTORY
        real_cleanup = cleanup_age_seconds
    else:
        real_logger = logger_handle
        real_max_history = max_history
        real_cleanup = cleanup_age_seconds

    handle = TaskManagerHandle(
        max_history=real_max_history,
        cleanup_age_seconds=real_cleanup,
        logger_handle=real_logger
    )

    log_debug(real_logger, TASK_CONTEXT,
              f"Task manager initialized (max_history={real_max_history})")

    return handle


def shutdown_task_manager(handle: TaskManagerHandle) -> None:
    """
    Shutdown task manager and clean up resources.

    Args:
        handle: Task manager handle

    C signature: void shutdown_task_manager(TaskManagerHandle* handle);
    """
    if handle is None:
        return

    with handle.mutex:
        task_count = len(handle.tasks)
        handle.tasks.clear()

    log_debug(handle.logger_handle, TASK_CONTEXT,
              f"Task manager shutdown (cleared {task_count} tasks)")


def create_task(
    handle: TaskManagerHandle,
    task_type: str,
    params: Optional[Dict[str, Any]] = None,
    message: str = "",
    callback: Optional[TaskCallback] = None
) -> Tuple[TaskErrorCode, str]:
    """
    Create a new task and add it to the registry.

    Args:
        handle: Task manager handle
        task_type: Type identifier (e.g., "upload", "download", "sync")
        params: Optional parameters for the task
        message: Initial status message
        callback: Optional callback for completion notification

    Returns:
        Tuple of (error code, task_id or empty string on error)

    C signature:
        TaskErrorCode create_task(TaskManagerHandle* handle,
                                  const char* task_type,
                                  const TaskParams* params,
                                  char* out_task_id);

    Example:
        err, task_id = create_task(handle, "upload", {"file_guid": guid})
        if err == TaskErrorCode.SUCCESS:
            print(f"Created task: {task_id}")
    """
    if handle is None:
        return TaskErrorCode.ERR_INVALID_PARAM, ""

    task_id = _generate_task_id()
    timestamp = _get_timestamp()

    status = TaskStatus(
        task_id=task_id,
        state=STATE_PENDING,
        progress=0,
        message=message or f"Task {task_type} created",
        created_timestamp=timestamp
    )

    entry = TaskEntry(
        status=status,
        task_type=task_type,
        params=params or {},
        callback=callback
    )

    with handle.mutex:
        # Check capacity
        # print(f"!!! DEBUG: create_task checking limit. Max History: {handle.max_history} (Type: {type(handle.max_history)})")
        if len(handle.tasks) >= handle.max_history:
            # Try to clean up old completed tasks
            _cleanup_old_tasks_locked(handle)

            if len(handle.tasks) >= handle.max_history:
                log_warning(handle.logger_handle, TASK_CONTEXT,
                           f"Task registry full ({handle.max_history} tasks)")
                return TaskErrorCode.ERR_REGISTRY_FULL, ""

        handle.tasks[task_id] = entry

    log_debug(handle.logger_handle, TASK_CONTEXT,
              f"Created task {task_id[:8]}... type={task_type}")

    return TaskErrorCode.SUCCESS, task_id


def get_task_status(
    handle: TaskManagerHandle,
    task_id: str
) -> Tuple[TaskErrorCode, Optional[TaskStatus]]:
    """
    Get current status of a task.

    Args:
        handle: Task manager handle
        task_id: Task identifier

    Returns:
        Tuple of (error code, TaskStatus or None)

    C signature:
        TaskErrorCode get_task_status(TaskManagerHandle* handle,
                                      const char* task_id,
                                      TaskStatus* out_status);

    Example:
        err, status = get_task_status(handle, task_id)
        if err == TaskErrorCode.SUCCESS:
            print(f"Progress: {status.progress}%")
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM, None

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND, None

        # Return a copy to prevent external modification
        status = _copy_status(entry.status)

    return TaskErrorCode.SUCCESS, status


def start_task(
    handle: TaskManagerHandle,
    task_id: str,
    message: str = ""
) -> TaskErrorCode:
    """
    Mark a task as running.

    Args:
        handle: Task manager handle
        task_id: Task identifier
        message: Optional status message

    Returns:
        Error code

    C signature:
        TaskErrorCode start_task(TaskManagerHandle* handle,
                                 const char* task_id,
                                 const char* message);
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if entry.status.state != STATE_PENDING:
            return TaskErrorCode.ERR_INVALID_STATE

        entry.status.state = STATE_RUNNING
        entry.status.started_timestamp = _get_timestamp()
        if message:
            entry.status.message = message

    log_debug(handle.logger_handle, TASK_CONTEXT,
              f"Started task {task_id[:8]}...")

    return TaskErrorCode.SUCCESS


def update_task_progress(
    handle: TaskManagerHandle,
    task_id: str,
    progress: int,
    message: str = ""
) -> TaskErrorCode:
    """
    Update task progress.

    Note: If task is still PENDING, it will be automatically transitioned
    to RUNNING state. This allows workers to skip explicit start_task() calls.

    Args:
        handle: Task manager handle
        task_id: Task identifier
        progress: Progress percentage (0-100), clamped to valid range
        message: Optional status message

    Returns:
        Error code

    C signature:
        TaskErrorCode update_task_progress(TaskManagerHandle* handle,
                                           const char* task_id,
                                           int progress,
                                           const char* message);

    Example:
        for i in range(0, 101, 10):
            update_task_progress(handle, task_id, i, f"Processing {i}%")
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    # Clamp progress to valid range
    progress = max(PROGRESS_MIN, min(PROGRESS_MAX, progress))

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if _is_terminal_state(entry.status.state):
            return TaskErrorCode.ERR_ALREADY_FINISHED

        # Auto-start if still pending (documented behavior)
        if entry.status.state == STATE_PENDING:
            entry.status.state = STATE_RUNNING
            entry.status.started_timestamp = _get_timestamp()

        entry.status.progress = progress
        if message:
            entry.status.message = message

    return TaskErrorCode.SUCCESS


def complete_task(
    handle: TaskManagerHandle,
    task_id: str,
    result: Any = None,
    message: str = ""
) -> TaskErrorCode:
    """
    Mark a task as completed successfully.

    Args:
        handle: Task manager handle
        task_id: Task identifier
        result: Optional result data (warning logged if > 1MB)
        message: Optional completion message

    Returns:
        Error code

    C signature:
        TaskErrorCode complete_task(TaskManagerHandle* handle,
                                    const char* task_id,
                                    void* result,
                                    const char* message);

    Example:
        complete_task(handle, task_id, {"bytes_sent": 1024}, "Upload complete")
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    # Check result size (warn if large)
    _check_result_size(result, handle.logger_handle)

    callback = None
    status_copy = None

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if _is_terminal_state(entry.status.state):
            return TaskErrorCode.ERR_ALREADY_FINISHED

        entry.status.state = STATE_COMPLETED
        entry.status.progress = PROGRESS_MAX
        entry.status.result = result
        entry.status.completed_timestamp = _get_timestamp()
        if message:
            entry.status.message = message
        else:
            entry.status.message = "Task completed successfully"

        # Prepare callback (call outside lock)
        if entry.callback:
            callback = entry.callback
            status_copy = _copy_status(entry.status)

    log_debug(handle.logger_handle, TASK_CONTEXT,
              f"Completed task {task_id[:8]}...")

    # Invoke callback outside lock
    if callback and status_copy:
        try:
            callback(task_id, status_copy)
        except Exception as e:
            # Log full stack trace for debugging
            log_warning(handle.logger_handle, TASK_CONTEXT,
                       f"Task callback failed: {e}\n{traceback.format_exc()}")

    return TaskErrorCode.SUCCESS


def fail_task(
    handle: TaskManagerHandle,
    task_id: str,
    error: str,
    message: str = ""
) -> TaskErrorCode:
    """
    Mark a task as failed.

    Args:
        handle: Task manager handle
        task_id: Task identifier
        error: Error description
        message: Optional status message

    Returns:
        Error code

    C signature:
        TaskErrorCode fail_task(TaskManagerHandle* handle,
                                const char* task_id,
                                const char* error,
                                const char* message);

    Example:
        fail_task(handle, task_id, "Connection timeout", "Upload failed")
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    callback = None
    status_copy = None

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if _is_terminal_state(entry.status.state):
            return TaskErrorCode.ERR_ALREADY_FINISHED

        entry.status.state = STATE_FAILED
        entry.status.error = error
        entry.status.completed_timestamp = _get_timestamp()
        if message:
            entry.status.message = message
        else:
            entry.status.message = f"Task failed: {error}"

        # Prepare callback (call outside lock)
        if entry.callback and entry.callback_on_error:
            callback = entry.callback
            status_copy = _copy_status(entry.status)

    log_warning(handle.logger_handle, TASK_CONTEXT,
                f"Failed task {task_id[:8]}...: {error}")

    # Invoke callback outside lock
    if callback and status_copy:
        try:
            callback(task_id, status_copy)
        except Exception as e:
            # Log full stack trace for debugging
            log_warning(handle.logger_handle, TASK_CONTEXT,
                       f"Task callback failed: {e}\n{traceback.format_exc()}")

    return TaskErrorCode.SUCCESS


def cancel_task(
    handle: TaskManagerHandle,
    task_id: str,
    message: str = ""
) -> TaskErrorCode:
    """
    Cancel a task and signal workers to stop.

    Sets the task's cancel_event, which workers can check to stop work:
        event = get_cancel_event(handle, task_id)
        if event and event.is_set():
            return  # Stop work

    Args:
        handle: Task manager handle
        task_id: Task identifier
        message: Optional cancellation message

    Returns:
        Error code (SUCCESS if cancelled, ERR_ALREADY_FINISHED if already done)

    C signature:
        TaskErrorCode cancel_task(TaskManagerHandle* handle,
                                  const char* task_id,
                                  const char* message);

    Example:
        err = cancel_task(handle, task_id, "User requested cancellation")
        if err == TaskErrorCode.SUCCESS:
            print("Task cancelled")
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if _is_terminal_state(entry.status.state):
            return TaskErrorCode.ERR_ALREADY_FINISHED

        # Signal workers to stop
        entry.cancel_event.set()

        entry.status.state = STATE_CANCELLED
        entry.status.completed_timestamp = _get_timestamp()
        if message:
            entry.status.message = message
        else:
            entry.status.message = "Task cancelled"

    log_info(handle.logger_handle, TASK_CONTEXT,
             f"Cancelled task {task_id[:8]}...")

    return TaskErrorCode.SUCCESS


def list_active_tasks(
    handle: TaskManagerHandle
) -> Tuple[TaskErrorCode, List[TaskStatus]]:
    """
    List all active (non-finished) tasks.

    Args:
        handle: Task manager handle

    Returns:
        Tuple of (error code, list of TaskStatus)

    C signature:
        TaskErrorCode list_active_tasks(TaskManagerHandle* handle,
                                        TaskStatus** out_tasks,
                                        int* out_count);

    Example:
        err, tasks = list_active_tasks(handle)
        for task in tasks:
            print(f"{task.task_id}: {task.state} ({task.progress}%)")
    """
    if handle is None:
        return TaskErrorCode.ERR_INVALID_PARAM, []

    active_tasks = []

    with handle.mutex:
        for entry in handle.tasks.values():
            if not _is_terminal_state(entry.status.state):
                # Return copies to prevent external modification
                active_tasks.append(_copy_status(entry.status))

    return TaskErrorCode.SUCCESS, active_tasks


def list_all_tasks(
    handle: TaskManagerHandle,
    include_finished: bool = True
) -> Tuple[TaskErrorCode, List[TaskStatus]]:
    """
    List all tasks, optionally including finished ones.

    Args:
        handle: Task manager handle
        include_finished: Whether to include completed/failed/cancelled tasks

    Returns:
        Tuple of (error code, list of TaskStatus)

    C signature:
        TaskErrorCode list_all_tasks(TaskManagerHandle* handle,
                                     bool include_finished,
                                     TaskStatus** out_tasks,
                                     int* out_count);
    """
    if handle is None:
        return TaskErrorCode.ERR_INVALID_PARAM, []

    tasks = []

    with handle.mutex:
        for entry in handle.tasks.values():
            if include_finished or not _is_terminal_state(entry.status.state):
                # Return copies to prevent external modification
                tasks.append(_copy_status(entry.status))

    return TaskErrorCode.SUCCESS, tasks


def get_task_count(
    handle: TaskManagerHandle,
    active_only: bool = False
) -> Tuple[TaskErrorCode, int]:
    """
    Get count of tasks in registry.

    Args:
        handle: Task manager handle
        active_only: If True, count only non-finished tasks

    Returns:
        Tuple of (error code, count)

    C signature:
        TaskErrorCode get_task_count(TaskManagerHandle* handle,
                                     bool active_only,
                                     int* out_count);
    """
    if handle is None:
        return TaskErrorCode.ERR_INVALID_PARAM, 0

    with handle.mutex:
        if active_only:
            count = sum(1 for e in handle.tasks.values()
                       if not _is_terminal_state(e.status.state))
        else:
            count = len(handle.tasks)

    return TaskErrorCode.SUCCESS, count


def cleanup_finished_tasks(
    handle: TaskManagerHandle,
    max_age_seconds: Optional[int] = None
) -> Tuple[TaskErrorCode, int]:
    """
    Remove finished tasks older than specified age.

    Args:
        handle: Task manager handle
        max_age_seconds: Remove tasks older than this (uses default if None)

    Returns:
        Tuple of (error code, number of tasks removed)

    C signature:
        TaskErrorCode cleanup_finished_tasks(TaskManagerHandle* handle,
                                             int max_age_seconds,
                                             int* out_removed_count);
    """
    if handle is None:
        return TaskErrorCode.ERR_INVALID_PARAM, 0

    max_age = max_age_seconds if max_age_seconds is not None else handle.cleanup_age_seconds

    with handle.mutex:
        removed = _cleanup_old_tasks_locked(handle, max_age)

    if removed > 0:
        log_debug(handle.logger_handle, TASK_CONTEXT,
                  f"Cleaned up {removed} finished tasks")

    return TaskErrorCode.SUCCESS, removed


def _cleanup_old_tasks_locked(
    handle: TaskManagerHandle,
    max_age_seconds: Optional[int] = None
) -> int:
    """
    Internal cleanup function (must be called with mutex held).

    C signature: int cleanup_old_tasks_locked(TaskManagerHandle* handle, int max_age_seconds);

    Returns:
        Number of tasks removed
    """
    if max_age_seconds is None:
        max_age_seconds = handle.cleanup_age_seconds

    now = datetime.now(timezone.utc)
    to_remove = []

    for task_id, entry in handle.tasks.items():
        if not _is_terminal_state(entry.status.state):
            continue

        # Check age
        if entry.status.completed_timestamp:
            try:
                completed = datetime.fromisoformat(entry.status.completed_timestamp)
                # Handle both timezone-aware and naive timestamps
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                age = (now - completed).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(task_id)
            except (ValueError, TypeError):
                # Invalid timestamp, remove it
                to_remove.append(task_id)

    for task_id in to_remove:
        del handle.tasks[task_id]

    return len(to_remove)


def delete_task(
    handle: TaskManagerHandle,
    task_id: str
) -> TaskErrorCode:
    """
    Delete a task from the registry (only finished tasks can be deleted).

    Args:
        handle: Task manager handle
        task_id: Task identifier

    Returns:
        Error code

    C signature:
        TaskErrorCode delete_task(TaskManagerHandle* handle,
                                  const char* task_id);
    """
    if handle is None or not task_id:
        return TaskErrorCode.ERR_INVALID_PARAM

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return TaskErrorCode.ERR_NOT_FOUND

        if not _is_terminal_state(entry.status.state):
            return TaskErrorCode.ERR_INVALID_STATE

        del handle.tasks[task_id]

    log_debug(handle.logger_handle, TASK_CONTEXT,
              f"Deleted task {task_id[:8]}...")

    return TaskErrorCode.SUCCESS


def get_cancel_event(
    handle: TaskManagerHandle,
    task_id: str
) -> Optional[threading.Event]:
    """
    Get the cancellation event for a task.

    Workers should check this event periodically to support cooperative cancellation:
        event = get_cancel_event(handle, task_id)
        for chunk in data:
            if event and event.is_set():
                return  # Stop work, task was cancelled
            process(chunk)

    Args:
        handle: Task manager handle
        task_id: Task identifier

    Returns:
        threading.Event or None if task not found

    C signature:
        void* get_cancel_event(TaskManagerHandle* handle, const char* task_id);
        // Returns platform-specific event (pthread_cond_t* or HANDLE)
    """
    if handle is None or not task_id:
        return None

    with handle.mutex:
        entry = handle.tasks.get(task_id)
        if entry is None:
            return None
        return entry.cancel_event


def is_task_cancelled(
    handle: TaskManagerHandle,
    task_id: str
) -> bool:
    """
    Check if a task has been cancelled.

    Convenience function for workers to check cancellation status:
        if is_task_cancelled(handle, task_id):
            return  # Stop work

    Args:
        handle: Task manager handle
        task_id: Task identifier

    Returns:
        True if task was cancelled, False otherwise

    C signature:
        bool is_task_cancelled(TaskManagerHandle* handle, const char* task_id);
    """
    event = get_cancel_event(handle, task_id)
    return event is not None and event.is_set()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def run_with_task(
    handle: TaskManagerHandle,
    task_type: str,
    func: Callable[..., Any],
    *args,
    params: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Tuple[TaskErrorCode, str, Any]:
    """
    Run a function wrapped in task tracking.

    Creates a task, runs the function, and completes/fails the task based
    on the result. Useful for simple synchronous operations.

    Args:
        handle: Task manager handle
        task_type: Type identifier for the task
        func: Function to execute
        *args: Arguments to pass to function
        params: Optional task parameters for tracking
        **kwargs: Keyword arguments to pass to function

    Returns:
        Tuple of (error code, task_id, function result or None)

    Example:
        def upload_file(path):
            # ... upload logic ...
            return {"bytes": 1024}

        err, task_id, result = run_with_task(handle, "upload", upload_file, "/path/to/file")
    """
    # Create task
    err, task_id = create_task(handle, task_type, params)
    if err != TaskErrorCode.SUCCESS:
        return err, "", None

    # Start task
    start_task(handle, task_id)

    try:
        result = func(*args, **kwargs)
        complete_task(handle, task_id, result)
        return TaskErrorCode.SUCCESS, task_id, result
    except Exception as e:
        fail_task(handle, task_id, str(e))
        return TaskErrorCode.SUCCESS, task_id, None
    
def _encode_pown_bytes(pown_string: str) -> bytes:
    """
    Helper: Converts a 25-char 'ppfff...' string into 13 bytes (25 nibbles).
    Used by write_coin_file to populate Byte 16.
    """
    res = bytearray(13)
    # Mapping: p=1, f=0, u=2
    val_map = {'p': 1, 'f': 0, 'u': 2}
    
    for i in range(25):
        char = pown_string[i].lower()
        val = val_map.get(char, 2)
        byte_idx = i // 2
        if i % 2 == 0:
            res[byte_idx] |= (val << 4)  # High nibble
        else:
            res[byte_idx] |= (val & 0x0F) # Low nibble
    return bytes(res)

def stake_locker_identity(locker_code_bytes, app_context, target_wallet="Mailbox", logger=None):
    """
    FULL STAKING: Downloads identity from RAIDA and saves using Stable Naming.
    Aligned with cmd_locker.c and your write_coin_file logic.
    """
    from src.protocol import build_complete_locker_download_request, ProtocolErrorCode

    # Convert bytes to string if needed - preserve case for Go compatibility
    if isinstance(locker_code_bytes, bytes):
        locker_code_str = locker_code_bytes.decode('ascii', errors='ignore').strip()
    else:
        locker_code_str = str(locker_code_bytes).strip()

    log_info(logger, "Staking", f"Staking coins into {target_wallet} wallet via Command 8...")
    log_debug(logger, "Staking", f"Locker code: {locker_code_str}")

    # Hardcoded RAIDA IP addresses as fallback (from config.py)
    RAIDA_IPS_FALLBACK = [
        "78.46.170.45",      # RAIDA 0
        "47.229.9.94",       # RAIDA 1
        "209.46.126.167",    # RAIDA 2
        "116.203.157.233",   # RAIDA 3
        "95.183.51.104",     # RAIDA 4
        "31.163.201.90",     # RAIDA 5
        "52.14.83.91",       # RAIDA 6
        "161.97.169.229",    # RAIDA 7
        "13.234.55.11",      # RAIDA 8
        "124.187.106.233",   # RAIDA 9
        "94.130.179.247",    # RAIDA 10
        "67.181.90.11",      # RAIDA 11
        "3.16.169.178",      # RAIDA 12
        "113.30.247.109",    # RAIDA 13
        "168.220.219.199",   # RAIDA 14
        "185.37.61.73",      # RAIDA 15
        "193.7.195.250",     # RAIDA 16
        "5.161.63.179",      # RAIDA 17
        "76.114.47.144",     # RAIDA 18
        "190.105.235.113",   # RAIDA 19
        "184.18.166.118",    # RAIDA 20
        "125.236.210.184",   # RAIDA 21
        "5.161.123.254",     # RAIDA 22
        "130.255.77.156",    # RAIDA 23
        "209.205.66.24",     # RAIDA 24
    ]

    seeds = {}
    responses = {}

    # 2. Parallel Network Requests (Command 8)
    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_raida = {}
        servers_used = 0

        for raida_id in range(25):
            # Try app_context first, then use fallback hardcoded IPs
            ip = None
            if app_context:
                ip = app_context.get_server_ip(raida_id)

            if not ip:
                # Fallback to hardcoded IPs
                ip = RAIDA_IPS_FALLBACK[raida_id]
                log_debug(logger, "Staking", f"RAIDA {raida_id}: Using fallback IP {ip}")
            else:
                log_debug(logger, "Staking", f"RAIDA {raida_id}: Using cached IP {ip}")

            servers_used += 1

            # Seed required for AN derivation formula in cmd_locker.c
            seed = os.urandom(16)
            seeds[raida_id] = seed

            srv_cfg = type('Srv', (), {'host': ip, 'port': 50000 + raida_id, 'raida_id': raida_id})()

            # build_complete_locker_download_request takes the locker code string
            # and derives the key internally: MD5(raida_id + locker_code_str) + 0xFFFFFFFF
            err_p, packet, _, _ = build_complete_locker_download_request(
                raida_id=raida_id,
                locker_code_str=locker_code_str,
                seed=seed,
                logger_handle=logger
            )

            if err_p != ProtocolErrorCode.SUCCESS:
                log_warning(logger, "Staking", f"RAIDA {raida_id}: Failed to build request packet")
                continue

            # Note: execute_single_stake remains as you defined it earlier
            future = executor.submit(execute_single_stake, srv_cfg, packet, logger, raida_id)
            future_to_raida[future] = raida_id

        log_info(logger, "Staking", f"Sending requests to {servers_used} RAIDA servers...")

        success_count = 0
        error_count = 0
        for future in as_completed(future_to_raida):
            try:
                rid = future_to_raida[future]
                err, coins_found = future.result(timeout=5.0)
                if err == 0 and coins_found:
                    responses[rid] = coins_found
                    success_count += 1
                    log_debug(logger, "Staking", f"RAIDA {rid}: Found {len(coins_found)} coins")
                else:
                    error_count += 1
                    if err != 0:
                        log_debug(logger, "Staking", f"RAIDA {rid}: Error {err}")
            except Exception as e:
                error_count += 1
                log_warning(logger, "Staking", f"RAIDA {future_to_raida.get(future, '?')}: Exception {e}")
                continue

        log_info(logger, "Staking", f"Results: {success_count} success, {error_count} errors")

    if not responses:
        log_error(logger, "Staking", "Consensus failed: Locker is empty or all servers failed.")
        return False

    # 3. Identify Unique Coins (DN, SN pairs)
    all_coin_keys = set()
    for coin_list in responses.values():
        for dn, sn in coin_list:
            all_coin_keys.add((dn, sn))

    bank_path = f"Data/Wallets/{target_wallet}/Bank"
    os.makedirs(bank_path, exist_ok=True)

    # 4. Reconstruct ANs and Write Files
    for dn, sn in all_coin_keys:
        calculated_ans = []
        for raida_id in range(25):
            if raida_id in seeds:
                # AN Formula: MD5( Denom(1) + SN(4) + Seed(16) )
                binary_input = struct.pack(">B", dn) + struct.pack(">I", sn) + seeds[raida_id]
                digest = bytearray(hashlib.md5(binary_input).digest())
                
                # --- MANDATORY TAIL (cmd_locker.c line 191) ---
                # RAIDA isko future payments ke liye "Passport" maanta hai
                digest[12:16] = b'\xff\xff\xff\xff'
                calculated_ans.append(digest) # Store as raw bytes
            else:
                calculated_ans.append(bytes(16))

        # Build coin object for write_coin_file
        # It must have: denomination, serial_number, ans, pown_string
        coin_obj = type('Coin', (), {
            'denomination': dn,
            'serial_number': sn,
            'ans': calculated_ans,
            'pown_string': 'p' * 25  # All passed since we just downloaded them
        })()

        # STABLE NAMING: DN.SN.bin (e.g., 1.9572.bin)
        filename = f"{dn}.{sn}.bin"
        save_path = os.path.join(bank_path, filename)
        
        # Call your fixed write_coin_file
        from src.cloudcoin import write_coin_file
        write_coin_file(save_path, coin_obj, logger)
        
        log_info(logger, "Staking", f"✓ Reconstructed Stable Identity: {filename}")

    return True

def execute_single_stake(srv_cfg, packet, logger, raida_id=None):
    """Network worker for Command 8"""
    from src.network import connect_to_server, disconnect, send_raw_request
    from src.protocol import parse_locker_download_response

    rid_str = f"RAIDA {raida_id}" if raida_id is not None else "RAIDA ?"

    try:
        conn_err, conn = connect_to_server(srv_cfg)
        if conn_err != 0:
            log_info(logger, "Staking", f"{rid_str}: Connection failed (error {conn_err})")
            return 1, None

        # Aggressive timeout for responsive staking
        net_err, resp_h, resp_b = send_raw_request(conn, packet, timeout_ms=5000, logger_handle=logger)
        disconnect(conn)

        if net_err != 0:
            log_info(logger, "Staking", f"{rid_str}: Network error {net_err}")
            return 2, None

        if resp_h is None:
            log_info(logger, "Staking", f"{rid_str}: No response header")
            return 3, None

        # FIX: Accept both 250 (OK) and 241 (ALL_PASS) as success
        # RAIDA uses 241 to mean "Validation Passed & Coins Returned"
        if resp_h.status == 250 or resp_h.status == 241:
            err, coins = parse_locker_download_response(resp_b, logger)
            if err == 0:
                log_info(logger, "Staking", f"{rid_str}: Status {resp_h.status}, found {len(coins) if coins else 0} coins")
            return err, coins
        else:
            # Log the actual status for debugging (INFO level so user can see)
            status_meaning = {
                251: "Locker not found/empty",
                252: "Invalid key",
                253: "Locker expired",
                200: "OK but no coins",
                241: "All Checks Passed" 
            }.get(resp_h.status, f"Unknown status")
            log_info(logger, "Staking", f"{rid_str}: Status {resp_h.status} ({status_meaning})")
            return 4, None

    except Exception as e:
        log_warning(logger, "Staking", f"{rid_str}: Exception: {e}")
        return 5, None
# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the task manager module.
    """
    print("=" * 60)
    print("task_manager.py - Test Suite")
    print("=" * 60)

    # Test 1: Initialize task manager
    print("\n1. Testing init_task_manager()...")
    handle = init_task_manager(max_history=100)
    assert handle is not None
    assert handle.max_history == 100
    print("   SUCCESS: Task manager initialized")

    # Test 2: Create task
    print("\n2. Testing create_task()...")
    err, task_id = create_task(handle, "upload", {"file": "test.txt"}, "Uploading test file")
    assert err == TaskErrorCode.SUCCESS
    assert len(task_id) == 36  # UUID format
    print(f"   Created task: {task_id[:8]}...")
    print("   SUCCESS: Task created")

    # Test 3: Get task status
    print("\n3. Testing get_task_status()...")
    err, status = get_task_status(handle, task_id)
    assert err == TaskErrorCode.SUCCESS
    assert status.state == STATE_PENDING
    assert status.progress == 0
    print(f"   State: {status.state}, Progress: {status.progress}%")
    print("   SUCCESS: Task status retrieved")

    # Test 4: Start task
    print("\n4. Testing start_task()...")
    err = start_task(handle, task_id, "Starting upload...")
    assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id)
    assert status.state == STATE_RUNNING
    assert status.started_timestamp is not None
    print(f"   State: {status.state}, Started: {status.started_timestamp}")
    print("   SUCCESS: Task started")

    # Test 5: Update progress
    print("\n5. Testing update_task_progress()...")
    for pct in [25, 50, 75]:
        err = update_task_progress(handle, task_id, pct, f"Progress {pct}%")
        assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id)
    assert status.progress == 75
    print(f"   Progress: {status.progress}%")
    print("   SUCCESS: Progress updated")

    # Test 6: Complete task
    print("\n6. Testing complete_task()...")
    err = complete_task(handle, task_id, {"bytes_sent": 1024}, "Upload complete")
    assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id)
    assert status.state == STATE_COMPLETED
    assert status.progress == 100
    assert status.result == {"bytes_sent": 1024}
    assert status.is_finished
    assert status.is_successful
    print(f"   State: {status.state}, Result: {status.result}")
    print("   SUCCESS: Task completed")

    # Test 7: Cannot update completed task
    print("\n7. Testing state protection...")
    err = update_task_progress(handle, task_id, 50)
    assert err == TaskErrorCode.ERR_ALREADY_FINISHED
    print("   SUCCESS: Cannot modify finished task")

    # Test 8: Create and fail task
    print("\n8. Testing fail_task()...")
    err, task_id2 = create_task(handle, "download", {}, "Downloading...")
    start_task(handle, task_id2)
    err = fail_task(handle, task_id2, "Connection timeout", "Download failed")
    assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id2)
    assert status.state == STATE_FAILED
    assert status.error == "Connection timeout"
    assert status.is_finished
    assert not status.is_successful
    print(f"   State: {status.state}, Error: {status.error}")
    print("   SUCCESS: Task failed correctly")

    # Test 9: Create and cancel task
    print("\n9. Testing cancel_task()...")
    err, task_id3 = create_task(handle, "sync", {}, "Syncing...")
    start_task(handle, task_id3)
    update_task_progress(handle, task_id3, 30)
    err = cancel_task(handle, task_id3, "User cancelled")
    assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id3)
    assert status.state == STATE_CANCELLED
    print(f"   State: {status.state}")
    print("   SUCCESS: Task cancelled")

    # Test 10: List active tasks
    print("\n10. Testing list_active_tasks()...")
    err, task_id4 = create_task(handle, "pending_task", {})
    err, active = list_active_tasks(handle)
    assert err == TaskErrorCode.SUCCESS
    assert len(active) == 1  # Only the pending task
    assert active[0].task_id == task_id4
    print(f"   Active tasks: {len(active)}")
    print("   SUCCESS: Active tasks listed")

    # Test 11: List all tasks
    print("\n11. Testing list_all_tasks()...")
    err, all_tasks = list_all_tasks(handle)
    assert err == TaskErrorCode.SUCCESS
    assert len(all_tasks) == 4  # All 4 tasks we created
    print(f"   Total tasks: {len(all_tasks)}")
    print("   SUCCESS: All tasks listed")

    # Test 12: Get task count
    print("\n12. Testing get_task_count()...")
    err, total = get_task_count(handle)
    err, active_count = get_task_count(handle, active_only=True)
    assert total == 4
    assert active_count == 1
    print(f"   Total: {total}, Active: {active_count}")
    print("   SUCCESS: Task counts correct")

    # Test 13: Delete finished task
    print("\n13. Testing delete_task()...")
    err = delete_task(handle, task_id)  # The completed task
    assert err == TaskErrorCode.SUCCESS
    err, status = get_task_status(handle, task_id)
    assert err == TaskErrorCode.ERR_NOT_FOUND
    print("   SUCCESS: Finished task deleted")

    # Test 14: Cannot delete active task
    print("\n14. Testing delete protection...")
    err = delete_task(handle, task_id4)  # The pending task
    assert err == TaskErrorCode.ERR_INVALID_STATE
    print("   SUCCESS: Cannot delete active task")

    # Test 15: Callback on completion
    print("\n15. Testing callback on completion...")
    callback_called = [False]
    callback_status = [None]

    def on_complete(tid, status):
        callback_called[0] = True
        callback_status[0] = status

    err, task_id5 = create_task(handle, "callback_test", {}, callback=on_complete)
    start_task(handle, task_id5)
    complete_task(handle, task_id5, "done")
    assert callback_called[0]
    assert callback_status[0].state == STATE_COMPLETED
    print("   SUCCESS: Callback invoked on completion")

    # Test 16: run_with_task helper
    print("\n16. Testing run_with_task()...")

    def dummy_operation(x, y):
        return x + y

    err, task_id6, result = run_with_task(handle, "compute", dummy_operation, 10, 20)
    assert err == TaskErrorCode.SUCCESS
    assert result == 30
    err, status = get_task_status(handle, task_id6)
    assert status.state == STATE_COMPLETED
    print(f"   Result: {result}")
    print("   SUCCESS: run_with_task works")

    # Test 17: run_with_task with exception
    print("\n17. Testing run_with_task with exception...")

    def failing_operation():
        raise ValueError("Intentional error")

    err, task_id7, result = run_with_task(handle, "failing", failing_operation)
    assert err == TaskErrorCode.SUCCESS
    assert result is None
    err, status = get_task_status(handle, task_id7)
    assert status.state == STATE_FAILED
    assert "Intentional error" in status.error
    print(f"   Error captured: {status.error}")
    print("   SUCCESS: Exception handled correctly")

    # Test 18: Cleanup finished tasks
    print("\n18. Testing cleanup_finished_tasks()...")
    # Force cleanup of all finished tasks (0 seconds age)
    err, removed = cleanup_finished_tasks(handle, max_age_seconds=0)
    assert err == TaskErrorCode.SUCCESS
    err, total = get_task_count(handle)
    err, active = get_task_count(handle, active_only=True)
    print(f"   Removed: {removed}, Remaining: {total}, Active: {active}")
    assert total == active  # Only active tasks remain
    print("   SUCCESS: Finished tasks cleaned up")

    # Test 19: Thread safety (basic)
    print("\n19. Testing thread safety...")
    import concurrent.futures

    def create_many_tasks(n):
        for i in range(n):
            create_task(handle, f"thread_test_{i}", {})

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(create_many_tasks, 25) for _ in range(4)]
        concurrent.futures.wait(futures)

    err, total = get_task_count(handle)
    # Should have created 100 tasks (4 threads x 25 tasks each) plus the 1 active from before
    assert total >= 100
    print(f"   Created {total} tasks from 4 threads")
    print("   SUCCESS: Thread safety verified")

    # Test 20: Cancellation token
    print("\n20. Testing cancellation token...")
    handle = init_task_manager(max_history=100)  # Fresh handle
    err, cancel_task_id = create_task(handle, "long_running", {})
    start_task(handle, cancel_task_id)

    # Get cancel event before cancellation
    event = get_cancel_event(handle, cancel_task_id)
    assert event is not None
    assert not event.is_set()
    assert not is_task_cancelled(handle, cancel_task_id)

    # Cancel and verify event is set
    cancel_task(handle, cancel_task_id, "User cancelled")
    assert event.is_set()
    assert is_task_cancelled(handle, cancel_task_id)
    print("   SUCCESS: Cancellation token works")

    # Test 21: UTC timestamps
    print("\n21. Testing UTC timestamps...")
    err, task_id_utc = create_task(handle, "utc_test", {})
    err, status = get_task_status(handle, task_id_utc)
    assert status.created_timestamp is not None
    assert "+00:00" in status.created_timestamp or "Z" in status.created_timestamp
    print(f"   Created timestamp: {status.created_timestamp}")
    print("   SUCCESS: UTC timestamps used")

    # Test 22: _copy_status helper
    print("\n22. Testing _copy_status helper...")
    original = TaskStatus(
        task_id="test-id",
        state=STATE_RUNNING,
        progress=50,
        message="Test message"
    )
    copied = _copy_status(original)
    assert copied.task_id == original.task_id
    assert copied.state == original.state
    assert copied.progress == original.progress
    # Verify it's a copy, not same object
    copied.progress = 100
    assert original.progress == 50
    print("   SUCCESS: _copy_status creates independent copy")

    # Test 23: Shutdown
    print("\n23. Testing shutdown_task_manager()...")
    shutdown_task_manager(handle)
    err, total = get_task_count(handle)
    assert total == 0
    print("   SUCCESS: Task manager shutdown")

    print("\n" + "=" * 60)
    print("All task manager tests passed! (v1.1.0)")
    print("=" * 60)
