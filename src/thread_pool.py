"""
thread_pool.py - Thread Pool Module for QMail Client Core

This module provides a C-portable thread pool abstraction for managing
worker threads and parallel task execution.

Author: Claude Opus 4.5
Phase: I
Version: 1.1.0

Design Goals:
    - Simple, C-portable API
    - Handle-based design (no global state)
    - Thread-safe statistics tracking
    - Graceful shutdown with task completion
    - Future-based result retrieval

C Notes:
    - Maps to pthreads on Unix, Windows threads on Win32
    - Work queue implemented with condition variables
    - Future handles track individual task completion
    - Pool stats use atomic counters in C

Usage:
    pool = create_pool(num_workers=4)
    future = submit_work(pool, my_function, (arg1, arg2))
    result = wait_for_result(future)
    destroy_pool(pool)
"""

import sys
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from datetime import datetime, timezone

# Python version check
PYTHON_39_PLUS = sys.version_info >= (3, 9)

# Import logger
try:
    from .logger import log_error, log_info, log_debug, log_warning
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
TP_CONTEXT = "ThreadPool"

# Default number of workers (typically CPU count)
DEFAULT_NUM_WORKERS = 4

# Maximum number of workers allowed
MAX_WORKERS = 64

# Default timeout for waiting on results (milliseconds)
DEFAULT_TIMEOUT_MS = 30000

# Shutdown timeout (seconds)
SHUTDOWN_TIMEOUT_SEC = 10.0

# Maximum queue size (prevents memory exhaustion)
MAX_QUEUE_SIZE = 10000

# Maximum completed futures to retain (cleanup threshold)
MAX_COMPLETED_FUTURES = 1000


# ============================================================================
# ERROR CODES
# ============================================================================

class ThreadPoolErrorCode(IntEnum):
    """
    Error codes for thread pool operations.
    C: typedef enum { TP_SUCCESS = 0, ... } ThreadPoolErrorCode;
    """
    SUCCESS = 0
    ERR_INVALID_PARAM = 1
    ERR_POOL_SHUTDOWN = 2
    ERR_POOL_FULL = 3
    ERR_TIMEOUT = 4
    ERR_TASK_FAILED = 5
    ERR_TASK_CANCELLED = 6
    ERR_ALREADY_SHUTDOWN = 7


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class PoolStats:
    """
    Statistics for a thread pool.

    C: typedef struct PoolStats {
           int num_workers;
           int active_workers;
           int pending_tasks;
           int completed_tasks;
           int failed_tasks;
           double uptime_seconds;
       } PoolStats;
    """
    num_workers: int = 0           # Total worker threads
    active_workers: int = 0        # Currently executing tasks
    pending_tasks: int = 0         # Tasks waiting in queue
    completed_tasks: int = 0       # Successfully completed tasks
    failed_tasks: int = 0          # Tasks that raised exceptions
    cancelled_tasks: int = 0       # Tasks that were cancelled
    uptime_seconds: float = 0.0    # Time since pool creation


@dataclass
class FutureHandle:
    """
    Handle to a submitted task's future result.

    C: typedef struct FutureHandle {
           int task_id;
           void* internal_future;
           bool completed;
           bool cancelled;
       } FutureHandle;
    """
    task_id: int                           # Unique task identifier
    future: Future                         # Python Future object
    submitted_time: str = ""               # ISO timestamp
    function_name: str = ""                # Name of submitted function
    completed: bool = False                # Whether task has completed
    cancelled: bool = False                # Whether task was cancelled


@dataclass
class ThreadPoolHandle:
    """
    Handle for thread pool operations.

    C: typedef struct ThreadPoolHandle {
           int num_workers;
           void* executor;
           pthread_mutex_t mutex;
           bool shutdown;
           PoolStats stats;
       } ThreadPoolHandle;
    """
    num_workers: int = DEFAULT_NUM_WORKERS
    executor: Optional[ThreadPoolExecutor] = None
    mutex: threading.Lock = field(default_factory=threading.Lock)
    shutdown: bool = False
    created_time: str = ""                 # ISO timestamp
    logger_handle: Optional[object] = None

    # Statistics (protected by mutex)
    _next_task_id: int = 0
    _pending_count: int = 0            # Tasks submitted but not yet started
    _active_count: int = 0             # Tasks currently executing
    _completed_count: int = 0          # Tasks completed successfully
    _failed_count: int = 0             # Tasks that raised exceptions
    _cancelled_count: int = 0          # Tasks that were cancelled
    _futures: Dict[int, FutureHandle] = field(default_factory=dict)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _get_timestamp() -> str:
    """
    Get current timestamp in ISO format (UTC).

    C signature: void get_timestamp(char* buffer, size_t size);
    """
    return datetime.now(timezone.utc).isoformat()


def _wrap_task(pool: ThreadPoolHandle, task_id: int,
               func: Callable, args: tuple) -> Any:
    """
    Wrapper function that tracks task execution and updates stats.

    C signature: void* wrap_task(ThreadPoolHandle* pool, int task_id,
                                 void* (*func)(void*), void* args);
    """
    # Transition from pending to active
    with pool.mutex:
        pool._pending_count -= 1
        pool._active_count += 1

    try:
        # Execute the actual function
        result = func(*args)

        # Update completed count
        with pool.mutex:
            pool._completed_count += 1
            if task_id in pool._futures:
                pool._futures[task_id].completed = True

        return result

    except Exception as e:
        # Update failed count
        with pool.mutex:
            pool._failed_count += 1
            if task_id in pool._futures:
                pool._futures[task_id].completed = True

        # Re-raise to be captured by the Future
        raise

    finally:
        # Decrement active count and trigger cleanup
        with pool.mutex:
            pool._active_count -= 1
        # Cleanup old completed futures (outside of lock)
        _cleanup_completed_futures(pool)


def _cleanup_completed_futures(pool: ThreadPoolHandle) -> int:
    """
    Remove completed futures from the pool to prevent memory leak.

    Only cleans up when the number of futures exceeds MAX_COMPLETED_FUTURES.
    Keeps the most recent futures for potential result retrieval.

    C signature: int cleanup_completed_futures(ThreadPoolHandle* pool);

    Returns:
        Number of futures cleaned up
    """
    with pool.mutex:
        total_futures = len(pool._futures)
        if total_futures <= MAX_COMPLETED_FUTURES:
            return 0

        # Find completed futures (sorted by task_id to keep recent ones)
        completed_ids = sorted([
            tid for tid, fh in pool._futures.items()
            if fh.completed or fh.cancelled
        ])

        # Remove oldest completed futures, keep MAX_COMPLETED_FUTURES / 2
        to_remove = len(completed_ids) - (MAX_COMPLETED_FUTURES // 2)
        if to_remove <= 0:
            return 0

        removed = 0
        for tid in completed_ids[:to_remove]:
            del pool._futures[tid]
            removed += 1

        return removed


# ============================================================================
# POOL LIFECYCLE FUNCTIONS
# ============================================================================

def create_pool(
    num_workers: int = DEFAULT_NUM_WORKERS,
    logger_handle: Optional[object] = None
) -> Optional[ThreadPoolHandle]:
    """
    Create a new thread pool with the specified number of workers.

    Args:
        num_workers: Number of worker threads (1 to MAX_WORKERS)
        logger_handle: Optional logger handle for logging

    Returns:
        ThreadPoolHandle on success, None on failure

    C signature:
        ThreadPoolHandle* create_pool(int num_workers);

    Example:
        pool = create_pool(num_workers=4)
        if pool:
            # Use pool
            destroy_pool(pool)
    """
    # Validate parameters
    if num_workers < 1:
        log_error(logger_handle, TP_CONTEXT,
                  "create_pool failed", f"num_workers must be >= 1, got {num_workers}")
        return None

    if num_workers > MAX_WORKERS:
        log_warning(logger_handle, TP_CONTEXT,
                   f"Limiting workers from {num_workers} to {MAX_WORKERS}")
        num_workers = MAX_WORKERS

    try:
        # Create the pool handle
        pool = ThreadPoolHandle(
            num_workers=num_workers,
            created_time=_get_timestamp(),
            logger_handle=logger_handle
        )

        # Create the thread pool executor
        pool.executor = ThreadPoolExecutor(
            max_workers=num_workers,
            thread_name_prefix="QMailWorker"
        )

        log_debug(logger_handle, TP_CONTEXT,
                 f"Thread pool created with {num_workers} workers")

        return pool

    except Exception as e:
        log_error(logger_handle, TP_CONTEXT,
                  "create_pool failed", str(e))
        return None


def destroy_pool(pool: ThreadPoolHandle, wait: bool = True) -> ThreadPoolErrorCode:
    """
    Destroy a thread pool, optionally waiting for pending tasks.

    Args:
        pool: Thread pool handle to destroy
        wait: If True, wait for pending tasks to complete (default)
              If False, cancel pending tasks immediately

    Returns:
        Error code

    C signature:
        ThreadPoolErrorCode destroy_pool(ThreadPoolHandle* pool, bool wait);

    Example:
        err = destroy_pool(pool)
        if err != ThreadPoolErrorCode.SUCCESS:
            print("Failed to destroy pool")
    """
    if pool is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM

    with pool.mutex:
        if pool.shutdown:
            return ThreadPoolErrorCode.ERR_ALREADY_SHUTDOWN

        pool.shutdown = True

    try:
        if pool.executor:
            if wait:
                # Wait with timeout
                pool.executor.shutdown(wait=False)
                start_time = time.time()
                while time.time() - start_time < SHUTDOWN_TIMEOUT_SEC:
                    with pool.mutex:
                        pending = pool._pending_count
                        active = pool._active_count
                    if pending == 0 and active == 0:
                        break
                    time.sleep(0.1)
                else:
                    log_warning(pool.logger_handle, TP_CONTEXT,
                               f"Pool shutdown timeout ({SHUTDOWN_TIMEOUT_SEC}s) - forcing")
                # Force final shutdown
                if PYTHON_39_PLUS:
                    pool.executor.shutdown(wait=False, cancel_futures=True)
                else:
                    pool.executor.shutdown(wait=False)
            else:
                # Immediate shutdown - cancel pending if possible
                if PYTHON_39_PLUS:
                    pool.executor.shutdown(wait=False, cancel_futures=True)
                else:
                    pool.executor.shutdown(wait=False)

        log_debug(pool.logger_handle, TP_CONTEXT,
                 f"Thread pool destroyed (completed={pool._completed_count}, "
                 f"failed={pool._failed_count})")

        return ThreadPoolErrorCode.SUCCESS

    except (OSError, RuntimeError) as e:
        log_error(pool.logger_handle, TP_CONTEXT,
                  "destroy_pool failed", str(e))
        return ThreadPoolErrorCode.ERR_TASK_FAILED


# ============================================================================
# WORK SUBMISSION FUNCTIONS
# ============================================================================

def submit_work(
    pool: ThreadPoolHandle,
    func: Callable,
    args: tuple = ()
) -> Tuple[ThreadPoolErrorCode, Optional[FutureHandle]]:
    """
    Submit a function for execution in the thread pool.

    Args:
        pool: Thread pool handle
        func: Function to execute
        args: Tuple of arguments to pass to the function

    Returns:
        Tuple of (error code, FutureHandle or None)

    C signature:
        ThreadPoolErrorCode submit_work(ThreadPoolHandle* pool,
                                        void* (*func)(void*),
                                        void* args,
                                        FutureHandle* out_future);

    Example:
        def my_task(x, y):
            return x + y

        err, future = submit_work(pool, my_task, (1, 2))
        if err == ThreadPoolErrorCode.SUCCESS:
            result = wait_for_result(future)
    """
    if pool is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM, None

    if func is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM, None

    with pool.mutex:
        if pool.shutdown:
            log_warning(pool.logger_handle, TP_CONTEXT,
                       "Cannot submit work to shutdown pool")
            return ThreadPoolErrorCode.ERR_POOL_SHUTDOWN, None

        # Check queue size limit
        queue_size = pool._pending_count + pool._active_count
        if queue_size >= MAX_QUEUE_SIZE:
            log_warning(pool.logger_handle, TP_CONTEXT,
                       f"Queue full ({queue_size} tasks)")
            return ThreadPoolErrorCode.ERR_POOL_FULL, None

        # Generate task ID
        task_id = pool._next_task_id
        pool._next_task_id += 1

        # Increment pending count (will be decremented when task starts)
        pool._pending_count += 1

    try:
        # Get function name for debugging
        func_name = getattr(func, '__name__', str(func))

        # Submit the wrapped task
        future = pool.executor.submit(_wrap_task, pool, task_id, func, args)

        # Create future handle
        handle = FutureHandle(
            task_id=task_id,
            future=future,
            submitted_time=_get_timestamp(),
            function_name=func_name
        )

        # Store the future handle
        with pool.mutex:
            pool._futures[task_id] = handle

        log_debug(pool.logger_handle, TP_CONTEXT,
                 f"Submitted task {task_id} ({func_name})")

        return ThreadPoolErrorCode.SUCCESS, handle

    except (OSError, RuntimeError) as e:
        # Decrement pending count on failure
        with pool.mutex:
            pool._pending_count -= 1
        log_error(pool.logger_handle, TP_CONTEXT,
                  "submit_work failed", str(e))
        return ThreadPoolErrorCode.ERR_TASK_FAILED, None


def submit_work_batch(
    pool: ThreadPoolHandle,
    tasks: List[Tuple[Callable, tuple]]
) -> Tuple[ThreadPoolErrorCode, List[FutureHandle]]:
    """
    Submit multiple tasks for execution in the thread pool.

    Args:
        pool: Thread pool handle
        tasks: List of (function, args) tuples

    Returns:
        Tuple of (error code, list of FutureHandles)
        If some tasks fail to submit, returns partial list with error code.

    C signature:
        ThreadPoolErrorCode submit_work_batch(ThreadPoolHandle* pool,
                                              WorkItem* items,
                                              int count,
                                              FutureHandle** out_futures,
                                              int* out_count);

    Example:
        tasks = [(add, (1, 2)), (multiply, (3, 4)), (subtract, (5, 1))]
        err, futures = submit_work_batch(pool, tasks)
    """
    if pool is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM, []

    if not tasks:
        return ThreadPoolErrorCode.SUCCESS, []

    futures = []
    for func, args in tasks:
        err, future = submit_work(pool, func, args)
        if err == ThreadPoolErrorCode.SUCCESS:
            futures.append(future)
        else:
            # Return partial results on failure
            return err, futures

    return ThreadPoolErrorCode.SUCCESS, futures


# ============================================================================
# RESULT RETRIEVAL FUNCTIONS
# ============================================================================

def wait_for_result(
    future: FutureHandle,
    timeout_ms: int = DEFAULT_TIMEOUT_MS
) -> Tuple[ThreadPoolErrorCode, Any]:
    """
    Wait for a task to complete and return its result.

    Args:
        future: FutureHandle from submit_work
        timeout_ms: Maximum time to wait in milliseconds (0 = no timeout)

    Returns:
        Tuple of (error code, result or None)

    C signature:
        ThreadPoolErrorCode wait_for_result(FutureHandle* future,
                                            int timeout_ms,
                                            void** out_result);

    Example:
        err, result = wait_for_result(future, timeout_ms=5000)
        if err == ThreadPoolErrorCode.SUCCESS:
            print(f"Result: {result}")
    """
    if future is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM, None

    try:
        # Convert timeout to seconds (None for no timeout)
        timeout_sec = timeout_ms / 1000.0 if timeout_ms > 0 else None

        # Wait for result
        result = future.future.result(timeout=timeout_sec)
        return ThreadPoolErrorCode.SUCCESS, result

    except TimeoutError:
        return ThreadPoolErrorCode.ERR_TIMEOUT, None

    except Exception as e:
        # Task raised an exception
        return ThreadPoolErrorCode.ERR_TASK_FAILED, None


def wait_for_all(
    futures: List[FutureHandle],
    timeout_ms: int = DEFAULT_TIMEOUT_MS
) -> Tuple[ThreadPoolErrorCode, List[Tuple[ThreadPoolErrorCode, Any]]]:
    """
    Wait for multiple tasks to complete.

    Args:
        futures: List of FutureHandles
        timeout_ms: Maximum total time to wait in milliseconds

    Returns:
        Tuple of (overall error code, list of (error code, result) tuples)

    C signature:
        ThreadPoolErrorCode wait_for_all(FutureHandle** futures,
                                         int count,
                                         int timeout_ms,
                                         ResultItem** out_results);

    Example:
        err, results = wait_for_all(futures, timeout_ms=10000)
        for task_err, result in results:
            if task_err == ThreadPoolErrorCode.SUCCESS:
                print(f"Result: {result}")
    """
    if not futures:
        return ThreadPoolErrorCode.SUCCESS, []

    results = []
    start_time = time.time()
    remaining_ms = timeout_ms

    for future in futures:
        if timeout_ms > 0:
            elapsed_ms = (time.time() - start_time) * 1000
            remaining_ms = max(0, timeout_ms - int(elapsed_ms))
            if remaining_ms == 0:
                # Timeout - mark remaining as timeout
                results.append((ThreadPoolErrorCode.ERR_TIMEOUT, None))
                continue

        err, result = wait_for_result(future, timeout_ms=remaining_ms)
        results.append((err, result))

    # Determine overall status
    all_success = all(r[0] == ThreadPoolErrorCode.SUCCESS for r in results)
    return ThreadPoolErrorCode.SUCCESS if all_success else ThreadPoolErrorCode.ERR_TASK_FAILED, results


def is_task_done(future: FutureHandle) -> bool:
    """
    Check if a task has completed (without blocking).

    Args:
        future: FutureHandle to check

    Returns:
        True if task is done (success, failure, or cancelled), False otherwise

    C signature:
        bool is_task_done(FutureHandle* future);
    """
    if future is None:
        return True

    return future.future.done()


def cancel_task(future: FutureHandle,
                pool: Optional[ThreadPoolHandle] = None) -> bool:
    """
    Attempt to cancel a pending task.

    Note: Only works for tasks that haven't started executing yet.

    Args:
        future: FutureHandle to cancel
        pool: Optional pool handle to track cancelled count

    Returns:
        True if successfully cancelled, False otherwise

    C signature:
        bool cancel_task(FutureHandle* future, ThreadPoolHandle* pool);
    """
    if future is None:
        return False

    if future.future.cancel():
        future.cancelled = True
        # Update pool statistics if pool is provided
        if pool is not None:
            with pool.mutex:
                pool._cancelled_count += 1
                pool._pending_count -= 1  # Task was pending when cancelled
        return True
    return False


def get_task_exception(future: FutureHandle) -> Optional[Exception]:
    """
    Get the exception raised by a failed task.

    Args:
        future: FutureHandle to check

    Returns:
        Exception if task failed, None otherwise

    C signature:
        const char* get_task_exception(FutureHandle* future);
    """
    if future is None:
        return None

    if not future.future.done():
        return None

    return future.future.exception()


# ============================================================================
# STATISTICS FUNCTIONS
# ============================================================================

def get_pool_stats(pool: ThreadPoolHandle) -> Tuple[ThreadPoolErrorCode, Optional[PoolStats]]:
    """
    Get current statistics for a thread pool.

    Args:
        pool: Thread pool handle

    Returns:
        Tuple of (error code, PoolStats or None)

    C signature:
        ThreadPoolErrorCode get_pool_stats(ThreadPoolHandle* pool,
                                           PoolStats* out_stats);

    Example:
        err, stats = get_pool_stats(pool)
        if err == ThreadPoolErrorCode.SUCCESS:
            print(f"Active workers: {stats.active_workers}")
            print(f"Completed tasks: {stats.completed_tasks}")
    """
    if pool is None:
        return ThreadPoolErrorCode.ERR_INVALID_PARAM, None

    with pool.mutex:
        # Use tracked pending count directly
        pending = pool._pending_count

        # Calculate uptime with error handling
        uptime = 0.0
        if pool.created_time:
            try:
                created = datetime.fromisoformat(pool.created_time)
                uptime = (datetime.now(timezone.utc) - created).total_seconds()
            except (ValueError, TypeError):
                uptime = 0.0

        stats = PoolStats(
            num_workers=pool.num_workers,
            active_workers=pool._active_count,
            pending_tasks=pending,
            completed_tasks=pool._completed_count,
            failed_tasks=pool._failed_count,
            cancelled_tasks=pool._cancelled_count,
            uptime_seconds=uptime
        )

    return ThreadPoolErrorCode.SUCCESS, stats


def get_active_count(pool: ThreadPoolHandle) -> int:
    """
    Get number of currently executing tasks.

    Args:
        pool: Thread pool handle

    Returns:
        Number of active tasks, or -1 on error

    C signature:
        int get_active_count(ThreadPoolHandle* pool);
    """
    if pool is None:
        return -1

    with pool.mutex:
        return pool._active_count


def is_pool_idle(pool: ThreadPoolHandle) -> bool:
    """
    Check if pool has no active or pending tasks.

    Args:
        pool: Thread pool handle

    Returns:
        True if pool is idle, False otherwise

    C signature:
        bool is_pool_idle(ThreadPoolHandle* pool);
    """
    if pool is None:
        return True

    with pool.mutex:
        return pool._active_count == 0 and pool._pending_count == 0


def is_pool_shutdown(pool: ThreadPoolHandle) -> bool:
    """
    Check if pool has been shutdown.

    Args:
        pool: Thread pool handle

    Returns:
        True if pool is shutdown, False otherwise

    C signature:
        bool is_pool_shutdown(ThreadPoolHandle* pool);
    """
    if pool is None:
        return True

    with pool.mutex:
        return pool.shutdown


# ============================================================================
# TEST SUITE
# ============================================================================

if __name__ == "__main__":
    """
    Test the thread_pool module.
    """
    import random

    print("=" * 60)
    print("thread_pool.py - Test Suite")
    print("=" * 60)

    # Test 1: Create pool
    print("\n1. Testing create_pool()...")
    pool = create_pool(num_workers=4)
    assert pool is not None
    assert pool.num_workers == 4
    assert not pool.shutdown
    print("   SUCCESS: Pool created with 4 workers")

    # Test 2: Get initial stats
    print("\n2. Testing get_pool_stats() (initial)...")
    err, stats = get_pool_stats(pool)
    assert err == ThreadPoolErrorCode.SUCCESS
    assert stats.num_workers == 4
    assert stats.active_workers == 0
    assert stats.completed_tasks == 0
    print(f"   Stats: workers={stats.num_workers}, active={stats.active_workers}")
    print("   SUCCESS: Initial stats correct")

    # Test 3: Submit simple work
    print("\n3. Testing submit_work()...")
    def add(x, y):
        return x + y

    err, future = submit_work(pool, add, (10, 20))
    assert err == ThreadPoolErrorCode.SUCCESS
    assert future is not None
    assert future.task_id == 0
    print(f"   Submitted task {future.task_id} ({future.function_name})")
    print("   SUCCESS: Work submitted")

    # Test 4: Wait for result
    print("\n4. Testing wait_for_result()...")
    err, result = wait_for_result(future, timeout_ms=5000)
    assert err == ThreadPoolErrorCode.SUCCESS
    assert result == 30
    print(f"   Result: {result}")
    print("   SUCCESS: Result retrieved")

    # Test 5: Submit multiple tasks
    print("\n5. Testing submit_work_batch()...")
    def multiply(x, y):
        time.sleep(0.1)  # Simulate work
        return x * y

    tasks = [
        (multiply, (i, i + 1))
        for i in range(5)
    ]
    err, futures = submit_work_batch(pool, tasks)
    assert err == ThreadPoolErrorCode.SUCCESS
    assert len(futures) == 5
    print(f"   Submitted {len(futures)} tasks")
    print("   SUCCESS: Batch submitted")

    # Test 6: Wait for all
    print("\n6. Testing wait_for_all()...")
    err, results = wait_for_all(futures, timeout_ms=10000)
    assert err == ThreadPoolErrorCode.SUCCESS
    assert len(results) == 5
    for i, (task_err, result) in enumerate(results):
        assert task_err == ThreadPoolErrorCode.SUCCESS
        expected = i * (i + 1)
        assert result == expected, f"Expected {expected}, got {result}"
    print(f"   Results: {[r[1] for r in results]}")
    print("   SUCCESS: All results retrieved")

    # Test 7: Check stats after work
    print("\n7. Testing get_pool_stats() (after work)...")
    err, stats = get_pool_stats(pool)
    assert err == ThreadPoolErrorCode.SUCCESS
    assert stats.completed_tasks == 6  # 1 + 5 tasks
    assert stats.failed_tasks == 0
    print(f"   Completed: {stats.completed_tasks}, Failed: {stats.failed_tasks}")
    print("   SUCCESS: Stats updated correctly")

    # Test 8: Test task that raises exception
    print("\n8. Testing failed task...")
    def failing_task():
        raise ValueError("Intentional failure")

    err, future = submit_work(pool, failing_task, ())
    assert err == ThreadPoolErrorCode.SUCCESS
    err, result = wait_for_result(future, timeout_ms=5000)
    assert err == ThreadPoolErrorCode.ERR_TASK_FAILED
    assert result is None
    exc = get_task_exception(future)
    assert exc is not None
    print(f"   Exception: {type(exc).__name__}: {exc}")
    print("   SUCCESS: Failed task handled correctly")

    # Test 9: Test is_task_done
    print("\n9. Testing is_task_done()...")
    def slow_task():
        time.sleep(0.5)
        return "done"

    err, future = submit_work(pool, slow_task, ())
    assert err == ThreadPoolErrorCode.SUCCESS
    # Task should not be done immediately
    initial_done = is_task_done(future)
    # Wait for completion
    err, result = wait_for_result(future)
    final_done = is_task_done(future)
    assert final_done == True
    print(f"   Initial done: {initial_done}, Final done: {final_done}")
    print("   SUCCESS: is_task_done works")

    # Test 10: Test timeout
    print("\n10. Testing timeout...")
    def very_slow_task():
        time.sleep(10)
        return "never"

    err, future = submit_work(pool, very_slow_task, ())
    assert err == ThreadPoolErrorCode.SUCCESS
    err, result = wait_for_result(future, timeout_ms=100)
    assert err == ThreadPoolErrorCode.ERR_TIMEOUT
    print("   SUCCESS: Timeout handled correctly")

    # Test 11: Test cancel_task
    print("\n11. Testing cancel_task()...")
    # Submit many tasks to fill the queue
    slow_futures = []
    for _ in range(10):
        err, f = submit_work(pool, very_slow_task, ())
        slow_futures.append(f)

    # Try to cancel the last ones (may or may not work depending on timing)
    cancelled = 0
    for f in slow_futures:
        if cancel_task(f):
            cancelled += 1
    print(f"   Cancelled {cancelled} tasks")
    print("   SUCCESS: cancel_task executed (actual cancellation depends on timing)")

    # Test 12: Test pool idle check
    print("\n12. Testing is_pool_idle()...")
    # Create fresh pool for clean test
    pool2 = create_pool(num_workers=2)
    assert is_pool_idle(pool2) == True
    err, f = submit_work(pool2, lambda: time.sleep(0.2), ())
    time.sleep(0.05)  # Let task start
    # Pool should not be idle while task running
    assert is_pool_idle(pool2) == False
    time.sleep(0.3)  # Wait for task
    assert is_pool_idle(pool2) == True
    destroy_pool(pool2)
    print("   SUCCESS: is_pool_idle works")

    # Test 13: Test invalid parameters
    print("\n13. Testing invalid parameters...")
    assert create_pool(num_workers=0) is None
    assert create_pool(num_workers=-1) is None
    err, _ = submit_work(None, add, (1, 2))
    assert err == ThreadPoolErrorCode.ERR_INVALID_PARAM
    err, _ = submit_work(pool, None, ())
    assert err == ThreadPoolErrorCode.ERR_INVALID_PARAM
    print("   SUCCESS: Invalid parameters handled")

    # Test 14: Test max workers limit
    print("\n14. Testing max workers limit...")
    big_pool = create_pool(num_workers=100)
    assert big_pool is not None
    assert big_pool.num_workers == MAX_WORKERS  # Should be capped
    destroy_pool(big_pool)
    print(f"   Requested 100, got {MAX_WORKERS} (capped)")
    print("   SUCCESS: Max workers enforced")

    # Test 15: Concurrent stress test
    print("\n15. Testing concurrent stress test...")
    stress_pool = create_pool(num_workers=8)

    def random_work(n):
        time.sleep(random.uniform(0.01, 0.05))
        return n * 2

    stress_futures = []
    for i in range(50):
        err, f = submit_work(stress_pool, random_work, (i,))
        if err == ThreadPoolErrorCode.SUCCESS:
            stress_futures.append((i, f))

    # Wait for all and verify results
    correct = 0
    for i, f in stress_futures:
        err, result = wait_for_result(f, timeout_ms=5000)
        if err == ThreadPoolErrorCode.SUCCESS and result == i * 2:
            correct += 1

    err, stats = get_pool_stats(stress_pool)
    print(f"   Completed: {stats.completed_tasks}, Correct: {correct}/50")
    assert correct == 50
    destroy_pool(stress_pool)
    print("   SUCCESS: Stress test passed")

    # Test 16: Test destroy with wait=False
    print("\n16. Testing destroy_pool(wait=False)...")
    quick_pool = create_pool(num_workers=2)
    # Submit slow tasks
    for _ in range(5):
        submit_work(quick_pool, lambda: time.sleep(1), ())
    # Destroy without waiting
    err = destroy_pool(quick_pool, wait=False)
    assert err == ThreadPoolErrorCode.SUCCESS
    print("   SUCCESS: Pool destroyed without waiting")

    # Test 17: Test shutdown prevents new submissions
    print("\n17. Testing shutdown prevents submissions...")
    shutdown_pool = create_pool(num_workers=2)
    destroy_pool(shutdown_pool, wait=True)
    err, _ = submit_work(shutdown_pool, add, (1, 2))
    assert err == ThreadPoolErrorCode.ERR_POOL_SHUTDOWN
    print("   SUCCESS: Shutdown pool rejects new work")

    # Test 18: Test double shutdown
    print("\n18. Testing double shutdown...")
    double_pool = create_pool(num_workers=2)
    err = destroy_pool(double_pool)
    assert err == ThreadPoolErrorCode.SUCCESS
    err = destroy_pool(double_pool)
    assert err == ThreadPoolErrorCode.ERR_ALREADY_SHUTDOWN
    print("   SUCCESS: Double shutdown handled")

    # Cleanup original pool
    print("\n19. Cleaning up main test pool...")
    # Wait a bit for slow tasks to complete or timeout
    time.sleep(0.5)
    err = destroy_pool(pool, wait=False)
    print("   SUCCESS: Main pool destroyed")

    print("\n" + "=" * 60)
    print("All thread_pool tests passed! (19 tests)")
    print("=" * 60)
