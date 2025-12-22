# gemini_core/task_manager.py
# Tracks the progress of active asynchronous tasks.

import logging
import uuid
from typing import Dict, Tuple, Optional, Any
from .types import ErrorCode, Task, TaskState

# In-memory dictionary to store tasks.
# For persistence, this could be moved to the database.
_tasks: Dict[str, Task] = {}

def create_task(description: str) -> Tuple[ErrorCode, Optional[str]]:
    """
    Creates and registers a new asynchronous task.

    Args:
        description: A human-readable description of the task.

    Returns:
        A tuple of (ErrorCode, task_id). The ID is None on failure.
    """
    try:
        task_id = str(uuid.uuid4())
        task = Task(id=task_id, description=description)
        _tasks[task_id] = task
        logging.info(f"Created task '{task_id}': {description}")
        return ErrorCode.SUCCESS, task_id
    except Exception as e:
        logging.error(f"Failed to create task: {e}")
        return ErrorCode.FAILURE, None

def get_task_status(task_id: str) -> Tuple[ErrorCode, Optional[Task]]:
    """
    Retrieves the status of a specific task.

    Args:
        task_id: The ID of the task to look up.

    Returns:
        A tuple of (ErrorCode, Task instance). The instance is None if not found.
    """
    task = _tasks.get(task_id)
    if not task:
        logging.warning(f"Attempted to get status for non-existent task '{task_id}'.")
        return ErrorCode.ERR_TASK_NOT_FOUND, None
    
    return ErrorCode.SUCCESS, task

def update_task_progress(task_id: str, state: TaskState, progress: int, result: Any = None, error_message: str = "") -> ErrorCode:
    """
    Updates the state and progress of a task.

    Args:
        task_id: The ID of the task to update.
        state: The new state of the task (e.g., IN_PROGRESS, COMPLETED).
        progress: The new progress percentage (0-100).
        result: The final result of the task, if completed.
        error_message: A message to store if the task failed.

    Returns:
        An ErrorCode indicating success or failure.
    """
    err, task = get_task_status(task_id)
    if err != ErrorCode.SUCCESS:
        return err

    try:
        task.state = state
        task.progress = progress
        if result is not None:
            task.result = result
        if error_message:
            task.error_message = error_message
        
        logging.info(f"Updated task '{task_id}': State={state.name}, Progress={progress}%")
        return ErrorCode.SUCCESS
    except Exception as e:
        logging.error(f"Failed to update task '{task_id}': {e}")
        return ErrorCode.FAILURE
