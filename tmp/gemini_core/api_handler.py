# gemini_core/api_handler.py
# This module contains the logic for the REST API endpoints.
# These functions are designed to be called by a web framework (e.g., Flask, FastAPI).
# They orchestrate calls to other core modules.

import logging
from typing import Dict, Any

from . import striping, crypto, database, task_manager, cloudcoin
from .types import ErrorCode, Email

# This would be initialized at startup
DB_HANDLE = None
COIN_LOCKER = None

def initialize_handlers(db_handle, coin_locker):
    """A function to be called at server startup to provide necessary handles."""
    global DB_HANDLE, COIN_LOCKER
    DB_HANDLE = db_handle
    COIN_LOCKER = coin_locker
    logging.info("API Handlers initialized with DB handle and Coin locker.")

# --- Endpoint Logic ---

def handle_mail_send(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestrates the process of sending an email.
    This would be called by the `/mail/send` endpoint.

    Args:
        request_data: A dictionary containing 'subject', 'sender', 'recipients', 'body'.

    Returns:
        A dictionary to be serialized as the JSON response.
    """
    logging.info("API: /mail/send triggered.")
    
    # 1. Create a task for this operation
    err, task_id = task_manager.create_task("Sending new email")
    if err != ErrorCode.SUCCESS:
        return {"status": "error", "message": "Failed to create task."}

    # In a real async implementation, the rest of this function would
    # run in a background thread.
    task_manager.update_task_progress(task_id, task_manager.TaskState.IN_PROGRESS, 10)

    # 2. Extract data and create Email object
    email = Email(
        subject=request_data.get('subject'),
        sender=request_data.get('sender'),
        recipients=request_data.get('recipients'),
        body=request_data.get('body')
    )

    # 3. Serialize and encrypt the email data (simplified)
    email_bytes = str(email).encode('utf-8')
    key = crypto.generate_key()
    err, encrypted_data = crypto.encrypt_data(email_bytes, key)
    if err != ErrorCode.SUCCESS:
        task_manager.update_task_progress(task_id, task_manager.TaskState.FAILED, 100, error_message="Encryption failed.")
        return {"status": "error", "task_id": task_id, "message": "Encryption failed."}
    
    task_manager.update_task_progress(task_id, task_manager.TaskState.IN_PROGRESS, 30)

    # 4. Create stripes
    err, stripes = striping.create_stripes(encrypted_data, num_data_stripes=3, num_parity_stripes=1)
    if err != ErrorCode.SUCCESS:
        task_manager.update_task_progress(task_id, task_manager.TaskState.FAILED, 100, error_message="Striping failed.")
        return {"status": "error", "task_id": task_id, "message": "Striping failed."}

    # 5. "Send" stripes to servers (placeholder)
    logging.info(f"Distributing {len(stripes)} stripes to servers...")
    task_manager.update_task_progress(task_id, task_manager.TaskState.IN_PROGRESS, 60)

    # 6. Spend CloudCoins for the operation
    err = cloudcoin.spend_coins(COIN_LOCKER, 10)
    if err != ErrorCode.SUCCESS:
        # In a real app, you might need to roll back the operation
        task_manager.update_task_progress(task_id, task_manager.TaskState.FAILED, 100, error_message="Payment failed.")
        return {"status": "error", "task_id": task_id, "message": "Could not spend CloudCoins."}
    
    # 7. Store metadata in database
    meta = {"subject": email.subject, "sender": email.sender, "recipients": email.recipients}
    database.store_email_metadata(DB_HANDLE, meta)
    task_manager.update_task_progress(task_id, task_manager.TaskState.IN_PROGRESS, 90)

    # 8. Mark task as complete
    task_manager.update_task_progress(task_id, task_manager.TaskState.COMPLETED, 100, result="Email sent successfully.")
    
    return {"status": "success", "task_id": task_id, "message": "Email sending process initiated."}


def handle_task_status(task_id: str) -> Dict[str, Any]:
    """
    Retrieves the status of a task.
    This would be called by the `/task/status/{task_id}` endpoint.
    """
    logging.info(f"API: /task/status for '{task_id}' triggered.")
    
    err, task = task_manager.get_task_status(task_id)
    if err != ErrorCode.SUCCESS:
        return {"status": "error", "message": f"Task ID '{task_id}' not found."}

    return {
        "status": "success",
        "task_id": task.id,
        "task_status": task.state.name,
        "progress": task.progress,
        "description": task.description,
        "result": task.result,
        "error": task.error_message
    }
