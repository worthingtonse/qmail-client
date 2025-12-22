# gemini_core/cloudcoin.py
# Manages the CloudCoin digital currency required for server interactions.

import logging
from typing import Tuple, Optional
from .types import ErrorCode, CloudCoinLocker

def open_locker(key_path: str) -> Tuple[ErrorCode, Optional[CloudCoinLocker]]:
    """
    Opens a CloudCoin locker and loads the coins (stub).
    In a real implementation, this would involve file I/O and decryption.

    Args:
        key_path: The path to the locker's key file.

    Returns:
        A tuple of (ErrorCode, CloudCoinLocker instance). The instance is None on failure.
    """
    try:
        # Placeholder: In a real app, this would read an encrypted file.
        # Here we just simulate a successful opening with a starting balance.
        logging.info(f"Opening CloudCoin locker with key from {key_path}...")
        locker = CloudCoinLocker(key_path=key_path, balance=1000)
        logging.info(f"Locker opened. Initial balance: {locker.balance} coins.")
        return ErrorCode.SUCCESS, locker
    except Exception as e:
        logging.error(f"Failed to open locker at {key_path}: {e}")
        return ErrorCode.ERR_IO, None

def spend_coins(locker: CloudCoinLocker, amount: int) -> ErrorCode:
    """
    Spends a specified amount of CloudCoins from the locker.

    Args:
        locker: The CloudCoinLocker instance.
        amount: The number of coins to spend.

    Returns:
        An ErrorCode indicating success or failure.
    """
    if not locker:
        logging.error("Cannot spend coins: Locker is not valid.")
        return ErrorCode.ERR_INVALID_PARAM

    if locker.balance < amount:
        logging.error(f"Cannot spend {amount} coins: Insufficient funds. Balance: {locker.balance}.")
        return ErrorCode.ERR_INSUFFICIENT_FUNDS

    try:
        locker.balance -= amount
        logging.info(f"Spent {amount} coins for an operation. Remaining balance: {locker.balance}.")
        # In a real implementation, this would create a transaction record
        # and prepare it to be sent to a server.
        return ErrorCode.SUCCESS
    except Exception as e:
        logging.error(f"An unexpected error occurred while spending coins: {e}")
        return ErrorCode.FAILURE

def get_balance(locker: CloudCoinLocker) -> int:
    """
    Returns the current balance of the locker.
    """
    return locker.balance if locker else 0
