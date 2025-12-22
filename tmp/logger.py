
import logging
import logging.handlers
import os
import gzip

class GzipRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    A rotating file handler that compresses rotated logs using gzip.
    """
    def doRollover(self):
        """
        Do a rollover, gzipping the old log file.
        """
        super().doRollover()
        # gzip the old log file
        log_file = self.baseFilename
        rotated_log = f"{log_file}.1"
        if os.path.exists(rotated_log):
            with open(rotated_log, 'rb') as f_in:
                with gzip.open(f"{rotated_log}.gz", 'wb') as f_out:
                    f_out.writelines(f_in)
            os.remove(rotated_log)

def init_logger(log_path, max_bytes=1024*1024, backup_count=5, buffer_capacity=100):
    """
    Initializes a logger with rotation, compression, and buffering.

    Args:
        log_path (str): The full path to the log file.
        max_bytes (int): The maximum size of the log file in bytes before rotation.
        backup_count (int): The number of backup logs to keep.
        buffer_capacity (int): The number of log records to buffer in memory.

    Returns:
        logging.Logger: The configured logger instance (handle).
    """
    logger = logging.getLogger(log_path)
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if init_logger is called multiple times
    if logger.handlers:
        return logger

    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(module)s.%(funcName)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Rotating file handler with gzip compression
    handler = GzipRotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    handler.setFormatter(formatter)

    # Memory handler to buffer logs and flush on error or when full
    memory_handler = logging.handlers.MemoryHandler(
        capacity=buffer_capacity,
        flushLevel=logging.ERROR,
        target=handler
    )
    memory_handler.setFormatter(formatter)

    logger.addHandler(memory_handler)

    return logger

def log_debug(handle, message):
    """Logs a debug message."""
    if handle:
        handle.debug(message)

def log_info(handle, message):
    """Logs an info message."""
    if handle:
        handle.info(message)

def log_warning(handle, message):
    """Logs a warning message."""
    if handle:
        handle.warning(message)

def log_error(handle, message):
    """Logs an error message."""
    if handle:
        handle.error(message)

def flush_log(handle):
    """Flushes the log handlers."""
    if handle:
        for handler in handle.handlers:
            handler.flush()

def close_logger(handle):
    """Closes the logger and removes its handlers."""
    if handle:
        # Flush any buffered records before closing
        flush_log(handle)
        for handler in handle.handlers[:]:
            handler.close()
            handle.removeHandler(handler)

if __name__ == '__main__':
    # Example usage:
    # Note: The log path is now relative to the src directory
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file_path = os.path.join(log_dir, 'gemini_mail.mlog')


    # Initialize logger
    logger = init_logger(log_file_path, max_bytes=500, backup_count=3, buffer_capacity=5)
    if logger:
        print(f"Logger initialized. Logging to {log_file_path}")

        # These messages will be buffered
        log_info(logger, "Qmail client starting up.")
        log_debug(logger, "Reading configuration from opus45_qmail.toml.")
        log_info(logger, "Pinging servers.")
        log_warning(logger, "Connection to server 1.2.3.4 is slow.")

        # This error message will trigger a flush of the buffer
        print("Logging an error, which should flush the buffer...")
        log_error(logger, "Failed to authenticate with server 5.6.7.8.")

        # These messages will be in a new buffer
        log_info(logger, "Doing some more work...")
        log_debug(logger, "Work complete.")

        # This will fill up the buffer and trigger a flush
        print("Logging enough to fill the buffer...")
        for i in range(6):
            log_info(logger, f"Logging message {i+1}")


        # Log enough to trigger rotation
        print("Logging enough to trigger rotation...")
        for i in range(20):
            log_error(logger, "This is a long line to fill up the log file quickly and test rotation and compression.")


        # Flush and close
        close_logger(logger)
        print("Logger closed.")

        print(f"\nLog files in {log_dir}:")
        for f in os.listdir(log_dir):
            print(f" - {f}")

    else:
        print("Failed to initialize logger.")
