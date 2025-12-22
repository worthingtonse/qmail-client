# gemini_qmail_client.py
# Main application entry point and orchestrator for the QMail Client Core.
# This revised version uses a modular, C-portable structure.

import logging
import sys
from typing import Dict, Any

from gemini_core import (
    logger,
    database,
    cloudcoin,
    api_handler,
    striping,
    crypto
)
from gemini_core.types import ErrorCode

class QMailClientCore:
    """
    The main class that initializes and orchestrates all components.
    In a real application, this would be managed by the web server's lifecycle.
    """
    def __init__(self):
        self.db_handle = None
        self.coin_locker = None

    def initialize(self, in_memory_db: bool = False) -> ErrorCode:
        """
        Initializes all modules and sets up application state.
        
        Returns:
            ErrorCode indicating success or failure of initialization.
        """
        logger.setup_logger()
        logging.info("--- QMail Client Core Initializing ---")
        
        # Use an in-memory database for the demo
        db_path = ":memory:" if in_memory_db else "qmail_client.db"

        # Initialize Database
        err, db_handle = database.initialize()
        if err != ErrorCode.SUCCESS:
            logging.fatal("CRITICAL: Database initialization failed. Aborting.")
            return err
        self.db_handle = db_handle

        # Initialize CloudCoin Wallet
        err, coin_locker = cloudcoin.open_locker("main_wallet.key")
        if err != ErrorCode.SUCCESS:
            logging.fatal("CRITICAL: Could not open CloudCoin locker. Aborting.")
            database.close_database(self.db_handle) # Cleanup
            return err
        self.coin_locker = coin_locker
        
        # Provide handlers with necessary resources
        api_handler.initialize_handlers(self.db_handle, self.coin_locker)
        
        logging.info("--- All core modules initialized successfully ---")
        return ErrorCode.SUCCESS

    def shutdown(self):
        """
        Cleanly shuts down all application components.
        """
        logging.info("--- QMail Client Core Shutting Down ---")
        if self.db_handle:
            database.close_database(self.db_handle)
        logging.info("--- Shutdown complete ---")

def run_demonstration():
    """
    Runs a demonstration of the core features, including checksums and parity.
    """
    print("=" * 70)
    print("QMAIL CLIENT CORE - DEMONSTRATION")
    print("=" * 70)

    # 1. Checksum Demo
    print("\n[1] CHECKSUM MODULE (via crypto.py)")
    print("-" * 40)
    test_data = b"This is a test for CRC32 checksum."
    checksum = crypto.calculate_checksum(test_data)
    print(f"    Data: \"{test_data.decode()}\"")
    print(f"    CRC32 Checksum: 0x{checksum:08X}")
    print(f"    Verification: {'OK' if crypto.calculate_checksum(test_data) == checksum else 'FAIL'}")

    # 2. Striping and Parity Demo
    print("\n[2] STRIPING & PARITY MODULE (via striping.py)")
    print("-" * 40)
    original_data = b"QMail Core demonstrates data integrity and redundancy!" * 2
    num_data = 3
    num_parity = 1
    print(f"    Original Data: \"{original_data.decode()}\"")
    print(f"    Configuration: {num_data} data stripes, {num_parity} parity stripe.")
    
    err, all_stripes = striping.create_stripes(original_data, num_data, num_parity)
    if err != ErrorCode.SUCCESS:
        print("    ERROR: Failed to create stripes.")
        return

    print(f"\n    -> Successfully created {len(all_stripes)} total stripes:")
    for s in all_stripes:
        stripe_type = "Data" if s.index < num_data else "Parity"
        print(f"       - Stripe {s.index} ({stripe_type}): {s.size} bytes, checksum=0x{s.checksum:08X}")

    # 3. Reassembly Demo (Normal)
    print("\n[3] REASSEMBLY (Normal case)")
    print("-" * 40)
    err, reassembled_data = striping.reassemble_stripes(all_stripes)
    if err == ErrorCode.SUCCESS and reassembled_data == original_data:
        print("    SUCCESS: Data reassembled perfectly.")
    else:
        print("    FAILURE: Data did not match after reassembly.")

    # 4. Corruption Detection Demo
    print("\n[4] REASSEMBLY (Corruption case)")
    print("-" * 40)
    print("    -> Modifying stripe 1 data without updating checksum...")
    corrupted_stripes = [s for s in all_stripes]
    # Do not deepcopy, modify in place for demo clarity
    corrupted_stripes[1] = corrupted_stripes[1]._replace(data=b'CORRUPTED DATA')
    err, _ = striping.reassemble_stripes(corrupted_stripes)
    if err == ErrorCode.ERR_STRIPE_CORRUPTED:
        print("    SUCCESS: Checksum validation correctly detected corruption.")
    else:
        print("    FAILURE: Corruption was not detected.")
        
    # 5. Recovery Demo (Missing Stripe) - NOT YET IMPLEMENTED
    # print("\n[5] REASSEMBLY (Recovery case)")
    # print("-" * 40)
    # lost_stripe_index = 2
    # print(f"    -> Simulating loss of Stripe {lost_stripe_index}...")
    # available_stripes = [s for s in all_stripes if s.index != lost_stripe_index]
    # err, recovered_data = striping.reassemble_stripes(available_stripes, missing_indexes=[lost_stripe_index])
    # if err == ErrorCode.SUCCESS and recovered_data == original_data:
    #      print("    SUCCESS: Data successfully recovered using parity and reassembled.")
    # else:
    #      print(f"    FAILURE: Could not recover and reassemble data. Error: {err.name}")


def main():
    """Main application entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        run_demonstration()
        return

    # Normal application flow
    core_app = QMailClientCore()
    init_status = core_app.initialize()
    if init_status != ErrorCode.SUCCESS:
        print("Failed to initialize QMail Client Core. Check mail.mlog for details.")
        return

    print("\n--- QMail Client Core is running (simulation) ---")
    # In a real app, this is where the API server would start and block
    print("--- Shutting down immediately (run with --demo for demonstration) ---")
    
    core_app.shutdown()


if __name__ == '__main__':
    main()