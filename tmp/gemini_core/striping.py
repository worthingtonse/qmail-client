# gemini_core/striping.py
# Handles the RAID-style splitting of data into stripes and reassembly.

import logging
from typing import List, Tuple, Optional
from .types import ErrorCode, Stripe
from . import crypto

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Helper function to XOR two byte sequences."""
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, b'\x00')
    b = b.ljust(max_len, b'\x00')
    return bytes(x ^ y for x, y in zip(a, b))

def create_stripes(data: bytes, num_data_stripes: int, num_parity_stripes: int) -> Tuple[ErrorCode, Optional[List[Stripe]]]:
    """
    Splits data into binary stripes with checksums and generates a real parity stripe.
    
    Args:
        data: The binary data to be split.
        num_data_stripes: The number of stripes to split the data into.
        num_parity_stripes: The number of parity stripes to generate (supports 1).

    Returns:
        A tuple of (ErrorCode, List of all Stripes).
    """
    if num_data_stripes <= 0 or num_parity_stripes < 0:
        logging.error("Cannot create stripes: number of stripes must be valid.")
        return ErrorCode.ERR_INVALID_PARAM, None

    try:
        data_stripes = []
        all_stripes = []
        stripe_size = (len(data) + num_data_stripes - 1) // num_data_stripes
        
        # Create data stripes
        for i in range(num_data_stripes):
            start = i * stripe_size
            end = start + stripe_size
            stripe_data = data[start:end]
            checksum = crypto.calculate_checksum(stripe_data)
            stripe = Stripe(index=i, data=stripe_data, checksum=checksum)
            data_stripes.append(stripe)
        
        all_stripes.extend(data_stripes)

        # Create real parity stripes (XOR-based)
        if num_parity_stripes > 0:
            # For this demo, we only implement 1 parity stripe (RAID-4/5 style)
            if not data_stripes:
                parity_data = b''
            else:
                parity_data = data_stripes[0].data
                for stripe in data_stripes[1:]:
                    parity_data = _xor_bytes(parity_data, stripe.data)
            
            parity_checksum = crypto.calculate_checksum(parity_data)
            parity_stripe = Stripe(index=num_data_stripes, data=parity_data, checksum=parity_checksum)
            all_stripes.append(parity_stripe)

        logging.info(f"Created {len(data_stripes)} data stripes and {num_parity_stripes} parity stripe(s) with checksums.")
        return ErrorCode.SUCCESS, all_stripes

    except Exception as e:
        logging.error(f"An unexpected error occurred during stripe creation: {e}")
        return ErrorCode.FAILURE, None

def reassemble_stripes(stripes: List[Stripe], missing_indexes: List[int] = []) -> Tuple[ErrorCode, Optional[bytes]]:
    """
    Joins data stripes together, validating checksums and recovering if necessary.

    Args:
        stripes: A list of all available stripes (data and parity).
        missing_indexes: A list of indexes of stripes that are missing.

    Returns:
        A tuple of (ErrorCode, reassembled_data).
    """
    if not stripes:
        logging.warning("Reassembly warning: Stripe list is empty.")
        return ErrorCode.SUCCESS, b''

    try:
        # Validate checksums of all available stripes first
        for s in stripes:
            if crypto.calculate_checksum(s.data) != s.checksum:
                logging.error(f"Checksum mismatch for stripe {s.index}! Data is corrupt.")
                return ErrorCode.ERR_STRIPE_CORRUPTED, None
        logging.info("All available stripe checksums verified.")

        # --- Recovery Logic ---
        if len(missing_indexes) == 1:
            logging.info(f"Attempting recovery of missing stripe: {missing_indexes[0]}")
            
            parity_stripes = [s for s in stripes if s.index >= (len(stripes) - len(missing_indexes))]
            if not parity_stripes:
                logging.error("Cannot recover: Parity stripe is missing.")
                return ErrorCode.ERR_NOT_FOUND, None
            
            # Simple XOR recovery
            recovered_data = parity_stripes[0].data
            for s in stripes:
                if s.index != missing_indexes[0] and s not in parity_stripes:
                     recovered_data = _xor_bytes(recovered_data, s.data)
            
            recovered_checksum = crypto.calculate_checksum(recovered_data)
            recovered_stripe = Stripe(index=missing_indexes[0], data=recovered_data, checksum=recovered_checksum)
            stripes.append(recovered_stripe)
            logging.info(f"Successfully recovered stripe {missing_indexes[0]}.")
        
        elif len(missing_indexes) > 1:
            logging.error("Cannot recover more than 1 stripe with simple XOR parity.")
            return ErrorCode.FAILURE, None

        # --- Reassembly Logic ---
        data_stripes = sorted(
            [s for s in stripes if s.index < (len(stripes) - len(missing_indexes) - (1 if any(i >= len(stripes)-len(missing_indexes) for i in missing_indexes) else 0) )], # Heuristic to find data stripes
            key=lambda s: s.index
        )
        
        num_data_stripes_present = len(data_stripes)
        
        # Heuristic to find total number of data stripes
        total_data_stripes = max(s.index for s in stripes if s not in parity_stripes) + 1 if any(s not in parity_stripes for s in stripes) else 0

        if num_data_stripes_present != total_data_stripes and not missing_indexes:
             logging.warning(f"Reassembling with missing data stripes but no recovery was attempted.")


        reassembled_data = b"".join([s.data for s in data_stripes])
        
        logging.info(f"Reassembled data from {len(data_stripes)} stripes.")
        return ErrorCode.SUCCESS, reassembled_data
    
    except Exception as e:
        logging.error(f"An unexpected error occurred during stripe reassembly: {e}")
        return ErrorCode.FAILURE, None
