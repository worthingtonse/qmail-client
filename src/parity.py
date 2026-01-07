"""
parity.py - Parity Calculation Module for QMail Client Core

This module calculates parity stripes for redundancy and error recovery,
similar to RAID-5 implementation. Uses XOR-based parity for efficient
computation and recovery.

Author: Claude Opus 4.5
Phase: I
Version: 1.0.1

================================================================================
IMPORTANT LIMITATION - SINGLE PARITY ONLY (RAID-5 STYLE)
================================================================================
This module implements SINGLE XOR parity, which can recover ONLY ONE missing
stripe. If TWO or more stripes are lost simultaneously, DATA IS UNRECOVERABLE.

Real-world implications:
- If 2 servers go down at the same time -> PERMANENT DATA LOSS
- If a second failure occurs during recovery -> PERMANENT DATA LOSS
- Network issues affecting multiple servers -> POTENTIAL DATA LOSS

For critical data requiring higher redundancy, consider:
- RAID-6 style dual parity (survives 2 failures)
- Reed-Solomon erasure coding (configurable N+K redundancy)
- Libraries: pyeclib, zfec, or reedsolo

This single-parity limitation is acceptable for:
- Low-importance data with reliable servers
- Development/testing environments
- Systems with fast failure detection and recovery

For production mail systems with important data, dual parity is recommended.
================================================================================

Functions:
    calculate_parity(stripes)           -> List[ParityStripe]
    recover_stripe(stripes, parity)     -> Stripe
    verify_integrity(stripe_set)        -> bool

C Notes:
    - XOR-based parity for efficient computation
    - Can recover any single missing stripe using parity
    - Similar to RAID-5 implementation
    - Use SIMD instructions for XOR on large buffers in C
"""

from typing import List, Optional, Tuple

# Import types from qmail_types
try:
    from qmail_types import Stripe, ParityStripe, StripeSet, ErrorCode
except ImportError:
    # Fallback for standalone testing
    from dataclasses import dataclass, field
    from enum import IntEnum

    @dataclass
    class Stripe:
        index: int
        data: bytes = b''
        size: int = 0
        checksum: int = 0

    @dataclass
    class ParityStripe:
        index: int
        data: bytes = b''
        size: int = 0

    @dataclass
    class StripeSet:
        stripes: List[Stripe] = field(default_factory=list)
        parity_stripes: List[ParityStripe] = field(default_factory=list)
        total_size: int = 0
        encryption_key: bytes = b''

    class ErrorCode(IntEnum):
        SUCCESS = 0
        ERR_INVALID_PARAM = 1
        ERR_NOT_FOUND = 2
        ERR_TOO_MANY_FAILURES = 10  # Cannot recover - too many missing stripes

# Import logger (optional - for error reporting)
try:
    from logger import log_error, log_info, log_debug, log_warning
except ImportError:
    # Fallback for standalone testing
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")

# Import striping module for validation
try:
    from striping import validate_stripe, _calculate_checksum
except ImportError:
    import zlib
    def _calculate_checksum(data: bytes) -> int:
        return zlib.crc32(data) & 0xFFFFFFFF

    def validate_stripe(stripe, logger_handle=None) -> bool:
        if stripe is None or stripe.data is None:
            return False
        if stripe.size != len(stripe.data):
            return False
        return _calculate_checksum(stripe.data) == stripe.checksum


# ============================================================================
# CONSTANTS
# ============================================================================

# Module context for logging
PARITY_CONTEXT = "ParityMod"


# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte arrays together.

    If arrays are different lengths, the result is padded with the
    longer array's remaining bytes (XOR with 0).

    Args:
        a: First byte array
        b: Second byte array

    Returns:
        XOR result as bytes

    C signature: static void _xor_bytes(const uint8_t* a, const uint8_t* b,
                                         uint8_t* out, size_t len);
    """
    # Ensure both are byte-like
    a = bytes(a) if not isinstance(a, bytes) else a
    b = bytes(b) if not isinstance(b, bytes) else b

    # XOR corresponding bytes
    max_len = max(len(a), len(b))
    result = bytearray(max_len)

    for i in range(max_len):
        byte_a = a[i] if i < len(a) else 0
        byte_b = b[i] if i < len(b) else 0
        result[i] = byte_a ^ byte_b

    return bytes(result)


def _pad_to_length(data: bytes, length: int) -> bytes:
    """
    Pad data with zeros to reach specified length.

    Args:
        data: Original data
        length: Target length

    Returns:
        Padded data

    C signature: static void _pad_to_length(const uint8_t* data, size_t data_len,
                                             uint8_t* out, size_t target_len);
    """
    if len(data) >= length:
        return data
    return data + b'\x00' * (length - len(data))


# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def calculate_parity(
    stripes: List[Stripe],
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, List[ParityStripe]]:
    """
    Calculate parity stripes for a set of data stripes.

    Uses XOR-based parity (RAID-5 style). A single parity stripe is
    calculated by XORing all data stripes together. This allows
    recovery of any single missing data stripe.

    Args:
        stripes: List of data Stripe objects
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (ErrorCode, list of ParityStripe objects)
        - SUCCESS, parity stripes on success
        - ERR_INVALID_PARAM, empty list on error

    C signature:
        ErrorCode calculate_parity(const Stripe* stripes, int stripe_count,
                                    ParityStripe** out_parity, int* out_count);

    Example:
        err, parity = calculate_parity(data_stripes)
        if err == ErrorCode.SUCCESS:
            print(f"Generated {len(parity)} parity stripe(s)")
    """
    # Validate inputs
    if stripes is None:
        log_error(logger_handle, PARITY_CONTEXT, "calculate_parity failed", "stripes is None")
        return ErrorCode.ERR_INVALID_PARAM, []

    if len(stripes) == 0:
        log_warning(logger_handle, PARITY_CONTEXT, "calculate_parity called with empty stripes list")
        return ErrorCode.SUCCESS, []

    if len(stripes) == 1:
        # With only one stripe, parity is just a copy of the stripe
        parity_data = stripes[0].data
        parity = ParityStripe(
            index=0,
            data=parity_data,
            size=len(parity_data)
        )
        log_debug(logger_handle, PARITY_CONTEXT, f"Generated parity for 1 stripe")
        return ErrorCode.SUCCESS, [parity]

    # Find maximum stripe size (for padding)
    max_size = max(s.size for s in stripes)

    # Calculate XOR parity across all stripes
    parity_data = b'\x00' * max_size  # Start with zeros

    for stripe in stripes:
        # Pad stripe data to max size
        padded_data = _pad_to_length(stripe.data, max_size)
        parity_data = _xor_bytes(parity_data, padded_data)

    # Create parity stripe
    parity = ParityStripe(
        index=0,
        data=parity_data,
        size=len(parity_data)
    )

    log_debug(
        logger_handle, PARITY_CONTEXT,
        f"Generated parity stripe ({len(parity_data)} bytes) from {len(stripes)} data stripes"
    )

    return ErrorCode.SUCCESS, [parity]


def recover_stripe(
    stripes: List[Stripe],
    parity_stripes: List[ParityStripe],
    missing_index: int,
    expected_total_stripes: int = 0,
    original_size: int = 0,
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, Optional[Stripe]]:
    """
    Recover a missing stripe using parity and remaining stripes.

    Uses XOR property: if P = A ^ B ^ C, then A = P ^ B ^ C.
    Can recover any SINGLE missing stripe from the parity and
    remaining data stripes.

    LIMITATION: This function can only recover ONE missing stripe.
    If multiple stripes are missing, recovery is IMPOSSIBLE with
    single XOR parity. Use expected_total_stripes to detect this.

    Args:
        stripes: List of available data Stripe objects (excluding missing)
        parity_stripes: List of ParityStripe objects
        missing_index: Index of the missing stripe to recover
        expected_total_stripes: Total stripes expected (used to detect multiple failures)
                               If 0, skips multiple failure detection (not recommended)
        original_size: Original size of the missing stripe (0 = use parity size)
                      Important for correct recovery when stripes have different sizes
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (ErrorCode, recovered Stripe or None)
        - SUCCESS, recovered stripe on success
        - ERR_INVALID_PARAM, None on invalid inputs
        - ERR_TOO_MANY_FAILURES, None if multiple stripes missing

    C signature:
        ErrorCode recover_stripe(const Stripe* stripes, int stripe_count,
                                  const ParityStripe* parity, int parity_count,
                                  int missing_index, int expected_total,
                                  size_t original_size, Stripe* out_stripe);

    Example:
        err, recovered = recover_stripe(remaining_stripes, parity, missing_index=2,
                                        expected_total_stripes=5, original_size=1024)
        if err == ErrorCode.SUCCESS:
            print(f"Recovered stripe {recovered.index}")
    """
    # Validate inputs
    if stripes is None:
        log_error(logger_handle, PARITY_CONTEXT, "recover_stripe failed", "stripes is None")
        return ErrorCode.ERR_INVALID_PARAM, None

    if parity_stripes is None or len(parity_stripes) == 0:
        log_error(logger_handle, PARITY_CONTEXT, "recover_stripe failed", "parity_stripes is empty")
        return ErrorCode.ERR_INVALID_PARAM, None

    if missing_index < 0:
        log_error(logger_handle, PARITY_CONTEXT, "recover_stripe failed", "missing_index is negative")
        return ErrorCode.ERR_INVALID_PARAM, None

    # Check if missing_index is mistakenly included in stripes
    for stripe in stripes:
        if stripe.index == missing_index:
            log_error(
                logger_handle, PARITY_CONTEXT,
                "recover_stripe failed",
                f"stripe marked as missing (index {missing_index}) is present in provided stripes"
            )
            return ErrorCode.ERR_INVALID_PARAM, None

    # Detect multiple missing stripes if expected_total_stripes is provided
    if expected_total_stripes > 0:
        available_count = len(stripes)
        missing_count = expected_total_stripes - available_count

        if missing_count > 1:
            log_error(
                logger_handle, PARITY_CONTEXT,
                "recover_stripe failed",
                f"cannot recover {missing_count} missing stripes (single parity only recovers 1)"
            )
            return ErrorCode.ERR_TOO_MANY_FAILURES, None

        if missing_count < 1:
            log_warning(
                logger_handle, PARITY_CONTEXT,
                f"Expected {expected_total_stripes} stripes but have {available_count} - no recovery needed?"
            )

    # Get the parity data
    parity = parity_stripes[0]
    max_size = parity.size

    # Recovery: XOR parity with all available stripes
    # If P = A ^ B ^ C and A is missing, then A = P ^ B ^ C
    recovered_data = parity.data

    for stripe in stripes:
        # Pad stripe data to match parity size
        padded_data = _pad_to_length(stripe.data, max_size)
        recovered_data = _xor_bytes(recovered_data, padded_data)

    # Truncate to original size if provided (fixes padding issue)
    if original_size > 0 and original_size < len(recovered_data):
        recovered_data = recovered_data[:original_size]
        recovered_size = original_size
    else:
        recovered_size = len(recovered_data)

    # Calculate checksum for recovered data
    checksum = _calculate_checksum(recovered_data)

    # Create recovered stripe
    recovered = Stripe(
        index=missing_index,
        data=recovered_data,
        size=recovered_size,
        checksum=checksum
    )

    log_debug(
        logger_handle, PARITY_CONTEXT,
        f"Recovered stripe {missing_index} ({recovered_size} bytes) using parity"
    )

    return ErrorCode.SUCCESS, recovered


def verify_integrity(
    stripe_set: StripeSet,
    logger_handle: Optional[object] = None
) -> bool:
    """
    Verify the integrity of a complete stripe set.

    Checks:
    1. All data stripes have valid checksums
    2. Parity is consistent with data stripes

    Args:
        stripe_set: The StripeSet to verify
        logger_handle: Optional logger handle for error reporting

    Returns:
        True if stripe set is valid, False otherwise

    C signature:
        bool verify_integrity(const StripeSet* stripe_set);

    Example:
        if verify_integrity(stripe_set):
            print("Stripe set is valid")
        else:
            print("Stripe set is corrupted!")
    """
    # Validate input
    if stripe_set is None:
        log_error(logger_handle, PARITY_CONTEXT, "verify_integrity failed", "stripe_set is None")
        return False

    if not stripe_set.stripes:
        log_warning(logger_handle, PARITY_CONTEXT, "verify_integrity called with empty stripe set")
        return True  # Empty set is technically valid

    # Verify each data stripe checksum
    for stripe in stripe_set.stripes:
        if not validate_stripe(stripe, logger_handle):
            log_warning(
                logger_handle, PARITY_CONTEXT,
                f"Stripe {stripe.index} failed checksum validation"
            )
            return False

    # If no parity stripes, skip parity verification
    if not stripe_set.parity_stripes:
        log_debug(logger_handle, PARITY_CONTEXT, "No parity stripes to verify")
        return True

    # Recalculate parity and compare
    err, expected_parity = calculate_parity(stripe_set.stripes, logger_handle)
    if err != ErrorCode.SUCCESS:
        log_error(logger_handle, PARITY_CONTEXT, "verify_integrity failed", "could not calculate expected parity")
        return False

    if len(expected_parity) != len(stripe_set.parity_stripes):
        log_warning(
            logger_handle, PARITY_CONTEXT,
            f"Parity count mismatch: expected {len(expected_parity)}, got {len(stripe_set.parity_stripes)}"
        )
        return False

    # Compare parity data
    for i, (expected, actual) in enumerate(zip(expected_parity, stripe_set.parity_stripes)):
        # Pad both to same length for comparison
        max_len = max(len(expected.data), len(actual.data))
        expected_padded = _pad_to_length(expected.data, max_len)
        actual_padded = _pad_to_length(actual.data, max_len)

        if expected_padded != actual_padded:
            log_warning(
                logger_handle, PARITY_CONTEXT,
                f"Parity stripe {i} data mismatch"
            )
            return False

    log_debug(
        logger_handle, PARITY_CONTEXT,
        f"Verified integrity of {len(stripe_set.stripes)} data stripes and {len(stripe_set.parity_stripes)} parity stripes"
    )

    return True


def create_stripe_set(
    stripes: List[Stripe],
    total_size: int = 0,
    encryption_key: bytes = b'',
    logger_handle: Optional[object] = None
) -> Tuple[ErrorCode, Optional[StripeSet]]:
    """
    Create a complete StripeSet with data and parity stripes.

    Convenience function that combines data stripes with calculated
    parity stripes into a complete StripeSet.

    Args:
        stripes: List of data Stripe objects
        total_size: Original data size before striping
        encryption_key: Encryption key used for the data
        logger_handle: Optional logger handle for error reporting

    Returns:
        Tuple of (ErrorCode, StripeSet or None)
        - SUCCESS, complete StripeSet on success
        - ERR_INVALID_PARAM, None on error

    C signature:
        ErrorCode create_stripe_set(const Stripe* stripes, int stripe_count,
                                     size_t total_size, const uint8_t* key,
                                     StripeSet* out_set);
    """
    if stripes is None:
        log_error(logger_handle, PARITY_CONTEXT, "create_stripe_set failed", "stripes is None")
        return ErrorCode.ERR_INVALID_PARAM, None

    # Calculate parity
    err, parity_stripes = calculate_parity(stripes, logger_handle)
    if err != ErrorCode.SUCCESS:
        return err, None

    # Calculate total size if not provided
    if total_size == 0:
        total_size = sum(s.size for s in stripes)

    # Create stripe set
    stripe_set = StripeSet(
        stripes=list(stripes),
        parity_stripes=parity_stripes,
        total_size=total_size,
        encryption_key=encryption_key
    )

    log_debug(
        logger_handle, PARITY_CONTEXT,
        f"Created stripe set: {len(stripes)} data, {len(parity_stripes)} parity, {total_size} bytes total"
    )

    return ErrorCode.SUCCESS, stripe_set


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    """
    Test the parity module with various scenarios.
    """
    import zlib

    print("=" * 60)
    print("parity.py - Test Suite")
    print("=" * 60)

    # Helper to create test stripes
    def make_stripe(index: int, data: bytes) -> Stripe:
        return Stripe(
            index=index,
            data=data,
            size=len(data),
            checksum=zlib.crc32(data) & 0xFFFFFFFF
        )

    # Test 1: Calculate parity for simple stripes
    print("\n1. Testing calculate_parity()...")
    stripe_a = make_stripe(0, b'\x01\x02\x03\x04')
    stripe_b = make_stripe(1, b'\x10\x20\x30\x40')
    stripe_c = make_stripe(2, b'\xAA\xBB\xCC\xDD')

    err, parity = calculate_parity([stripe_a, stripe_b, stripe_c])
    assert err == ErrorCode.SUCCESS
    assert len(parity) == 1
    print(f"   Generated parity: {parity[0].data.hex()}")
    print(f"   Parity size: {parity[0].size} bytes")

    # Verify XOR manually: 0x01^0x10^0xAA = 0xBB, 0x02^0x20^0xBB = 0x99, etc.
    expected_parity = _xor_bytes(_xor_bytes(stripe_a.data, stripe_b.data), stripe_c.data)
    assert parity[0].data == expected_parity
    print("   SUCCESS: Parity calculation correct")

    # Test 2: Recover a missing stripe
    print("\n2. Testing recover_stripe()...")
    # Remove stripe_b and try to recover it
    remaining = [stripe_a, stripe_c]
    err, recovered = recover_stripe(remaining, parity, missing_index=1)
    assert err == ErrorCode.SUCCESS
    assert recovered is not None
    assert recovered.index == 1
    # The recovered data should match stripe_b's data
    assert recovered.data == stripe_b.data
    print(f"   Recovered stripe 1: {recovered.data.hex()}")
    print(f"   Original stripe 1:  {stripe_b.data.hex()}")
    print("   SUCCESS: Stripe recovery correct")

    # Test 3: Verify integrity of valid stripe set
    print("\n3. Testing verify_integrity() with valid data...")
    err, stripe_set = create_stripe_set([stripe_a, stripe_b, stripe_c])
    assert err == ErrorCode.SUCCESS
    assert verify_integrity(stripe_set)
    print(f"   Stripe set: {len(stripe_set.stripes)} data, {len(stripe_set.parity_stripes)} parity")
    print("   SUCCESS: Valid stripe set verified")

    # Test 4: Verify integrity detects corruption
    print("\n4. Testing verify_integrity() with corrupted data...")
    # Corrupt a stripe
    corrupted_stripe = Stripe(
        index=1,
        data=b'\xFF\xFF\xFF\xFF',  # Wrong data
        size=4,
        checksum=stripe_b.checksum  # Wrong checksum for this data
    )
    corrupted_set = StripeSet(
        stripes=[stripe_a, corrupted_stripe, stripe_c],
        parity_stripes=parity,
        total_size=12
    )
    assert not verify_integrity(corrupted_set)
    print("   SUCCESS: Corruption detected")

    # Test 5: Recovery with different size stripes
    print("\n5. Testing with different size stripes...")
    stripe_short = make_stripe(0, b'\x01\x02')
    stripe_long = make_stripe(1, b'\x10\x20\x30\x40\x50')

    err, parity_diff = calculate_parity([stripe_short, stripe_long])
    assert err == ErrorCode.SUCCESS
    assert parity_diff[0].size == 5  # Should be size of longest stripe
    print(f"   Short stripe: {len(stripe_short.data)} bytes")
    print(f"   Long stripe: {len(stripe_long.data)} bytes")
    print(f"   Parity size: {parity_diff[0].size} bytes")
    print("   SUCCESS: Different size stripes handled")

    # Test 6: Recover short stripe from long parity
    print("\n6. Testing recovery with size mismatch...")
    err, recovered_short = recover_stripe([stripe_long], parity_diff, missing_index=0)
    assert err == ErrorCode.SUCCESS
    # Recovered data will be padded to parity size
    # First 2 bytes should match original short stripe (padded with zeros)
    assert recovered_short.data[:2] == stripe_short.data
    print(f"   Recovered (first 2 bytes): {recovered_short.data[:2].hex()}")
    print(f"   Original:                  {stripe_short.data.hex()}")
    print("   SUCCESS: Short stripe recovered correctly")

    # Test 7: Empty stripe handling
    print("\n7. Testing empty stripes...")
    err, empty_parity = calculate_parity([])
    assert err == ErrorCode.SUCCESS
    assert len(empty_parity) == 0
    print("   SUCCESS: Empty stripes handled")

    # Test 8: Single stripe parity
    print("\n8. Testing single stripe parity...")
    err, single_parity = calculate_parity([stripe_a])
    assert err == ErrorCode.SUCCESS
    assert single_parity[0].data == stripe_a.data
    print("   SUCCESS: Single stripe parity equals original")

    # Test 9: Large stripes
    print("\n9. Testing with large stripes (16KB each)...")
    import os
    large_a = make_stripe(0, os.urandom(16 * 1024))
    large_b = make_stripe(1, os.urandom(16 * 1024))
    large_c = make_stripe(2, os.urandom(16 * 1024))

    err, large_parity = calculate_parity([large_a, large_b, large_c])
    assert err == ErrorCode.SUCCESS
    print(f"   Parity size: {large_parity[0].size} bytes")

    # Recover large_b
    err, recovered_large = recover_stripe([large_a, large_c], large_parity, missing_index=1)
    assert err == ErrorCode.SUCCESS
    assert recovered_large.data == large_b.data
    print("   SUCCESS: Large stripe recovery correct")

    # Test 10: Create complete stripe set
    print("\n10. Testing create_stripe_set()...")
    test_stripes = [
        make_stripe(0, b'Hello'),
        make_stripe(1, b'World'),
        make_stripe(2, b'QMail')
    ]
    err, full_set = create_stripe_set(test_stripes, total_size=15, encryption_key=b'testkey')
    assert err == ErrorCode.SUCCESS
    assert len(full_set.stripes) == 3
    assert len(full_set.parity_stripes) == 1
    assert full_set.total_size == 15
    assert full_set.encryption_key == b'testkey'
    print(f"   Created set: {len(full_set.stripes)} data, {len(full_set.parity_stripes)} parity")
    print(f"   Total size: {full_set.total_size}")
    print("   SUCCESS: Complete stripe set created")

    # Test 11: Multiple missing stripes detection (expected_total_stripes)
    print("\n11. Testing multiple missing stripes detection...")
    # Create 5 stripes, provide only 3, try to recover (2 missing = should fail)
    five_stripes = [make_stripe(i, f"stripe{i}".encode()) for i in range(5)]
    err, five_parity = calculate_parity(five_stripes)
    assert err == ErrorCode.SUCCESS

    # Only provide stripes 0 and 2 (missing 1, 3, 4) - should fail
    partial_stripes = [five_stripes[0], five_stripes[2]]
    err, _ = recover_stripe(partial_stripes, five_parity, missing_index=1,
                           expected_total_stripes=5)
    assert err == ErrorCode.ERR_TOO_MANY_FAILURES
    print("   SUCCESS: Multiple missing stripes correctly detected")

    # Test 12: Mistaken missing_index validation
    print("\n12. Testing mistaken missing_index validation...")
    # Try to recover index 1 but include stripe 1 in the list
    err, _ = recover_stripe([stripe_a, stripe_b, stripe_c], parity, missing_index=1)
    assert err == ErrorCode.ERR_INVALID_PARAM
    print("   SUCCESS: Mistaken missing_index detected")

    # Test 13: Original size truncation
    print("\n13. Testing original_size truncation...")
    # Recover short stripe with original_size parameter
    err, recovered_correct = recover_stripe([stripe_long], parity_diff, missing_index=0,
                                            original_size=2)
    assert err == ErrorCode.SUCCESS
    assert len(recovered_correct.data) == 2
    assert recovered_correct.data == stripe_short.data
    assert recovered_correct.size == 2
    print(f"   Recovered with original_size=2: {recovered_correct.data.hex()}")
    print(f"   Original short stripe:          {stripe_short.data.hex()}")
    print("   SUCCESS: Original size truncation works correctly")

    print("\n" + "=" * 60)
    print("All parity tests passed!")
    print("=" * 60)
