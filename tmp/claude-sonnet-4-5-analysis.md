# QMail Client Core Configuration Analysis
**Author:** Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
**Date:** 2025-12-11
**Last Updated:** 2025-12-11 (Added RAIDA server list and clarifications)

## Executive Summary

After reviewing the comprehensive documentation (overview, plan, API specs, server protocol specs, and database schema), I recommend:

1. **Extract all config keys NOW** rather than incrementally
2. **Use TOML format** instead of JSON
3. **Name the file:** `qmail.toml`

## Detailed Analysis

### 1. Incremental vs. Complete Extraction

**Recommendation: EXTRACT NOW**

**Rationale:**
- The documentation is comprehensive and well-defined
- We have clear specifications for Phase I and Phase II features
- Extracting now provides:
  - Complete roadmap of configuration requirements
  - Prevention of rework during implementation
  - Early identification of missing requirements
  - Better documentation for development team
  - Validation that we haven't missed critical config items

**Approach:**
- Extract all config keys from documentation
- Clearly mark Phase I (immediate) vs Phase II (future)
- Distinguish between:
  - User-configurable settings
  - System-managed values
  - Required vs optional parameters
  - Runtime vs startup configuration

### 2. Configuration File Format

**Recommendation: TOML**

**Format Comparison:**

| Criterion | JSON | INI | TOML | Winner |
|-----------|------|-----|------|--------|
| Human Readable | Good | Excellent | Excellent | INI/TOML |
| Human Editable | Fair | Excellent | Excellent | INI/TOML |
| Nested Structures | Excellent | Poor | Excellent | JSON/TOML |
| Data Types | Good | Poor | Excellent | TOML |
| Comments | No | Yes | Yes | INI/TOML |
| C Parsing Libraries | Many | Simple | Available | INI |
| Memory Usage | ~1-2KB | ~0.5KB | ~1KB | All acceptable |
| Python Support | Built-in | Built-in | Library (tomllib) | JSON/INI |
| C Conversion Ease | Medium | Easy | Medium | INI |
| Industry Standard | Yes | Legacy | Modern | JSON/TOML |

**Why TOML wins:**
1. **Best of both worlds**: Human-friendly like INI but supports complex structures like JSON
2. **Strong typing**: Explicit booleans, integers, floats, dates - important for C conversion
3. **Comments**: Critical for documenting Phase I/II distinctions and explaining parameters
4. **Nested tables**: Clean organization of related settings (servers, crypto, network, etc.)
5. **Arrays**: Clean syntax for server lists and other arrays
6. **C parsing**: Libraries like `tomlc99` make parsing straightforward
7. **Industry momentum**: Increasingly used for configuration (Cargo, pip, etc.)

**Memory considerations:**
- For this config file: JSON ~1.5KB, INI ~0.8KB, TOML ~1KB
- Difference is negligible (< 1KB) in context of email client
- Runtime memory of parsed config is identical regardless of format

### 3. Configuration File Naming

**Recommendation: `qmail.toml`**

**Alternatives considered:**
- `qmail-client.toml` - Too verbose
- `config.toml` - Not descriptive enough
- `qmail.conf` - Generic, format-agnostic (good fallback)
- `qmail.ini` - Format-specific but dated
- `default_config.toml` - Implies there are variants

**Rationale for `qmail.toml`:**
- Short and descriptive
- Format-specific extension helps editors provide syntax highlighting
- Standard convention (application_name.toml)
- Works cross-platform
- Clear that it's THE config file, not one of many

### 4. Configuration Keys Extracted from Documentation

#### Phase I (Immediate Implementation)

**Core System:**
- `db_path` - SQLite database location ✓ (in prototype)
- `log_path` - mail.mlog file location ✓ (in prototype)
- `log_level` - Debug, Info, Warning, Error ✗ (missing)
- `log_buffer_size` - For flush optimization ✗ (missing)

**Network & Servers:**
- `server_list[]` - QMail server addresses/ports ✓ (in prototype)
- `server_connection_timeout_ms` - TCP timeout ✗ (missing)
- `server_max_retries` - Retry attempts ✗ (missing)
- `beacon_url` - Beacon server TCP address ✓ (in prototype)
- `beacon_interval_sec` - Check interval (600s) ✓ (in prototype)
- `guardian_servers[]` - Guardian server URLs ✗ (missing, from beacon docs)
- `raida_beacon_index` - Which RAIDA is beacon (14) ✗ (missing)

**Data Striping & RAID:**
- `data_stripe_count` - Number of data stripes (4) ✓ (in prototype)
- `parity_stripe_count` - Number of parity stripes (1) ✓ (in prototype)
- `stripe_size_bytes` - Size of each stripe ✗ (missing)
- `raid_type` - RAID configuration type ✗ (missing)

**Encryption:**
- `encryption_enabled` - Master switch ✓ (in prototype)
- `encryption_mode` - "A" (session) or "B" (AN) ✗ (missing)
- `aes_key_size` - 128 bits per spec ✗ (missing)

**Threading & Concurrency:**
- `thread_pool_size` - Worker thread count (5) ✓ (in prototype)
- `max_concurrent_uploads` - Parallel stripe uploads ✗ (missing)
- `max_concurrent_downloads` - Parallel stripe downloads ✗ (missing)

**API Server:**
- `api_host` - Bind address (127.0.0.1) ✓ (in prototype)
- `api_port` - Port number (null in prototype) ✓ (in prototype)
- `api_enable_cors` - CORS for web GUIs ✗ (missing)
- `api_max_request_size_mb` - Upload limits ✗ (missing)

**User Identity:**
- `user_coin_type` - Fixed 0x0006 per spec ✗ (missing)
- `user_denomination` - User's denomination ✗ (missing)
- `user_serial_number` - Mailbox ID (4 bytes) ✗ (missing)
- `user_device_id` - 16-bit device identifier ✗ (missing)
- `user_authenticity_number` - For Mode B encryption ✗ (missing)

**CloudCoin / Payment:**
- `locker_storage_path` - Where locker files are kept ✗ (missing)
- `default_storage_duration` - For uploads ✗ (missing)
- `auto_withdraw_enabled` - Auto-pay from locker ✗ (missing)

**Email Processing:**
- `max_attachment_size_mb` - Per-file limit ✗ (missing)
- `max_email_size_mb` - Total email limit ✗ (missing)
- `cbdf_compression_level` - 0-9 ✗ (missing)

#### Phase II (Future Features)

**Advanced Search:**
- `search_index_update_interval_sec`
- `search_results_max`
- `search_enable_fts5`

**AI Features:**
- `ai_semantic_encoding_enabled`
- `ai_image_processing_enabled`
- `ai_avatar_generation_enabled`

**Enhanced CloudCoin:**
- `cloudcoin_validation_strictness`
- `payment_retry_attempts`
- `locker_backup_path`

**Advanced Network:**
- `network_bandwidth_limit_kbps`
- `network_prefer_ipv6`
- `proxy_enabled`
- `proxy_address`

**Content Processing:**
- `max_subject_length`
- `enable_subject_formatting`
- `signature_storage_path`
- `avatar_storage_path`

#### System-Managed (Not User-Editable)

These should be in a separate runtime state file or database:
- Session IDs (ephemeral)
- Current server status/ping times
- Active task states
- Statistics (calls, bandwidth, uptime)

### 5. Configuration Organization

**Proposed TOML Structure:**

```toml
# Top-level metadata
[metadata]
version = "1.0.0"
phase = "I"

# Grouped by functional area
[system]
[logging]
[database]
[network]
[network.beacon]
[network.servers]
[striping]
[encryption]
[threading]
[api]
[identity]
[cloudcoin]
[email]
```

### 6. Additional Recommendations

**Multi-file strategy:**
1. `qmail.toml` - User-editable configuration
2. `qmail-defaults.toml` - Shipped defaults (don't edit)
3. `qmail-state.json` - Runtime state (auto-generated)
4. `qmail-secrets.toml` - Sensitive data (excluded from version control)

**Configuration validation:**
- Implement `validate_config()` function early
- Check for required vs optional fields
- Validate ranges (ports, timeouts, sizes)
- Verify file paths exist or can be created
- Validate server addresses/URLs

**Future C conversion:**
- Use simple types (int, float, string, bool)
- Avoid complex nested structures where possible
- Document units explicitly (bytes vs KB vs MB, seconds vs milliseconds)
- Use consistent naming (snake_case throughout)

### 7. Questions for User

1. **User identity**: How will users configure their mailbox ID? Environment variable? Setup wizard? Hardcoded for now?

2. **API port**: Should we default to a specific port (e.g., 8080) or random available port?

3. **Secrets management**: Should sensitive data (authenticity numbers, locker keys) be in a separate file?

4. **Server list**: Is the current server list definitive for Phase I, or will it change?

5. **Stripe size**: What's the default stripe size in bytes? Not specified in docs.

6. **Guardian servers**: Should we fetch the RAIDA list from guardians.csv or hardcode for Phase I?

## Conclusion

Extract all configuration requirements now, organize in TOML format as `qmail.toml`, with clear Phase I/II markings and comprehensive comments. This provides the development roadmap and prevents rework while maintaining excellent human-readability and C-conversion compatibility.
