# QMail Client Core Configuration Recommendations
**Author:** Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
**Last Updated:** 2025-12-11 (Added RAIDA servers and clarifications)

## Direct Answers to Your Questions

### 1. Should we add to config incrementally or extract everything now?

**Answer: Extract everything now.**

**Why:**
- You have comprehensive, well-documented specifications
- The architecture is clearly defined with Phase I and Phase II demarcations
- Extracting now gives you:
  - Complete visibility into all requirements
  - Prevention of rework during implementation
  - A roadmap for both immediate and future needs
  - Early validation that nothing is missing
  - Better planning for the C conversion

**How I did it:**
- Read all documentation in docs/ folder
- Extracted every configurable parameter mentioned
- Organized into logical groups
- Marked each with [Phase I] or [Phase II]
- Indicated [Required] vs [Optional]
- Provided sensible defaults where possible

### 2. Should we use JSON or something else (INI/TOML)?

**Answer: Use TOML**

**Comparison:**

| Format | Pros | Cons | Verdict |
|--------|------|------|---------|
| **JSON** | Built-in Python support, well-known | No comments, verbose, harder to hand-edit, no explicit types | ❌ Not recommended |
| **INI** | Very simple, extremely human-readable, smallest RAM | Poor nesting, limited types, dated | ⚠️ Acceptable but limited |
| **TOML** | Human-readable, supports comments, strong typing, good nesting, modern | Requires library in Python | ✅ **Recommended** |

**Why TOML wins:**
1. **Human-readable and editable** - Just as easy as INI
2. **Comments** - Critical for documenting phase distinctions and explaining parameters
3. **Strong typing** - Explicit booleans, integers, floats (important for C conversion)
4. **Nested structures** - Clean organization (e.g., [network.beacon], [identity.profile])
5. **Arrays** - Clean syntax for server lists
6. **Industry momentum** - Used by Rust (Cargo), Python (pyproject.toml), etc.
7. **C parsing libraries** - tomlc99, toml-c, etc. make conversion straightforward
8. **RAM usage** - Negligible difference for config files (<1KB difference)

**Python support:**
- Built-in as of Python 3.11: `import tomllib` (read-only)
- For write support: `pip install tomli-w`
- For full support: `pip install toml`

**C conversion:**
- Use `tomlc99` library (https://github.com/cktan/tomlc99)
- Simple API: `toml_parse_file()` -> struct
- No complex parsing code needed

### 3. What should we name the config file?

**Answer: `qmail.toml`**

**Alternatives considered:**
- `config.toml` - Too generic
- `qmail-client.toml` - Too verbose
- `default_config.toml` - Implies there are variants
- `qmail.conf` - Format-agnostic but less specific
- `qmail.ini` - Format-specific but dated format

**Why `qmail.toml`:**
- Short and descriptive
- Standard convention (app_name.format)
- Format-specific extension helps editors (syntax highlighting)
- Cross-platform compatible
- Clear it's THE config file

### 4. Configuration File Strategy

I recommend a **multi-file approach**:

1. **`qmail.toml`** - Main user-editable configuration
   - Shipped with sensible defaults
   - User modifies for their environment
   - Version controlled with sample values

2. **`qmail-secrets.toml`** - Sensitive data (Phase II)
   - Authenticity numbers
   - API keys
   - Locker keys
   - **NOT version controlled** (in .gitignore)

3. **`qmail-state.json`** - Runtime state (auto-generated)
   - Session IDs
   - Server ping times
   - Task states
   - Statistics
   - **NOT version controlled**
   - JSON is fine here (machine-written, not edited)

4. **`qmail-defaults.toml`** - Shipped defaults (optional)
   - Read-only reference
   - Users don't modify
   - Helps with upgrades

### 5. Clarifications Received (Updated 2025-12-11)

**RESOLVED:**
1. ✅ **Stripe size** - Variable, calculated dynamically as ~25% of document size
   - Each of 4 data stripes: document_size * 0.25
   - Parity stripe: also ~25% of total document size
   - NOT a config parameter - calculated at runtime

2. ✅ **RAIDA Guardian servers** - Complete list of 25 servers provided
   - IPs and ports for all RAIDA servers (index 0-24)
   - Beacon is RAIDA #14: 168.220.219.199:50014
   - All servers included in configuration file

3. ✅ **QMail storage servers** - 5 servers confirmed:
   - 47.229.9.94:50001
   - 124.187.106.233:50009
   - 113.30.247.109:50013
   - 168.220.219.199:50014 (also beacon)
   - 125.236.210.184:50021

4. ✅ **Thread pool size** - Minimum 5 required
   - One thread per QMail server for parallel operations
   - Configured as default in TOML file

5. ✅ **API port** - Must be specified at startup
   - Use command-line argument: --port 8080
   - Allows flexible port assignment without config changes

6. ✅ **User wallets location** - build/Data/Wallets/
   - User identity (denomination/serial number) loaded from wallet files
   - No need to configure path in config file

7. ✅ **Directory naming** - Use "Data" (capitalized)
   - Data/qmail.db
   - Data/mail.mlog
   - Consistent capitalization throughout

**Still to be documented:**
1. ❓ **Storage duration codes** - Meaning of codes 0-255 for upload duration
2. ❓ **Session ID generation** - Client or server responsibility?
3. ❓ **Device ID assignment** - Per-installation or per-machine?

### 6. Phase I vs Phase II Organization

**Phase I (Implement Now):**
- Core system paths (db, logs)
- Network & server configuration
- Striping & RAID parameters
- Basic encryption (Mode A)
- Threading configuration
- REST API basics
- User identity (serial number, denomination)
- Basic CloudCoin (locker path)
- Email size limits

**Phase II (Future):**
- AI features (semantic encoding, image processing)
- Advanced formatting
- Enhanced CloudCoin features
- Advanced networking (proxy, bandwidth limits)
- API authentication
- Advanced search parameters

**How to handle:**
- All Phase II settings are in the TOML file but commented out or set to `false`
- Clear comments indicate "[Phase II]"
- When implementing Phase II, just uncomment and set appropriately
- No config file restructuring needed later

### 7. Validation Strategy

**Implement `validate_config()` early:**

```python
def validate_config(config):
    """Validate configuration and return list of errors/warnings"""
    errors = []
    warnings = []

    # Check required fields
    if not config['database']['db_path']:
        errors.append("db_path is required")

    # Validate ranges
    if not (1 <= config['identity']['denomination'] <= 250):
        errors.append("denomination must be 1-250")

    # Validate paths
    db_dir = os.path.dirname(config['database']['db_path'])
    if not os.path.exists(db_dir):
        warnings.append(f"Database directory {db_dir} does not exist")

    # Validate network
    if config['striping']['data_stripe_count'] > len(config['network']['servers']):
        errors.append("Not enough servers for stripe count")

    return errors, warnings
```

### 8. C Conversion Considerations

**Design decisions for easier C conversion:**

1. **Simple types** - int, float, string, bool (no complex objects)
2. **Flat arrays** - `[[network.servers]]` becomes `struct server_config servers[]`
3. **Explicit units** - `timeout_ms`, `size_mb`, `interval_sec` (not ambiguous)
4. **Snake_case** - Consistent naming converts to C easily
5. **No dynamic keys** - All keys known at compile time
6. **Bounded arrays** - Document max sizes (e.g., "max 25 servers")

**Example C struct mapping:**

```c
// TOML: [network.servers]
typedef struct {
    char address[16];  // IPv4 address
    uint16_t port;
    char server_type[8];
    int priority;
} server_config_t;

// TOML: [striping]
typedef struct {
    int data_stripe_count;
    int parity_stripe_count;
    size_t stripe_size_bytes;
    char raid_type[16];
    int min_stripes_for_recovery;
} striping_config_t;

// Main config
typedef struct {
    // ... metadata ...
    database_config_t database;
    network_config_t network;
    striping_config_t striping;
    // ... etc ...
} qmail_config_t;
```

## Files Created

1. **`claude-sonnet-4-5-analysis.md`** - Detailed analysis and reasoning
2. **`claude-sonnet-4-5-qmail.toml`** - Complete configuration file with all extracted keys
3. **`claude-sonnet-4-5-recommendations.md`** - This file (direct answers)

## Update Summary (2025-12-11)

### Changes Made:
1. **Added complete RAIDA server list** - All 25 Guardian servers with IP:port
2. **Clarified QMail storage servers** - 5 servers explicitly listed for stripe distribution
3. **Updated stripe size documentation** - Noted as variable/calculated (not a config param)
4. **Updated thread pool minimum** - Documented minimum of 5 threads required
5. **Clarified API port handling** - Must be specified via command-line argument
6. **Added wallet location reference** - build/Data/Wallets/ for user identity
7. **Ensured consistent capitalization** - "Data" directory throughout

### Configuration File Status:
- ✅ All Phase I requirements extracted
- ✅ All server lists populated (RAIDA + QMail)
- ✅ Stripe calculation documented
- ✅ Thread requirements clarified
- ✅ User identity workflow documented
- ⚠️ Some Phase II features marked but not fully specified

## Next Steps

1. **Review the TOML file** - Check if all parameters make sense
2. **Implement command-line argument parsing** - Add --port flag for API server
3. **Set user identity** - Configure denomination and serial_number from wallets
4. **Test loading** - Write `config.py` module to load TOML
5. **Implement validation** - Add `validate_config()` function
6. **Start implementation** - Begin with logger.py using config values
