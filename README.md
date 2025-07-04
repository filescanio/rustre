# Rustre - Rust Binary Analysis Tool

A tool for analyzing Rust binaries to extract information about dependencies, source paths, and Rust compiler versions.

## Project Structure

```
rustre/
├── src/
│   ├── lib.rs          # Core analysis functionality
│   └── main.rs         # CLI application
├── tests/
│   ├── integration_tests.rs  # Comprehensive integration tests
│   └── samples/        # Test sample files (zipped)
├── real-malware/       # Actual binary files for testing
├── rust_versions.json  # Mapping of rustc hashes to Rust versions
├── tools/              # Helper scripts
└── Cargo.toml         # Project configuration
```

## Features

- **Package Detection**: Extracts Rust crate dependencies and their versions from binaries
- **Source Path Analysis**: Identifies framework vs user source code paths
- **Rust Version Detection**: Maps rustc commit hashes to Rust version numbers
- **Cross-Platform**: Supports both Linux ELF and Windows PE binaries

## Usage

```bash
# Build the project
cargo build --release

# Analyze a binary
./target/release/rustre path/to/binary

# Run tests
cargo test
```

## Output Format

The tool outputs JSON with the following structure:

```json
{
  "packages": [
    {
      "path": "/cargo/registry/src/index.crates.io-6f17d22bba15001f/package-1.0.0",
      "name": "package",
      "version": "1.0.0"
    }
  ],
  "framework_source_paths": [
    "/std/src/path.rs",
    "/cargo/registry/src/..."
  ],
  "user_source_paths": [
    "/src/main.rs",
    "/src/lib.rs"
  ],
  "rustc_hash": "84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc",
  "rust_version": "1.69.0"
}
```

## Testing

The project includes comprehensive integration tests for all sample files:

- **ELF binaries**: Tests Linux Rust executables
- **PE binaries**: Tests Windows Rust executables  
- **Version mapping**: Validates rustc hash to version correlation
- **Error handling**: Tests invalid file scenarios
- **Package uniqueness**: Ensures proper package deduplication

### Test Setup Options

The tests can work with sample files in three ways:

1. **Password-protected ZIP files** (default):
   - Files in `tests/samples/*.zip` with password "infected"
   - Uses pure Rust zip extraction if possible
   - Falls back to system `unzip` command if needed

2. **Pre-extracted files** (environment variable):
   ```bash
   # Extract files to a directory
   mkdir -p /tmp/rustre_samples
   cd /tmp/rustre_samples
   unzip -P infected /path/to/rustre/tests/samples/*.zip
   
   # Set environment variable
   export RUSTRE_TEST_SAMPLES_DIR=/tmp/rustre_samples
   cargo test
   ```

3. **Pre-extracted files** (default locations):
   - Linux: `/tmp/rustre_samples/`
   - Windows: `%TEMP%\rustre_samples\`

### Test Files

The `tests/integration_tests.rs` file contains individual tests for each binary sample:

- `test_sample_*.elf()` - Tests for Linux binaries
- `test_sample_*.exe()` - Tests for Windows binaries
- `test_version_mappings_functionality()` - Tests version lookup
- `test_analyze_binary_error_handling()` - Tests error cases
- `test_package_uniqueness()` - Tests package deduplication

Each test validates:
- Expected packages and their versions
- Rustc hash detection
- Rust version mapping
- User vs framework source path classification
- Error handling for edge cases

### Sample Files

The test samples include real Rust malware binaries that demonstrate different patterns:

- **Simple binaries**: Basic Rust programs with minimal dependencies
- **Complex binaries**: GUI applications with many dependencies
- **Source code traces**: Binaries containing user source paths (valuable for malware analysis)

## Key Insights from Tests

1. **Linux vs Windows**: Different cargo registry paths (`index.crates.io` vs `github.com`)
2. **Version patterns**: Different Rust versions have different rustc hashes
3. **Source code leakage**: Some binaries contain user source paths, which is valuable for malware analysis
4. **Dependency complexity**: GUI applications can have 20+ dependencies

## Development

The modular structure separates concerns:

- `src/lib.rs`: Contains all analysis logic, data structures, and utility functions
- `src/main.rs`: Simple CLI wrapper that calls the library
- `tests/integration_tests.rs`: Comprehensive tests based on real binary samples

This structure makes the code:
- **Testable**: Easy to write unit and integration tests
- **Maintainable**: Clear separation of CLI and core logic
- **Reusable**: Library can be used by other projects
- **Extensible**: New analysis features can be added to the library

## Dependencies

- `regex`: For pattern matching in binary data
- `serde`: For JSON serialization
- `serde_json`: For JSON output formatting 