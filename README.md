# 🔍 Rustre — Rust Binary Inspector

Analyze compiled Rust executables and print a clear JSON report.

## ✨ Features
- 📦 Extracts crate names and versions found in the binary (from embedded Cargo registry paths)
- 🧭 Lists source paths found inside the binary (separates framework vs user paths)
- 🧬 Detects the embedded rustc commit hash and maps it to a Rust version (using `rust_versions.json`)
- 🖨️ Outputs structured JSON to stdout
- 🖥️ Works with typical Linux ELF and Windows PE binaries (no disassembly; pure byte scan)

## 🚀 Quick start
### Download a prebuilt release (easiest)
- Go to this repository's Releases page and download the archive for your platform:
  - `x86_64-unknown-linux-gnu` (Linux)
  - `x86_64-apple-darwin` (macOS)
  - `x86_64-pc-windows-msvc` (Windows)
- Extract the archive. It contains the `rustre`/`rustre.exe` binary and `rust_versions.json`.
- Run it:
  - Linux/macOS: `./rustre path/to/binary`
  - Windows: `rustre.exe path\to\binary`

### Build from source
```bash
cargo build --release
./target/release/rustre path/to/binary
```

The tool prints a JSON object like:
```json
{
  "packages": [ { "path": ".../tokio-1.0.0", "name": "tokio", "version": "1.0.0" } ],
  "framework_source_paths": ["/std/..."],
  "user_source_paths": ["/home/.../src/main.rs"],
  "rustc_hash": "<40-hex>",
  "rust_version": "<resolved version or null>"
}
```

## 🔄 Update the Rust version database (optional)
`rust_versions.json` maps rustc commit hashes to released versions. To refresh it from GitHub:
```bash
./target/release/rustre --update-versions
```
This writes a new `rust_versions.json` in the current directory.

## Notes
- Offline by default; no network calls during analysis.
- `rust_versions.json` must be readable from the current working directory to resolve versions. If it’s missing, the JSON field `rust_version` will be `null` (the hash is still shown when present).
- Heuristic approach: results depend on what the compiler embedded; some binaries may expose more or fewer details.

## License
See `LICENSE.txt`.