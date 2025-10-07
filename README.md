# 🔍 Rustre - Rust Binary Forensics Tool

> **Uncover the secrets hidden in Rust binaries** - Extract dependencies, source paths, and compiler versions from compiled Rust executables

## ✨ What Makes This Special

🕵️ **Reverse Engineering Made Easy** - Analyze Rust malware and binaries to understand their composition  
📦 **Dependency Detective** - Extract exact crate versions used in compilation  
🔗 **Source Path Leakage** - Discover leaked developer paths (goldmine for malware analysis)  
🦀 **Rust Version Fingerprinting** - Map compiler hashes to exact Rust versions  
🌐 **Cross-Platform** - Works on both Linux ELF and Windows PE binaries  

## 🚀 Quick Start

```bash
# Build and run
cargo build --release
./target/release/rustre path/to/binary

# That's it! Get instant insights about any Rust binary
```

## 📊 What You'll Get

```json
{
  "packages": [
    { "name": "tokio", "version": "1.25.0" },
    { "name": "serde", "version": "1.0.152" }
  ],
  "user_source_paths": [
    "/home/attacker/malware/src/main.rs"  // 🎯 Jackpot!
  ],
  "framework_source_paths": [
    "/std/src/path.rs"
  ],
  "rust_version": "1.69.0"
}
```

## 🎯 Perfect For

- **🔐 Security Researchers** - Analyze Rust malware and suspicious binaries
- **📝 Forensic Analysts** - Extract compilation artifacts and source intelligence  
- **🐛 Reverse Engineers** - Understand binary composition and dependencies
- **🔍 Threat Hunters** - Fingerprint Rust-based threats

## 💡 Why This Matters

Most binary analysis tools ignore Rust-specific artifacts. **Rustre** extracts the goldmine of information that Rust compilers accidentally embed:

- **Developer machine paths** (often leaked in binaries)
- **Exact dependency versions** (crucial for vulnerability analysis)
- **Compilation environment details** (helps profile attackers)
- **Framework vs custom code separation** (focus your analysis)

## 🧪 Battle-Tested

Tested against real-world Rust malware samples including:
- Simple command-line tools
- Complex GUI applications  
- Sophisticated malware with 20+ dependencies
- Both Linux and Windows executables

## 🏗️ Architecture

```
rustre/
├── src/lib.rs          # 🧠 Core analysis engine
├── src/main.rs         # 🖥️  CLI interface
├── tests/              # 🧪 Real malware samples
└── tools/              # 🔧 Helper utilities
```

## 🤝 Contributing

Found an interesting binary that breaks the tool? Have ideas for new features? PRs welcome!

---

*Built with 🦀 Rust | Perfect for 🔍 Binary Analysis | Loved by 🕵️ Security Researchers* 