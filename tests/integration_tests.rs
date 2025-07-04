use std::collections::HashSet;
use std::fs::File;

use std::path::PathBuf;
use tempfile::TempDir;
use zip::ZipArchive;
use rustre::{analyze_binary, load_version_mappings, Package};

/// Helper function to extract a password-protected zip file and return the path to the extracted binary
fn extract_sample(zip_name: &str) -> (TempDir, PathBuf) {
    let zip_path = format!("tests/samples/{}", zip_name);
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Extract using pure Rust zip crate with password "infected"
    let file = File::open(&zip_path).expect(&format!("Failed to open zip file: {}", zip_path));
    let mut archive = ZipArchive::new(file).expect("Failed to read zip archive");
    
    // Get the first file in the archive
    let mut zip_file = archive.by_index_decrypt(0, b"infected")
        .expect("Failed to decrypt file with password 'infected'");
    
    let outpath = temp_dir.path().join(zip_file.name());
    
    // Security check to prevent directory traversal
    if !outpath.starts_with(temp_dir.path()) {
        panic!("Invalid zip file path detected");
    }
    
    let mut outfile = File::create(&outpath).expect("Failed to create output file");
    std::io::copy(&mut zip_file, &mut outfile).expect("Failed to extract file");
    
    (temp_dir, outpath)
}

#[test]
fn test_sample_005f7884f04fd8be032c875a714a6413933d6cebcda2b4fb06de2f88a42bb089_elf() {
    let filename = "005f7884f04fd8be032c875a714a6413933d6cebcda2b4fb06de2f88a42bb089.elf";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // Test expected packages
    let expected_packages = vec![
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/rustc-demangle-0.1.21".to_string(), name: "rustc-demangle".to_string(), version: "0.1.21".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/gimli-0.26.2".to_string(), name: "gimli".to_string(), version: "0.26.2".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/miniz_oxide-0.5.3".to_string(), name: "miniz_oxide".to_string(), version: "0.5.3".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/addr2line-0.17.0".to_string(), name: "addr2line".to_string(), version: "0.17.0".to_string() },
    ];
    
    // Check that all expected packages are present
    for expected_pkg in expected_packages {
        assert!(result.packages.contains(&expected_pkg), "Missing package: {:?}", expected_pkg);
    }
    
    // Test user source paths (should be empty for malware samples)
    assert!(result.user_source_paths.is_empty(), "User source paths should be empty");
    
    // Test rustc hash and version
    assert_eq!(result.rustc_hash, Some("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc".to_string()));
    assert_eq!(result.rust_version, Some("1.69.0".to_string()));
    
    // Test that we have packages
    assert!(!result.packages.is_empty(), "Packages list should not be empty");
}

#[test]
fn test_sample_42b0897474819a5d21de10488fdc539eea10b96d6e0679d9836bd4c6b40875aa_elf() {
    let filename = "42b0897474819a5d21de10488fdc539eea10b96d6e0679d9836bd4c6b40875aa.elf";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // Test expected packages
    let expected_packages = vec![
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/addr2line-0.17.0".to_string(), name: "addr2line".to_string(), version: "0.17.0".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/miniz_oxide-0.5.3".to_string(), name: "miniz_oxide".to_string(), version: "0.5.3".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/gimli-0.26.2".to_string(), name: "gimli".to_string(), version: "0.26.2".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/rustc-demangle-0.1.21".to_string(), name: "rustc-demangle".to_string(), version: "0.1.21".to_string() },
    ];
    
    for expected_pkg in expected_packages {
        assert!(result.packages.contains(&expected_pkg), "Missing package: {:?}", expected_pkg);
    }
    
    assert!(result.user_source_paths.is_empty());
    assert_eq!(result.rustc_hash, Some("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc".to_string()));
    assert_eq!(result.rust_version, Some("1.69.0".to_string()));
    assert!(!result.packages.is_empty());
}

#[test]
fn test_sample_5255ea080acd85ad274c48d1c4254c285c24f5ea67787666005c9a47c62ceb70_elf() {
    let filename = "5255ea080acd85ad274c48d1c4254c285c24f5ea67787666005c9a47c62ceb70.elf";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    let expected_packages = vec![
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/addr2line-0.17.0".to_string(), name: "addr2line".to_string(), version: "0.17.0".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/miniz_oxide-0.5.3".to_string(), name: "miniz_oxide".to_string(), version: "0.5.3".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/rustc-demangle-0.1.21".to_string(), name: "rustc-demangle".to_string(), version: "0.1.21".to_string() },
        Package { path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/gimli-0.26.2".to_string(), name: "gimli".to_string(), version: "0.26.2".to_string() },
    ];
    
    for expected_pkg in expected_packages {
        assert!(result.packages.contains(&expected_pkg), "Missing package: {:?}", expected_pkg);
    }
    
    assert!(result.user_source_paths.is_empty());
    assert_eq!(result.rustc_hash, Some("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc".to_string()));
    assert_eq!(result.rust_version, Some("1.69.0".to_string()));
    assert!(!result.packages.is_empty());
}

#[test]
fn test_sample_c18b24be70e5227a6b383c94034210b85c809fba8eca7a06b8b2136d510efee5_elf() {
    let filename = "c18b24be70e5227a6b383c94034210b85c809fba8eca7a06b8b2136d510efee5.elf";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // This should have similar pattern to other ELF files
    assert!(result.user_source_paths.is_empty());
    assert_eq!(result.rustc_hash, Some("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc".to_string()));
    assert_eq!(result.rust_version, Some("1.69.0".to_string()));
    assert!(!result.packages.is_empty());
    
    // Should contain common packages found in Rust binaries
    let has_rustc_demangle = result.packages.iter().any(|p| p.name == "rustc-demangle");
    assert!(has_rustc_demangle, "Should contain rustc-demangle package");
}

#[test]
fn test_sample_855f411bd0667b650c4f2fd3c9fbb4fa9209cf40b0d655fa9304dcdd956e0808_exe() {
    let filename = "855f411bd0667b650c4f2fd3c9fbb4fa9209cf40b0d655fa9304dcdd956e0808.exe";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // Test expected packages for Windows executable
    let expected_packages = vec![
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\winsafe-0.0.12".to_string(), name: "winsafe".to_string(), version: "0.0.12".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.5.1".to_string(), name: "rand_core".to_string(), version: "0.5.1".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\cipher-0.4.3".to_string(), name: "cipher".to_string(), version: "0.4.3".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\base64".to_string(), name: "base".to_string(), version: "64".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21".to_string(), name: "rustc-demangle".to_string(), version: "0.1.21".to_string() },
    ];
    
    for expected_pkg in expected_packages {
        assert!(result.packages.contains(&expected_pkg), "Missing package: {:?}", expected_pkg);
    }
    
    assert!(result.user_source_paths.is_empty());
    assert_eq!(result.rustc_hash, Some("4b91a6ea7258a947e59c6522cd5898e7c0a6a88f".to_string()));
    assert_eq!(result.rust_version, Some("1.63.0".to_string()));
    assert!(!result.packages.is_empty());
}

#[test]
fn test_sample_acc31048e00d1a0f4cd5569d5d4db539da8f506cc7a6a171942d015ecc817d43_exe() {
    let filename = "acc31048e00d1a0f4cd5569d5d4db539da8f506cc7a6a171942d015ecc817d43.exe";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    let expected_packages = vec![
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\winsafe-0.0.12".to_string(), name: "winsafe".to_string(), version: "0.0.12".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\base64".to_string(), name: "base".to_string(), version: "64".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.5.1".to_string(), name: "rand_core".to_string(), version: "0.5.1".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21".to_string(), name: "rustc-demangle".to_string(), version: "0.1.21".to_string() },
        Package { path: ".cargo\\registry\\src\\github.com-1ecc6299db9ec823\\cipher-0.4.3".to_string(), name: "cipher".to_string(), version: "0.4.3".to_string() },
    ];
    
    for expected_pkg in expected_packages {
        assert!(result.packages.contains(&expected_pkg), "Missing package: {:?}", expected_pkg);
    }
    
    assert!(result.user_source_paths.is_empty());
    assert_eq!(result.rustc_hash, Some("4b91a6ea7258a947e59c6522cd5898e7c0a6a88f".to_string()));
    assert_eq!(result.rust_version, Some("1.63.0".to_string()));
    assert!(!result.packages.is_empty());
}

#[test]
fn test_sample_6d337b95ca3361f5fc5733591095765beab6917555777f078eafea3064f735bd_exe() {
    let filename = "6d337b95ca3361f5fc5733591095765beab6917555777f078eafea3064f735bd.exe";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // This file contains user source paths (malware with source code traces)
    let expected_user_paths = vec![
        "/src/peparser/pe.rs".to_string(),
        "/src/peloader/winapi.rs".to_string(),
        "/src/lib.rs".to_string(),
        "/src/peloader/mod.rs".to_string(),
        "/src/main.rs".to_string(),
        "/src/peparser/section.rs".to_string(),
        "/src/peparser/header.rs".to_string(),
        "/akita/ww/obfstr/src/bytes.rs".to_string(),
    ];
    
    for expected_path in expected_user_paths {
        assert!(result.user_source_paths.contains(&expected_path), 
               "Missing user source path: {}", expected_path);
    }
    
    assert_eq!(result.rustc_hash, Some("4eb161250e340c8f48f66e2b929ef4a5bed7c181".to_string()));
    assert_eq!(result.rust_version, Some("1.85.1".to_string()));
    assert!(!result.packages.is_empty(), "Should have packages");
    
    // Should contain expected packages for this sample
    let has_native_windows_gui = result.packages.iter().any(|p| p.name == "native-windows-gui");
    assert!(has_native_windows_gui, "Should contain native-windows-gui package");
}

#[test]
fn test_sample_8ac509a776a326180877dc44636081e21f58c89431477ef2a38db10ad6bd15d1_exe() {
    let filename = "8ac509a776a326180877dc44636081e21f58c89431477ef2a38db10ad6bd15d1.exe";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    assert!(result.user_source_paths.is_empty());
    assert!(result.rustc_hash.is_some());
    assert!(result.rust_version.is_some());
    assert!(!result.packages.is_empty());
}

#[test]
fn test_sample_8765ef2a4575e52195223ecb045be569c08337e1ff73a894214b0644f7b480ba_exe() {
    let filename = "8765ef2a4575e52195223ecb045be569c08337e1ff73a894214b0644f7b480ba.exe";
    
    // Extract from password-protected zip
    let (_temp_dir, file_path) = extract_sample(&format!("{}.zip", filename));
    let result = analyze_binary(file_path.to_str().unwrap()).unwrap();
    
    // This file contains user source paths (malware with source code traces) 
    let expected_user_paths = vec![
        "/src/ui.rs".to_string(),
        "/src/main.rs".to_string(),
    ];
    
    for expected_path in expected_user_paths {
        assert!(result.user_source_paths.contains(&expected_path), 
               "Missing user source path: {}", expected_path);
    }
    
    assert_eq!(result.rustc_hash, Some("9fc6b43126469e3858e2fe86cafb4f0fd5068869".to_string()));
    assert_eq!(result.rust_version, Some("1.84.0".to_string()));
    assert!(!result.packages.is_empty());
    
    // Should contain many packages due to GUI dependencies
    assert!(result.packages.len() > 20, "Should have many packages due to complex dependencies");
}

#[test]
fn test_version_mappings_functionality() {
    // Test that version mappings are loaded correctly
    let mappings = load_version_mappings();
    assert!(mappings.is_some(), "Version mappings should be loaded");
    
    let mappings = mappings.unwrap();
    assert!(mappings.contains_key("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc"), "Should contain 1.69.0 hash");
    assert!(mappings.contains_key("4b91a6ea7258a947e59c6522cd5898e7c0a6a88f"), "Should contain 1.63.0 hash");
    
    assert_eq!(mappings.get("84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc"), Some(&"1.69.0".to_string()));
    assert_eq!(mappings.get("4b91a6ea7258a947e59c6522cd5898e7c0a6a88f"), Some(&"1.63.0".to_string()));
}

#[test]
fn test_analyze_binary_error_handling() {
    // Test with non-existent file
    let result = analyze_binary("non_existent_file.bin");
    assert!(result.is_err(), "Should return error for non-existent file");
}

#[test]
fn test_package_uniqueness() {
    // Test that packages with same name/version but different paths are treated as different
    let pkg1 = Package { 
        path: "/cargo/registry/src/index.crates.io-6f17d22bba15001f/test-1.0.0".to_string(), 
        name: "test".to_string(), 
        version: "1.0.0".to_string() 
    };
    let pkg2 = Package { 
        path: "/cargo/registry/src/github.com-1ecc6299db9ec823/test-1.0.0".to_string(), 
        name: "test".to_string(), 
        version: "1.0.0".to_string() 
    };
    
    let mut set = HashSet::new();
    set.insert(pkg1.clone());
    set.insert(pkg2.clone());
    
    assert_eq!(set.len(), 2, "Packages with different paths should be treated as different");
} 