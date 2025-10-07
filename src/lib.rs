use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use serde::Serialize;
use serde_json::from_str;
use log::{warn, debug};

pub mod update;

#[derive(PartialEq, Eq, Hash, Serialize, Debug, Clone)]
pub struct Package {
    pub path: String,
    pub name: String,
    pub version: String
}

#[derive(Serialize, Debug, Clone)]
pub struct AnalysisResult {
    pub packages: Vec<Package>,
    pub framework_source_paths: HashSet<String>,
    pub user_source_paths: HashSet<String>,
    pub rustc_hash: Option<String>,
    pub rust_version: Option<String>,
}

pub fn load_version_mappings() -> Option<HashMap<String, String>> {
    match fs::read_to_string("rust_versions.json") {
        Ok(content) => {
            match from_str::<HashMap<String, String>>(&content) {
                Ok(mappings) => Some(mappings),
                Err(e) => {
                    warn!("Failed to parse rust_versions.json: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            warn!("Failed to read rust_versions.json: {}", e);
            None
        }
    }
}

fn extract_packages(content: &[u8]) -> Result<HashSet<Package>, Box<dyn std::error::Error>> {
    // Keep the original more permissive regex pattern to handle edge cases like "base64"
    let re = Regex::new(
        r".cargo(?:/|\\)registry(?:/|\\)src(?:/|\\).*?-[a-f0-9]{8,}(?:/|\\)(.*?)-?([\d\.]{2,})"
    )?;

    let mut packages = HashSet::new();
    for mat in re.captures_iter(content) {
        if let (Some(path_match), Some(name_match), Some(version_match)) = 
            (mat.get(0), mat.get(1), mat.get(2)) {
            
            let path_str = std::str::from_utf8(path_match.as_bytes())?;
            let name_str = std::str::from_utf8(name_match.as_bytes())?;
            let version_str = std::str::from_utf8(version_match.as_bytes())?;
            
            let package = Package {
                path: path_str.to_string(),
                name: name_str.to_string(),
                version: version_str.to_string(),
            };
            packages.insert(package);
        }
    }
    debug!("Extracted {} packages", packages.len());
    Ok(packages)
}

fn extract_rustc_info(content: &[u8]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let rustc_hash_re = Regex::new(r"/rustc/([a-f0-9]{40})")?;
    let path_re = Regex::new(
        r"(?:[a-zA-Z]:[\\/]|/)(?:[a-zA-Z0-9._\-]+[\\/]){1,512}?(?:[a-zA-Z0-9._\-]+)\.rs"
    )?;
    
    for mat in path_re.find_iter(content) {
        if let Ok(path_str) = std::str::from_utf8(mat.as_bytes()) {
            if let Some(hash_match) = rustc_hash_re.captures(path_str.as_bytes()) {
                if let Some(hash_capture) = hash_match.get(1) {
                    if let Ok(hash_str) = std::str::from_utf8(hash_capture.as_bytes()) {
                        debug!("Found rustc hash: {}", hash_str);
                        return Ok(Some(hash_str.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn categorize_paths(content: &[u8]) -> Result<(HashSet<String>, HashSet<String>), Box<dyn std::error::Error>> {
    let path_re = Regex::new(
        r"(?:[a-zA-Z]:[\\/]|/)(?:[a-zA-Z0-9._\-]+[\\/]){1,512}?(?:[a-zA-Z0-9._\-]+)\.rs"
    )?;

    let mut framework_paths = HashSet::new();
    let mut user_paths = HashSet::new();
    
    for mat in path_re.find_iter(content) {
        if let Ok(path_str) = std::str::from_utf8(mat.as_bytes()) {
            if is_framework_path(path_str) {
                framework_paths.insert(path_str.to_string());
            } else {
                user_paths.insert(path_str.to_string());
            }
        }
    }
    
    debug!("Categorized {} framework paths and {} user paths", 
           framework_paths.len(), user_paths.len());
    Ok((framework_paths, user_paths))
}

fn is_framework_path(path: &str) -> bool {
    path.starts_with("/rust") 
        || path.contains(".cargo")
        || path.contains(".rustup")
        || path.contains(".crates.io")
        || path.starts_with("/root/")
        || path.starts_with("/cargo/")
        || path.starts_with("/core/") 
        || path.starts_with("/std/") 
        || path.starts_with("/alloc/") 
        || path.starts_with("/library/") 
        || path.starts_with("/proc_macro/") 
        || path.starts_with("/test/")
}

fn resolve_rust_version(rustc_hash: &Option<String>, version_mappings: &Option<HashMap<String, String>>) -> Option<String> {
    if let (Some(hash), Some(mappings)) = (rustc_hash, version_mappings) {
        mappings.get(hash).cloned()
    } else {
        None
    }
}

pub fn analyze_binary(file_path: &str) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    debug!("Starting analysis of binary: {}", file_path);
    
    let content = fs::read(file_path)?;
    debug!("Read {} bytes from binary", content.len());
    
    // Load version mappings
    let version_mappings = load_version_mappings();
    
    // Extract packages
    let packages = extract_packages(&content)?;
    
    // Extract rustc information
    let rustc_hash = extract_rustc_info(&content)?;
    
    // Categorize paths
    let (framework_paths, user_paths) = categorize_paths(&content)?;
    
    // Resolve Rust version
    let rust_version = resolve_rust_version(&rustc_hash, &version_mappings);
    
    // Convert packages HashSet to Vec for JSON serialization
    let packages_vec: Vec<Package> = packages.into_iter().collect();
    
    debug!("Analysis complete: {} packages, rustc_hash: {:?}, rust_version: {:?}", 
           packages_vec.len(), rustc_hash, rust_version);
    
    Ok(AnalysisResult {
        packages: packages_vec,
        framework_source_paths: framework_paths,
        user_source_paths: user_paths,
        rustc_hash,
        rust_version,
    })
} 