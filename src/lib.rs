use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use serde::Serialize;
use serde_json::from_str;

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
                    eprintln!("Warning: Failed to parse rust_versions.json: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to read rust_versions.json: {}", e);
            None
        }
    }
}

pub fn analyze_binary(file_path: &str) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let content = fs::read(file_path)?;
    
    // Load version mappings
    let version_mappings = load_version_mappings();
    
    let re = Regex::new(
        r".cargo(?:/|\\)registry(?:/|\\)src(?:/|\\).*?-[a-f0-9]{8,}(?:/|\\)(.*?)-?([\d\.]{2,})",
    )?;

    // Regex for finding file paths
    let path_re = Regex::new(
        r"(?:[a-zA-Z]:[\\/]|/)(?:[a-zA-Z0-9._\-]+[\\/]){1,512}?(?:[a-zA-Z0-9._\-]+)\.rs",
    )?;

    // Regex for extracting rustc hash
    let rustc_hash_re = Regex::new(r"/rustc/([a-f0-9]{40})")?;

    let mut packages = HashSet::new();
    for mat in re.captures_iter(&content) {
        if let Ok(match_str) = std::str::from_utf8(mat.get(0).unwrap().as_bytes()) {
            let package: Package = Package {
                path: match_str.to_string(),
                name: std::str::from_utf8(mat.get(1).unwrap().as_bytes()).unwrap().to_string(),
                version: std::str::from_utf8(mat.get(2).unwrap().as_bytes()).unwrap().to_string(),
            };
            packages.insert(package);
        }
    }

    // Find file paths using the path regex and separate framework vs user paths
    let mut framework_paths = HashSet::new();
    let mut user_paths = HashSet::new();
    let mut rustc_hash: Option<String> = None;
    for mat in path_re.find_iter(&content) {
        if let Ok(path_str) = std::str::from_utf8(mat.as_bytes()) {
            // Check for rustc hash if we haven't found one yet
            if rustc_hash.is_none() {
                if let Some(hash_match) = rustc_hash_re.captures(path_str.as_bytes()) {
                    if let Ok(hash_str) = std::str::from_utf8(hash_match.get(1).unwrap().as_bytes()) {
                        rustc_hash = Some(hash_str.to_string());
                    }
                }
            }
            
            // Check if this is a framework/system path
            let is_framework_path = path_str.starts_with("/rust") 
                || path_str.contains(".cargo")
                || path_str.contains(".rustup")
                || path_str.contains(".crates.io")
                || path_str.starts_with("/root/")
                || path_str.starts_with("/cargo/")
                || path_str.starts_with("/core/") 
                || path_str.starts_with("/std/") 
                || path_str.starts_with("/alloc/") 
                || path_str.starts_with("/library/") 
                || path_str.starts_with("/proc_macro/") 
                || path_str.starts_with("/test/");

            if is_framework_path {
                framework_paths.insert(path_str.to_string());
            } else {
                user_paths.insert(path_str.to_string());
            }
        }
    }

    // Convert packages HashSet to Vec for JSON serialization
    let packages_vec: Vec<Package> = packages.into_iter().collect();
    
    // Correlate rustc_hash with Rust version
    let rust_version = if let (Some(hash), Some(mappings)) = (&rustc_hash, &version_mappings) {
        mappings.get(hash).cloned()
    } else {
        None
    };
    
    Ok(AnalysisResult {
        packages: packages_vec,
        framework_source_paths: framework_paths,
        user_source_paths: user_paths,
        rustc_hash,
        rust_version,
    })
} 