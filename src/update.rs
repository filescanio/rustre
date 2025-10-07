use std::collections::HashMap;
use std::fs;
use log::{info, debug};

// GitHub API response structures
#[derive(serde::Deserialize, Debug)]
struct GitHubTag {
    name: String,
    commit: GitHubCommit,
}

#[derive(serde::Deserialize, Debug)]
struct GitHubCommit {
    sha: String,
}

async fn fetch_github_tags(owner: &str, repo: &str) -> Result<Vec<GitHubTag>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut tags = Vec::new();
    let mut page = 1;
    
    loop {
        let url = format!("https://api.github.com/repos/{}/{}/tags", owner, repo);
        
        info!("Fetching page {}...", page);
        
        let response = client
            .get(&url)
            .query(&[("per_page", "100"), ("page", &page.to_string())])
            .header("User-Agent", "rustre")
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("GitHub API error: {}", response.status()).into());
        }
        
        let page_tags: Vec<GitHubTag> = response.json().await?;
        
        if page_tags.is_empty() {
            break;
        }
        
        tags.extend(page_tags);
        page += 1;
    }
    
    Ok(tags)
}

fn process_tags(tags: Vec<GitHubTag>) -> HashMap<String, String> {
    let mut hash_to_version = HashMap::new();
    
    for tag in tags {
        // Store the mapping: commit hash -> version tag
        hash_to_version.insert(tag.commit.sha.clone(), tag.name.clone());
        debug!("  {} -> {}", tag.name, tag.commit.sha);
    }
    
    hash_to_version
}

pub async fn update_rust_versions() -> Result<(), Box<dyn std::error::Error>> {
    let owner = "rust-lang";
    let repo = "rust";
    let output_file = "rust_versions.json";
    
    info!("Fetching all tags from {}/{}...", owner, repo);
    
    // Fetch all tags from the repository
    let tags = fetch_github_tags(owner, repo).await?;
    
    info!("Found {} tags", tags.len());
    info!("Processing tags...");
    
    // Process tags into hash -> version mapping
    let hash_to_version = process_tags(tags);
    
    // Save to JSON file
    let json_content = serde_json::to_string_pretty(&hash_to_version)?;
    fs::write(output_file, json_content)?;
    
    info!("Successfully saved {} version mappings to {}", hash_to_version.len(), output_file);
    info!("Done!");
    
    Ok(())
} 