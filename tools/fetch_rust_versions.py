#!/usr/bin/env python3
"""
Script to fetch all Rust tags and their commit hashes from the rust-lang/rust repository.
Saves the data in a format that can be read by the Rust application for version correlation.
"""

import json
import requests
import sys
from typing import Dict, List, Optional


def fetch_github_tags(owner: str, repo: str, per_page: int = 100) -> List[Dict]:
    """
    Fetch all tags from a GitHub repository using the GitHub API.
    
    Args:
        owner: Repository owner (e.g., 'rust-lang')
        repo: Repository name (e.g., 'rust')
        per_page: Number of results per page (max 100)
    
    Returns:
        List of tag dictionaries containing name and commit info
    """
    tags = []
    page = 1
    
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/tags"
        params = {
            'per_page': per_page,
            'page': page
        }
        
        print(f"Fetching page {page}...", file=sys.stderr)
        
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            page_tags = response.json()
            if not page_tags:
                break
                
            tags.extend(page_tags)
            page += 1
            
        except requests.RequestException as e:
            print(f"Error fetching tags: {e}", file=sys.stderr)
            sys.exit(1)
    
    return tags


def process_tags(tags: List[Dict]) -> Dict[str, str]:
    """
    Process tags and create a mapping of commit hash to version tag.
    
    Args:
        tags: List of tag dictionaries from GitHub API
    
    Returns:
        Dictionary mapping commit hash to version tag
    """
    hash_to_version = {}
    
    for tag in tags:
        tag_name = tag['name']
        commit_sha = tag['commit']['sha']
        
        # Store the mapping: commit hash -> version tag
        hash_to_version[commit_sha] = tag_name
        
        print(f"  {tag_name} -> {commit_sha}", file=sys.stderr)
    
    return hash_to_version


def save_version_data(hash_to_version: Dict[str, str], output_file: str):
    """
    Save the version mapping to a JSON file.
    
    Args:
        hash_to_version: Dictionary mapping commit hash to version
        output_file: Path to output JSON file
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(hash_to_version, f, indent=2, sort_keys=True)
        
        print(f"Successfully saved {len(hash_to_version)} version mappings to {output_file}", file=sys.stderr)
        
    except IOError as e:
        print(f"Error writing to file {output_file}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main function to orchestrate the tag fetching and processing."""
    owner = "rust-lang"
    repo = "rust"
    output_file = "rust_versions.json"
    
    print(f"Fetching all tags from {owner}/{repo}...", file=sys.stderr)
    
    # Fetch all tags from the repository
    tags = fetch_github_tags(owner, repo)
    
    print(f"Found {len(tags)} tags", file=sys.stderr)
    print("Processing tags...", file=sys.stderr)
    
    # Process tags into hash -> version mapping
    hash_to_version = process_tags(tags)
    
    # Save to JSON file
    save_version_data(hash_to_version, output_file)
    
    print("Done!", file=sys.stderr)


if __name__ == "__main__":
    main() 