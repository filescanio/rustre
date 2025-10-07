use std::process;
use clap::Parser;
use serde_json::to_string_pretty;
use log::{error, info};
use rustre::analyze_binary;
use rustre::update::update_rust_versions;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the binary file to analyze
    #[arg(required_unless_present = "update_versions")]
    file_path: Option<String>,
    
    /// Update the Rust versions database from GitHub
    #[arg(long, help = "Update the Rust versions database from GitHub API")]
    update_versions: bool,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();
    
    let args = Args::parse();
    
    if args.update_versions {
        // Update the Rust versions database
        match update_rust_versions().await {
            Ok(()) => {
                info!("Successfully updated Rust versions database!");
            }
            Err(e) => {
                error!("Error updating Rust versions: {}", e);
                process::exit(1);
            }
        }
    } else if let Some(file_path) = args.file_path {
        // Analyze the binary file
        match analyze_binary(&file_path) {
            Ok(result) => {
                if let Ok(json) = to_string_pretty(&result) {
                    println!("{}", json);
                } else {
                    error!("Error serializing to JSON");
                    process::exit(1);
                }
            }
            Err(e) => {
                error!("Error analyzing binary: {}", e);
                process::exit(1);
            }
        }
    }
    // Note: The final else clause was removed as it's unreachable due to 
    // clap's required_unless_present attribute
}
