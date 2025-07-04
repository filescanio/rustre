use std::env;
use std::process;
use serde_json::to_string_pretty;
use rustre::analyze_binary;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        process::exit(1);
    }

    let file_path = &args[1];
    
    match analyze_binary(file_path) {
        Ok(result) => {
            if let Ok(json) = to_string_pretty(&result) {
                println!("{}", json);
            } else {
                eprintln!("Error serializing to JSON");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error analyzing binary: {}", e);
            process::exit(1);
        }
    }
}
