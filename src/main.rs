use std::process::Command;
use std::io::{BufRead, BufReader};
use regex::Regex;
use url::Url;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: reqtrace <command> [args...]");
        return;
    }

    let command = &args[1];
    let command_args = &args[2..];

    let mut child = Command::new(command)
        .args(command_args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to execute command");

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    for line in reader.lines() {
        let line = line.unwrap();
        if let Some(urls) = extract_urls(&line) {
            for url in urls {
                println!("API call detected: {}", url);
            }
        }
    }

    child.wait().expect("Failed to wait on child");
}

fn extract_urls(text: &str) -> Option<Vec<String>> {
    let url_regex = Regex::new(r"https?://[^\s<>\"']+").unwrap();
    let matches: Vec<String> = url_regex.find_iter(text)
        .filter_map(|m| {
            let url_str = m.as_str();
            match Url::parse(url_str) {
                Ok(_) => Some(url_str.to_string()),
                Err(_) => None
            }
        })
        .collect();

    if matches.is_empty() {
        None
    } else {
        Some(matches)
    }
} 