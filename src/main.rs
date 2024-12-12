use std::process::Command;
use std::io::{self, BufRead, BufReader};
use regex::Regex;
use url::Url;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: reqtrace <command> [args...]");
        std::process::exit(1);
    }

    let command = &args[1];
    let command_args = &args[2..];

    let mut child = Command::new(command)
        .args(command_args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    let stdout = child.stdout.take()
        .ok_or("Failed to capture stdout")?;
    let reader = BufReader::new(stdout);

    process_output(reader)?;
    
    child.wait()
        .map_err(|e| format!("Failed to wait on child process: {}", e))?;
    
    Ok(())
}

fn process_output(reader: impl BufRead) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if let Some(urls) = extract_urls(&line) {
            for url in urls {
                println!("API call detected: {}", url);
            }
        }
    }
    Ok(())
}

fn extract_urls(text: &str) -> Option<Vec<String>> {
    // Compile regex only once
    lazy_static! {
        static ref URL_REGEX: Regex = Regex::new(
            r"https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        ).unwrap();
    }

    let matches: Vec<String> = URL_REGEX.find_iter(text)
        .filter_map(|m| {
            let url_str = m.as_str();
            Url::parse(url_str)
                .map(|_| url_str.to_string())
                .ok()
        })
        .collect();

    (!matches.is_empty()).then_some(matches)
}