use std::process::Command;
use std::error::Error;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[cfg(target_os = "linux")]
use std::fs;
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use colored::*;
use chrono;
use std::env;
use std::collections::HashMap;

#[derive(PartialEq)]
enum ExecutionMode {
    Normal,
    ExitFirst,
    BlockAndContinue,
}

struct DnsCache {
    cache: HashMap<String, (Option<String>, Instant)>,
    ttl: Duration,
}

impl DnsCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn get(&mut self, ip: &str) -> Option<Option<String>> {
        if let Some((hostname, timestamp)) = self.cache.get(ip) {
            if timestamp.elapsed() < self.ttl {
                return Some(hostname.clone());
            }
        }
        None
    }

    fn set(&mut self, ip: String, hostname: Option<String>) {
        self.cache.insert(ip, (hostname, Instant::now()));
    }
}

#[cfg(target_os = "linux")]
fn get_process_connections(pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    let tcp = fs::read_to_string(format!("/proc/{}/net/tcp", pid))?;
    let tcp6 = fs::read_to_string(format!("/proc/{}/net/tcp6", pid))?;
    
    let mut connections = HashSet::new();
    
    for line in tcp.lines().chain(tcp6.lines()).skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let remote = parts[2];
            if remote != "00000000:0000" {  // Skip 0.0.0.0:0
                // Parse the remote address
                let (addr, port) = remote.split_once(':').unwrap_or(("", ""));
                if let (Ok(addr_num), Ok(port_num)) = (u32::from_str_radix(addr, 16), u16::from_str_radix(port, 16)) {
                    let ip = format!(
                        "{}.{}.{}.{}", 
                        (addr_num >> 24) & 0xFF,
                        (addr_num >> 16) & 0xFF,
                        (addr_num >> 8) & 0xFF,
                        addr_num & 0xFF
                    );
                    connections.insert(format!("{}:{}", ip, port_num));
                }
            }
        }
    }
    
    Ok(connections)
}

#[cfg(target_os = "macos")]
fn get_process_connections(pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "-p", &pid.to_string()])
        .output()?;

    let mut connections = HashSet::new();
    
    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("ESTABLISHED") || line.contains("SYN_SENT") {
                if let Some(addr) = line.split_whitespace().find(|&s| s.contains("->")) {
                    if let Some(remote) = addr.split("->").nth(1) {
                        connections.insert(remote.trim().to_string());
                    }
                }
            }
        }
    }
    
    Ok(connections)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_process_connections(_pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    Ok(HashSet::new())
}

fn resolve_domain_name(addr: &str, dns_cache: &Arc<Mutex<DnsCache>>) -> (String, Option<String>) {
    if let Ok(sock_addr) = addr.to_socket_addrs() {
        if let Some(addr) = sock_addr.into_iter().next() {
            let ip = addr.ip().to_string();
            
            // Check cache first
            if let Ok(mut cache) = dns_cache.lock() {
                if let Some(cached_result) = cache.get(&ip) {
                    return (format!("{}:{}", ip, addr.port()), cached_result);
                }
            }

            // Perform DNS lookup with timeout
            let dns_result = std::thread::spawn(move || {
                dns_lookup::lookup_addr(&addr.ip()).ok()
            });

            let hostname = match dns_result.join().unwrap() {
                Some(host) => Some(host),
                None => None,
            };

            // Cache the result
            if let Ok(mut cache) = dns_cache.lock() {
                cache.set(ip.clone(), hostname.clone());
            }

            return (format!("{}:{}", ip, addr.port()), hostname);
        }
    }
    (addr.to_string(), None)
}

#[derive(Default)]
struct ConnectionStats {
    total_connections: usize,
    domains: HashMap<String, usize>,
    ips: HashMap<String, usize>,
}

impl ConnectionStats {
    fn new() -> Self {
        Self::default()
    }

    fn add_connection(&mut self, addr: &str, domain: &Option<String>) {
        self.total_connections += 1;
        
        // Track IP addresses
        let ip = addr.split(':').next().unwrap_or(addr).to_string();
        *self.ips.entry(ip).or_insert(0) += 1;

        // Track domains if available
        if let Some(domain) = domain {
            *self.domains.entry(domain.to_string()).or_insert(0) += 1;
        }
    }

    fn print_summary(&self) {
        eprintln!("\n{}", "Network Activity Summary:".bright_blue().bold());
        eprintln!("Total connections: {}", self.total_connections.to_string().bright_yellow());

        if !self.domains.is_empty() {
            eprintln!("\n{}:", "Domains contacted".bright_blue());
            let mut domains: Vec<_> = self.domains.iter().collect();
            domains.sort_by(|a, b| b.1.cmp(a.1));
            for (domain, count) in domains {
                eprintln!("  {} → {} {}", 
                    count.to_string().bright_yellow(),
                    "requests to".dimmed(),
                    domain.bright_cyan()
                );
            }
        }

        if !self.ips.is_empty() {
            eprintln!("\n{}:", "IP addresses contacted".bright_blue());
            let mut ips: Vec<_> = self.ips.iter().collect();
            ips.sort_by(|a, b| b.1.cmp(a.1));
            for (ip, count) in ips {
                eprintln!("  {} → {}", 
                    count.to_string().bright_yellow(),
                    ip.bright_white()
                );
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: reqtrace [-e|-bc] <command> [args...]");
        eprintln!("Options:");
        eprintln!("  -e     Exit on first network connection attempt");
        eprintln!("  -bc    Block all network connections but continue execution");
        std::process::exit(1);
    }

    // Parse arguments to check for flags
    let mode = if args[1] == "-e" {
        ExecutionMode::ExitFirst
    } else if args[1] == "-bc" {
        ExecutionMode::BlockAndContinue
    } else {
        ExecutionMode::Normal
    };

    let (command, command_args) = if mode != ExecutionMode::Normal {
        if args.len() < 3 {
            eprintln!("Usage: reqtrace [-e|-bc] <command> [args...]");
            std::process::exit(1);
        }
        (&args[2], &args[3..])
    } else {
        (&args[1], &args[2..])
    };

    eprintln!("{} {} {}", 
        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).dimmed(),
        "STARTING".bright_blue(),
        command.bright_yellow()
    );

    // Start the child process
    let mut child = Command::new(command)
        .args(command_args)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    let pid = child.id();
    let mut stats = ConnectionStats::new();
    let mut known_connections = HashSet::new();
    let mut blocked_count = 0;

    // Give the process a moment to start
    thread::sleep(Duration::from_millis(100));

    // Add this near the start of main, after parsing arguments
    let dns_cache = Arc::new(Mutex::new(DnsCache::new(300))); // 5-minute TTL

    // Modify the monitoring loop
    while let None = child.try_wait()? {
        if let Ok(current_connections) = get_process_connections(pid) {
            for conn in current_connections.difference(&known_connections) {
                let (addr, maybe_domain) = resolve_domain_name(conn, &dns_cache);
                let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
                
                // Track statistics
                stats.add_connection(&addr, &maybe_domain);
                
                match mode {
                    ExecutionMode::Normal => {
                        eprint!("{} ", format!("[{}]", timestamp).dimmed());
                        eprint!("{} ", "CONNECTION".bright_green());
                    },
                    ExecutionMode::ExitFirst => {
                        eprint!("{} ", format!("[{}]", timestamp).dimmed());
                        eprint!("{} ", "BLOCKED".bright_red());
                        child.kill()?;
                        if let Some(domain) = &maybe_domain {
                            eprintln!("{} {} {}", 
                                addr.bright_yellow(),
                                "→".bright_blue(),
                                domain.bright_cyan()
                            );
                        } else {
                            eprintln!("{}", addr.bright_yellow());
                        }
                        eprintln!("{} {} Terminating process due to network activity", 
                            format!("[{}]", timestamp).dimmed(),
                            "STOPPED".bright_red(),
                        );
                        stats.print_summary();
                        return Ok(());
                    },
                    ExecutionMode::BlockAndContinue => {
                        blocked_count += 1;
                        eprint!("{} ", format!("[{}]", timestamp).dimmed());
                        eprint!("{} ", "BLOCKED".bright_red());
                    }
                }
                
                if let Some(domain) = maybe_domain {
                    eprintln!("{} {} {}", 
                        addr.bright_yellow(),
                        "→".bright_blue(),
                        domain.bright_cyan()
                    );
                } else {
                    eprintln!("{}", addr.bright_yellow());
                }
            }
            known_connections = current_connections;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Get the exit status
    let status = child.wait()?;

    eprintln!("{} {} {}", 
        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).dimmed(),
        "FINISHED".bright_blue(),
        command.bright_yellow()
    );

    // Enhance the ConnectionStats to show blocked connections
    if mode == ExecutionMode::BlockAndContinue {
        eprintln!("\n{} {}", 
            "Blocked Connections:".bright_red(),
            blocked_count.to_string().bright_yellow()
        );
    }

    // Print the summary before exiting
    stats.print_summary();

    // Propagate the exit code
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}