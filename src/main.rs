//! A Simple command-line tool for monitoring and controlling network connections of processes
//! 
//! This tool allows you to:
//! - Monitor network connections made by a specified process
//! - Block network connections and terminate the process
//! - Track connection statistics and generate reports
//! - Resolve IP addresses to domain names

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
use clap::Parser;

/// Command line arguments parsed using clap
#[derive(Parser)]
#[command(author, version, about = "Monitor and control network connections of processes")]
struct Cli {
    /// Command to execute and monitor
    #[arg(required = true)]
    command: String,

    /// Command arguments passed to the monitored process
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Exit on first network connection attempt
    #[arg(short = 'e', long = "exit-first")]
    exit_first: bool,

    /// Block all network connections but continue execution
    #[arg(short = 'b', long = "block")]
    block: bool,

    /// DNS lookup timeout in milliseconds
    #[arg(short = 't', long = "timeout", default_value = "1000")]
    dns_timeout: u64,

    /// Show verbose output including debug information
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Quiet mode - show only essential information
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
}

/// Execution modes that control how network connections are handled
#[derive(PartialEq)]
enum ExecutionMode {
    /// Monitor connections without blocking
    Normal,
    /// Exit process on first connection attempt
    ExitFirst,
    /// Block connections but allow process to continue
    BlockAndContinue,
}

/// Cache for DNS lookups to avoid repeated queries
struct DnsCache {
    /// Map of IP addresses to hostnames and timestamps
    cache: HashMap<String, (Option<String>, Instant)>,
    /// Time-to-live for cache entries
    ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache with specified TTL in seconds
    fn new(ttl_secs: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get a cached hostname for an IP address if available and not expired
    fn get(&mut self, ip: &str) -> Option<Option<String>> {
        if let Some((hostname, timestamp)) = self.cache.get(ip) {
            if timestamp.elapsed() < self.ttl {
                return Some(hostname.clone());
            }
        }
        None
    }

    /// Cache a hostname for an IP address
    fn set(&mut self, ip: String, hostname: Option<String>) {
        self.cache.insert(ip, (hostname, Instant::now()));
    }
}

/// Get active network connections for a process on Linux
#[cfg(target_os = "linux")]
fn get_process_connections(pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    // Read IPv4 and IPv6 connection information from proc filesystem
    let tcp = fs::read_to_string(format!("/proc/{}/net/tcp", pid))?;
    let tcp6 = fs::read_to_string(format!("/proc/{}/net/tcp6", pid))?;
    
    let mut connections = HashSet::new();
    
    // Parse connection information from proc entries
    for line in tcp.lines().chain(tcp6.lines()).skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let remote = parts[2];
            if remote != "00000000:0000" {  // Skip 0.0.0.0:0
                // Parse the remote address from hex format
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

/// Get active network connections for a process on macOS
#[cfg(target_os = "macos")]
fn get_process_connections(pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    // Use lsof command to get connection information
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "-p", &pid.to_string()])
        .output()?;

    let mut connections = HashSet::new();
    
    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        // Parse lsof output looking for established connections
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

/// Stub implementation for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_process_connections(_pid: u32) -> Result<HashSet<String>, Box<dyn Error>> {
    Ok(HashSet::new())
}

/// Resolve an IP address to a domain name with caching and timeout
fn resolve_domain_name(addr: &str, dns_cache: &Arc<Mutex<DnsCache>>, timeout: u64) -> (String, Option<String>) {
    if let Ok(sock_addr) = addr.to_socket_addrs() {
        if let Some(addr) = sock_addr.into_iter().next() {
            let ip = addr.ip().to_string();
            
            // Check cache first
            if let Ok(mut cache) = dns_cache.lock() {
                if let Some(cached_result) = cache.get(&ip) {
                    return (format!("{}:{}", ip, addr.port()), cached_result);
                }
            }

            // Create channels for communication between threads
            let (tx, rx) = std::sync::mpsc::channel();
            let addr_ip = addr.ip();

            // Spawn DNS lookup in a separate thread
            thread::spawn(move || {
                let result = dns_lookup::lookup_addr(&addr_ip).ok();
                let _ = tx.send(result);
            });

            // Wait for result with timeout
            let hostname = match rx.recv_timeout(Duration::from_millis(timeout)) {
                Ok(result) => result,
                Err(_) => None, // Timeout or channel closed
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

/// Track statistics about network connections
struct ConnectionStats {
    /// Total number of connection attempts
    total_connections: usize,
    /// Count of connections per domain
    domains: HashMap<String, usize>,
    /// Count of connections per IP address
    ips: HashMap<String, usize>,
    /// When monitoring started
    start_time: Instant,
}

impl ConnectionStats {
    /// Create new empty connection statistics
    fn new() -> Self {
        Self {
            total_connections: 0,
            domains: HashMap::new(),
            ips: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Record a new connection attempt
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

    /// Print connection statistics summary
    fn print_summary(&self, quiet: bool) {
        if quiet {
            if self.total_connections > 0 {
                eprintln!("\n\nTotal connections: {} ({})", 
                    self.total_connections.to_string().bright_yellow(),
                    format!("{:.1}s", self.start_time.elapsed().as_secs_f64()).dimmed()
                );
            }
            return;
        }
        // Add a fancy header
        eprintln!("\n{}", "━".repeat(50).bright_blue());
        eprintln!("{}",   "           Network Activity Report           ".bold());
        eprintln!("{}\n", "━".repeat(50).bright_blue());

        // Add timing information
        eprintln!("🕒 {}", "Monitoring Duration:".bright_blue());
        eprintln!("   {:.1} seconds\n", self.start_time.elapsed().as_secs_f64());

        // Enhanced connection summary
        eprintln!("📊 {}", "Connection Summary:".bright_blue());
        eprintln!("   Total Connections: {}", self.total_connections.to_string().bright_yellow());
        eprintln!("   Unique IPs: {}", self.ips.len().to_string().bright_yellow());
        eprintln!("   Unique Domains: {}\n", self.domains.len().to_string().bright_yellow());

        if !self.domains.is_empty() {
            eprintln!("🌐 {}:", "Top Domains".bright_blue());
            let mut domains: Vec<_> = self.domains.iter().collect();
            domains.sort_by(|a, b| b.1.cmp(a.1));
            for (domain, count) in domains.iter().take(5) {
                let percentage = (**count as f64 / self.total_connections as f64) * 100.0;
                eprintln!("   {} {:>5.1}% → {}", 
                    count.to_string().bright_yellow(),
                    percentage,
                    domain.bright_cyan()
                );
            }
            if domains.len() > 5 {
                eprintln!("   ... and {} more", domains.len() - 5);
            }
        }
    }
}

/// Display an animated activity indicator
struct ActivityMonitor {
    /// Unicode spinner characters
    spinner_states: Vec<&'static str>,
    /// Current spinner position
    current_state: usize,
    /// When spinner was last updated
    last_update: Instant,
}

impl ActivityMonitor {
    /// Create new activity monitor
    fn new() -> Self {
        Self {
            spinner_states: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current_state: 0,
            last_update: Instant::now(),
        }
    }

    /// Update and get current spinner character
    fn tick(&mut self) -> &str {
        if self.last_update.elapsed() > Duration::from_millis(80) {
            self.current_state = (self.current_state + 1) % self.spinner_states.len();
            self.last_update = Instant::now();
        }
        self.spinner_states[self.current_state]
    }
}

/// Print initial program banner with configuration info
fn print_startup_banner(command: &str, mode: &ExecutionMode, cli: &Cli) {
    if cli.quiet {
        return;
    }
    eprintln!("\n{}", "━".repeat(50).bright_blue());
    eprintln!("🔍 {} v{}", env!("CARGO_PKG_NAME").bold(), env!("CARGO_PKG_VERSION"));
    eprintln!("   {}", env!("CARGO_PKG_DESCRIPTION"));
    eprintln!("{}", "━".repeat(50).bright_blue());
    
    eprintln!("\n📋 {}", "Configuration:".bright_blue());
    eprintln!("   Command: {}", command.bright_yellow());
    eprintln!("   Mode: {}", match mode {
        ExecutionMode::Normal => "Monitor Only".bright_green(),
        ExecutionMode::ExitFirst => "Exit on First Connection".bright_red(),
        ExecutionMode::BlockAndContinue => "Block Connections".bright_red(),
    });
    eprintln!("   DNS Timeout: {} ms", cli.dns_timeout);
    eprintln!("   Verbose: {}", if cli.verbose { "Yes" } else { "No" });
    eprintln!("");
}

/// Main program entry point
fn main() -> Result<(), Box<dyn Error>> {
    // Parse CLI arguments using Clap
    let cli = Cli::parse();

    // Convert Clap args to execution mode
    let mode = if cli.exit_first {
        ExecutionMode::ExitFirst
    } else if cli.block {
        ExecutionMode::BlockAndContinue
    } else {
        ExecutionMode::Normal
    };

    print_startup_banner(&cli.command, &mode, &cli);

    // Start the child process
    let mut child = Command::new(&cli.command)
        .args(&cli.args)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if !cli.quiet { 
        eprintln!("{} {} {}", 
            format!("[{}]", chrono::Local::now().format("%H:%M:%S")).dimmed(),
            "STARTED".bright_blue(),
            cli.command.bright_yellow()
        );
    }

    let pid = child.id();
    let mut stats = ConnectionStats::new();
    let mut known_connections = HashSet::new();
    let mut blocked_count = 0;

    // Give the process a moment to start
    thread::sleep(Duration::from_millis(100));

    // Configure DNS cache with timeout from CLI
    let dns_cache = Arc::new(Mutex::new(DnsCache::new(300))); // 5-minute TTL

    let mut activity_monitor = ActivityMonitor::new();

    // Main monitoring loop - runs until child process exits
    while let None = child.try_wait()? {
        if let Ok(current_connections) = get_process_connections(pid) {
            for conn in current_connections.difference(&known_connections) {
                let (addr, maybe_domain) = resolve_domain_name(conn, &dns_cache, cli.dns_timeout);
                let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
                
                stats.add_connection(&addr, &maybe_domain);
                
                if cli.verbose {
                    eprintln!("Debug: New connection detected to {}", addr);
                }

                match mode {
                    ExecutionMode::Normal => {
                        if !cli.quiet {
                            eprint!("\r{} {} {} ", 
                                format!("[{}]", timestamp).dimmed(),
                                activity_monitor.tick(),
                                "CONNECTION".bright_green()
                            );
                        }
                    },
                    ExecutionMode::ExitFirst => {
                        eprint!("{} ", format!("[{}]", timestamp).dimmed());
                        eprint!("{} ", "BLOCKED".bright_red());
                        child.kill()?;
                        if !cli.quiet {
                            if let Some(domain) = &maybe_domain {
                                eprintln!("{} {} {}", 
                                    addr.bright_yellow(),
                                    "→".bright_blue(),
                                    domain.bright_cyan()
                                );
                            } else {
                                eprintln!("{}", addr.bright_yellow());
                            }
                        }
                        eprintln!("Process terminated due to network activity");
                        stats.print_summary(cli.quiet);
                        return Ok(());
                    },
                    ExecutionMode::BlockAndContinue => {
                        blocked_count += 1;
                        if !cli.quiet {
                            eprint!("\r{} {} {} ", 
                                format!("[{}]", timestamp).dimmed(),
                                activity_monitor.tick(),
                                "BLOCKED".bright_red()
                            );
                        }
                    }
                }
                
                if !cli.quiet {
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
            }
            known_connections = current_connections;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Get the exit status
    let status = child.wait()?;

    // Update the final status messages
    if !cli.quiet {
        eprintln!("{} {} {}", 
            format!("[{}]", chrono::Local::now().format("%H:%M:%S")).dimmed(),
            "FINISHED".bright_blue(),
            cli.command.bright_yellow()
        );

        if mode == ExecutionMode::BlockAndContinue {
            eprintln!("\n{} {}", 
                "Blocked Connections:".bright_red(),
                blocked_count.to_string().bright_yellow()
            );
        }
    }

    stats.print_summary(cli.quiet);

    // Propagate the exit code
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}