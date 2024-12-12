# reqtrace

A command-line tool to monitor and control network connections made by any program. Perfect for debugging, security auditing, and understanding network behavior of applications.

## Features

- 🔍 Monitor all network connections made by a program
- 🚫 Block network connections with different control modes
- 🌐 DNS resolution for IP addresses
- 📊 Detailed connection statistics
- 🎨 Color-coded output for better visibility
- 🖥️ Supports Linux and macOS

## Installation

You can install reqtrace using Cargo:

```bash
cargo install reqtrace
```

## Usage

```bash
reqtrace [-e|-bc] <command> [args...]
```

### Options

- No flag: Monitor and log all connections
- `-e`: Exit on first network connection attempt
- `-bc`: Block all network connections but continue execution

## Examples

### Monitor Network Activity

Watch all connections made by npm install:
```bash
$ reqtrace npm install express
[10:15:23] STARTING npm
[10:15:24] CONNECTION 104.16.23.35:443 → registry.npmjs.org
[10:15:24] CONNECTION 104.16.24.35:443 → registry.npmjs.org

Network Activity Summary:
Total connections: 2

Domains contacted:
  2 → requests to registry.npmjs.org
```

### Block and Exit on First Connection

Stop a program when it tries to make a network connection:
```bash
$ reqtrace -e python script.py
[14:20:15] STARTING python
[14:20:16] BLOCKED 93.184.216.34:443 → analytics.service.com
[14:20:16] STOPPED Terminating process due to network activity

Network Activity Summary:
Total connections: 1

Domains contacted:
  1 → requests to analytics.service.com
```

### Block All Connections but Continue

Let the program run but prevent network access:
```bash
$ reqtrace -bc node app.js
[15:45:30] STARTING node
[15:45:31] BLOCKED 151.101.1.194:443 → api.github.com
[15:45:32] BLOCKED 52.84.125.129:443 → api.stripe.com

Blocked Connections: 2

Network Activity Summary:
Total connections: 2

Domains contacted:
  1 → requests to api.github.com
  1 → requests to api.stripe.com
```

## How It Works

reqtrace monitors network connections using platform-specific methods:
- On Linux: Monitors `/proc/<pid>/net/tcp` and `/proc/<pid>/net/tcp6`
- On macOS: Uses `lsof` to track network connections
- Resolves IP addresses to domain names when possible
- Provides real-time connection monitoring and statistics

## Limitations

- Windows support is not yet available
- Only TCP connections are monitored
- Some privileged processes might require running with sudo

## Contributing

Contributions are welcome! Please feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## License

This project is licensed under the MIT License - see the LICENSE file for details.