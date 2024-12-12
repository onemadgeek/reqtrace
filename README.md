# reqtrace 🔍

A powerful command-line tool for real-time network activity monitoring, connection tracing, and network access control of any process or command.

[![Crates.io](https://img.shields.io/crates/v/reqtrace)](https://crates.io/crates/reqtrace)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Universal Command Monitoring**: Monitor any command or process (`curl`, `wget`, `npm`, `python`, etc.)
- **Real-time Connection Tracking**: Live visualization of all network connections
- **Domain Resolution**: Automatic DNS resolution for IP addresses
- **Network Control Modes**:
  - Monitor Only: Watch and log connections
  - Block & Exit: Terminate on first connection attempt
  - Block & Continue: Prevent network access while allowing execution
- **Detailed Statistics**: Connection counts, unique domains, and IPs
- **Beautiful CLI Interface**: Clear, colorful, and informative output

## 📦 Installation

```bash
cargo install reqtrace
```

## 🎯 Use Cases

### Development & Testing
- Test applications for unexpected network calls
- Debug API integrations
- Monitor dependency downloads
- Verify offline-first functionality

### Security & Compliance
- Audit network behavior of third-party tools
- Enforce network access policies
- Detect unwanted analytics or tracking
- Validate security requirements

### System Administration
- Monitor service network activity
- Debug connection issues
- Profile network usage
- Control application network access

## 📚 Examples

### Monitor Package Manager Activity
```bash
# Track npm installation network activity
reqtrace npm install express

# Monitor pip package downloads
reqtrace pip install requests

# Watch cargo dependencies
reqtrace cargo build
```

### Security Testing
```bash
# Ensure a script doesn't make unauthorized connections
reqtrace -e python script.py

# Block all network access but allow execution
reqtrace -b node app.js

# Monitor Docker container network activity
reqtrace docker run nginx
```

### API Development
```bash
# Debug API client connections
reqtrace curl api.example.com

# Monitor GraphQL queries
reqtrace npm run graphql-app

# Track WebSocket connections
reqtrace node websocket-server.js
```

## 🛠️ Command-Line Options

```bash
reqtrace [OPTIONS] <COMMAND> [ARGS]...

Options:
  -e, --exit-first     Exit on first network connection
  -b, --block         Block all network connections
  -t, --timeout       DNS lookup timeout (default: 1000ms)
  -v, --verbose       Show detailed debug information
  -h, --help          Show help information
  -V, --version       Show version information
```

## 🔧 Technical Details

### Platform Support
- ✅ Linux: Native `/proc` filesystem monitoring
- ✅ macOS: Integration with `lsof`

### Monitoring Capabilities
- TCP connections (IPv4 and IPv6)
- Domain name resolution
- Connection timestamps
- Process hierarchy

### Performance Impact
- Minimal overhead
- Non-blocking DNS resolution
- Efficient connection caching

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License - feel free to use in personal and commercial projects.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=onemadgeek/reqtrace&type=Date)](https://star-history.com/#onemadgeek/reqtrace&Date)
