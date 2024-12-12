# reqtrace

A command-line tool that traces HTTP/HTTPS API calls made by other commands by monitoring their stdout.

## Features

- Monitors command output for HTTP/HTTPS URLs
- Supports any command that outputs URLs to stdout
- Validates detected URLs
- Handles multiple URLs per line

## Installation

You can install reqtrace using Cargo:

```bash
reqtrace <command> [args...]
```

### Examples

Monitor curl requests:
```bash
reqtrace curl https://api.example.com/data
```

Monitor a Node.js application:
```bash
reqtrace node server.js
```

## How it Works

reqtrace works by:
1. Executing the specified command
2. Capturing its stdout
3. Analyzing each line for valid HTTP/HTTPS URLs
4. Printing detected API calls

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.