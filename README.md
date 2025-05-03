# SNI Capture
A tool to capture Server Name Indication (SNI) information from TLS handshakes and optionally log them along with JA3 fingerprints. Mainly used for research and pentesting.

## Features

- Capture SNI information from TLS handshakes
- Filter by direction (inbound, outbound, or both)
- Show JA3 fingerprints for TLS connections
- JSON output support
- Once mode to show each SNI only once
- Automatic external IP detection for accurate direction determination
- File logging with rotation support
- REST API server for real-time SNI data access

## Installation

```bash
apt install -y libpcap-dev build-essential
export CGO_ENABLED=1
go install github.com/7c/sni-capture-go@latest
```

## Build from source
```bash
apt install -y libpcap-dev build-essential
go build -o sni-capture-go main.go
## or
make
```

## Usage
Default it will listen to default interface and port 443 in console output mode.
```bash
sni-capture [options]
```

### Options

- `-d, --direction`: Direction of TLS handshake to capture (in|out|both) (default: "both")
- `-p, --port`: Ports to listen for TLS handshake (default: "443")
- `-o, --output`: Log output file
- `-i, --iface`: Network interface to attach to
- `--listiface`: List all available interfaces
- `-v, --verbose`: Enable verbose output
- `--ja3`: Show JA3 fingerprint for each TLS handshake
- `--json`: Output in JSON format
- `-1, --once`: Show each SNI only once per session
- `-l, --lockport`: Port to use for mutex mechanism (default: "23554")
- `--apiserver`: Enable API server
- `--apiserver-host`: API server host (default: "127.0.0.1")
- `--apiserver-port`: API server port (default: 7810)
- `--apiserver-log`: API server log file

### Examples

Capture all SNI information:
```bash
sni-capture
```

Capture only outbound SNI information:
```bash
sni-capture -d out
```

Capture SNI information with JA3 fingerprints:
```bash
sni-capture --ja3
```

Capture SNI information in JSON format:
```bash
sni-capture --json
```

Capture SNI information and save to file:
```bash
sni-capture -o /tmp/sni.log
```

Show each SNI only once:
```bash
sni-capture -1
```

Start with API server:
```bash
sni-capture --apiserver
```

Start with API server and custom settings:
```bash
sni-capture --apiserver --apiserver-host 0.0.0.0 --apiserver-port 8080 --apiserver-log /tmp/api.log
```

## API Endpoints

When the API server is enabled, the following endpoints are available:

### GET /api/ping
Check if the API server is running.

Response:
```json
{
  "retcode": 200
}
```

### GET /api/snis/unique
Get all unique SNIs seen so far.

Response:
```json
{
  "retcode": 200,
  "data": {
    "snis": [
      {
        "timestamp": "2024-03-21T10:30:45Z",
        "source_ip": "192.168.1.100",
        "dest_ip": "1.2.3.4",
        "dest_port": 443,
        "sni": "example.com",
        "verified": true,
        "seen_count": 1,
        "dir": "out",
        "ja3": "abc123..."
      }
    ],
    "count": 1
  }
}
```

### GET /api/snis/{minutes}
Get SNIs from the last N minutes (1-10).

Response:
```json
{
  "retcode": 200,
  "data": {
    "snis": [
      {
        "timestamp": "2024-03-21T10:30:45Z",
        "source_ip": "192.168.1.100",
        "dest_ip": "1.2.3.4",
        "dest_port": 443,
        "sni": "example.com",
        "verified": true,
        "seen_count": 1,
        "dir": "out",
        "ja3": "abc123..."
      }
    ],
    "count": 1
  }
}
```

## API Logging

When `--apiserver-log` is specified, all API requests and responses are logged in JSON format:

```json
{
  "timestamp": "2024-03-21T10:30:45Z",
  "method": "GET",
  "path": "/api/snis/unique",
  "client_ip": "192.168.1.100",
  "client_port": "12345",
  "user_agent": "curl/7.68.0",
  "headers": {
    "Accept": "*/*",
    "User-Agent": "curl/7.68.0"
  },
  "status_code": 200,
  "response_body": {
    "retcode": 200,
    "data": {
      "snis": [...],
      "count": 1
    }
  }
}
```

## Output Format

### Text Mode

```
SNI: 192.168.1.100 -> 1.2.3.4:443 example.com (SSL VERIFIED) seen:1 dir:out ja3:abc123...
```

### JSON Mode

```json
{
  "timestamp": "2024-03-21T10:30:45Z",
  "source_ip": "192.168.1.100",
  "dest_ip": "1.2.3.4",
  "dest_port": 443,
  "sni": "example.com",
  "verified": true,
  "seen_count": 1,
  "dir": "out",
  "ja3": "a7f2d0376cd3fde3117bf6a8369b2ab8"
}
```

## Direction Filtering

The tool automatically detects your external IP address and uses it to determine traffic direction:

- `dir: "in"`: Traffic coming to your machine (source IP != external IP)
- `dir: "out"`: Traffic going from your machine (source IP == external IP)

You can filter traffic by direction using the `-d` flag:
- `-d in`: Show only inbound traffic
- `-d out`: Show only outbound traffic
- `-d both`: Show all traffic (default)

## Once Mode

When `--once` is enabled, each SNI will be shown only once, regardless of how many times it appears. The seen count will still track the total number of occurrences.

## JA3 Fingerprinting

When `--ja3` is enabled, each SNI entry will include a JA3 fingerprint of the TLS handshake. This can be useful for identifying specific clients or applications.

## File Logging

When `-o` is specified, logs will be written to the specified file with rotation support:
- Maximum file size: 500MB
- Maximum backup files: 3
- Maximum age: 28 days

## License

MIT 