# wormhole-rs

Rust implementation of the Magic Wormhole protocol for secure file and text transfers.

[![Rust](https://github.com/liberodark/wormhole-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/liberodark/wormhole-rs/actions/workflows/rust.yml)

## Features

- Secure end-to-end encrypted transfers using SPAKE2 key exchange
- Send and receive text messages
- Send and receive files
- Send and receive directories (as zip)
- Compatible with [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole) Python client
- Built-in rendezvous server for testing
- No external dependencies required

## Installation

### Via cargo
```bash
cargo install --path .
```

### Manual build
```bash
git clone https://github.com/liberodark/wormhole-rs.git
cd wormhole-rs
cargo build --release
sudo cp target/release/wormhole-rs /usr/local/bin/
```

### Precompiled binaries
Precompiled binaries are available in the [Releases](https://github.com/liberodark/wormhole-rs/releases) section.

## Usage

### Send text
```bash
# Send a text message
wormhole-rs send --text "Hello, World!"

# Send with custom code
wormhole-rs send --text "Secret message" --code 42-purple-elephant
```

### Send file
```bash
# Send a file
wormhole-rs send document.pdf

# Send with verification prompt
wormhole-rs send --verify document.pdf
```

### Send directory
```bash
# Send entire directory (compressed as zip)
wormhole-rs send my-folder/
```

### Receive
```bash
# Receive with code
wormhole-rs recv 42-purple-elephant

# Receive with verification
wormhole-rs recv --verify 42-purple-elephant
```

### Run local server
```bash
# Start rendezvous server on default port (4000)
wormhole-rs server

# Start on custom port
wormhole-rs server --port 8080
```

### Options

| Option | Description |
|--------|-------------|
| `--text <MSG>` | Send text message instead of file |
| `--code <CODE>` | Use specific wormhole code |
| `--verify` | Display verification string before transfer |
| `--relay-url <URL>` | Custom rendezvous server URL |
| `--port <PORT>` | Server port (server mode only) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WORMHOLE_RELAY_URL` | Rendezvous server URL | `ws://relay.magic-wormhole.io:4000/v1` |
| `WORMHOLE_TRANSIT_RELAY` | Transit relay address | `transit.magic-wormhole.io:4001` |

## Interoperability

wormhole-rs is compatible with the official Python magic-wormhole client:

```bash
# Send from wormhole-rs, receive with Python client
wormhole-rs send file.txt
# On other machine:
wormhole receive <code>

# Send from Python client, receive with wormhole-rs
wormhole send file.txt
# On other machine:
wormhole-rs recv <code>
```

## Protocol

The implementation follows the Magic Wormhole protocol:

1. **Rendezvous**: Both clients connect to a rendezvous server
2. **PAKE Exchange**: SPAKE2 key agreement using the shared code
3. **Encrypted Channel**: All subsequent messages encrypted with derived keys
4. **Transit**: Direct or relayed connection for file transfers

### Supported Transfer Types

- `TransferText`: Plain text messages
- `TransferFile`: Single file transfer
- `TransferDirectory`: Directory as zip archive

## Example Output

### Sending
```
$ wormhole-rs send test.tar.gz
Wormhole code is: 9-bookseller-vapor
On the other computer, please run:
  wormhole-rs recv 9-bookseller-vapor
file sent
```

### Receiving
```
$ wormhole-rs recv 9-bookseller-vapor
Receiving file (415 bytes): test.tar.gz
Accept? (y/n): y
Received file: test.tar.gz
```

### Server
```
$ wormhole-rs server --port 4000
Starting wormhole-rs server...
Rendezvous: ws://0.0.0.0:4000
Transit relay: 0.0.0.0:4001
Rendezvous server listening on ws://0.0.0.0:4000
Transit relay listening on 0.0.0.0:4001
```
