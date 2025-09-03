# socks-to-http-proxy ![Rust](https://github.com/KaranGauswami/socks-to-http-proxy/workflows/Rust/badge.svg) ![release](https://img.shields.io/github/v/release/KaranGauswami/socks-to-http-proxy?include_prereleases)

An executable to convert SOCKS5 proxy into HTTP proxy

## About

`sthp` purpose is to create HTTP proxy on top of the Socks 5 Proxy

## How it works

It uses hyper library HTTP proxy [example](https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs) and adds functionality to connect via Socks5

## Compiling

Follow these instructions to compile

1.  Ensure you have current version of `cargo` and [Rust](https://www.rust-lang.org) installed
2.  Clone the project `$ git clone https://github.com/KaranGauswami/socks-to-http-proxy.git && cd socks-to-http-proxy`
3.  Build the project `$ cargo build --release`
4.  Once complete, the binary will be located at `target/release/sthp`

## Usage

```bash
sthp -p 8080 -s 127.0.0.1:1080
```

This will create proxy server on 8080 and use localhost:1080 as a Socks5 Proxy

### Options

There are a few options for using `sthp`.

```text
Usage: sthp [OPTIONS]

Options:
  -p, --port <PORT>                        port where Http proxy should listen [default: 8080]
      --listen-ip <LISTEN_IP>              [default: 0.0.0.0]
  -u, --username <USERNAME>                Socks5 username
  -P, --password <PASSWORD>                Socks5 password
      --http-basic <USER:PASSWD>           HTTP Basic Auth
      --no-httpauth <1/0>                  Ignore HTTP Basic Auth, [default: 1]
  -s, --socks-address <SOCKS_ADDRESS>      Socks5 proxy address [default: 127.0.0.1:1080]
      --allowed-domains <ALLOWED_DOMAINS>  Comma-separated list of allowed domains
      --idle-timeout <IDLE_TIMEOUT>        Idle timeout in seconds for tunnel connections [default: 540]
  -h, --help                               Print help information
  -V, --version                            Print version information
```

## Log Level Control

`sthp` uses structured logging with different levels to help you monitor and debug the proxy. By default, it runs at `warn` level for optimal performance in production environments.

### Log Levels

- **error**: Only critical errors that may cause service interruption
- **warn**: Warnings including connection errors, timeouts, and important status changes (default)
- **info**: General information including service startup, high connection counts, and large file transfers
- **debug**: Detailed debugging information including all connections and data transfers

### Usage Examples

**Default (warn level) - Recommended for production:**
```bash
sthp -p 8080 -s 127.0.0.1:1080
```

**Enable debug logging for troubleshooting:**
```bash
RUST_LOG=sthp=debug sthp -p 8080 -s 127.0.0.1:1080
```

**Show only errors:**
```bash
RUST_LOG=sthp=error sthp -p 8080 -s 127.0.0.1:1080
```

**Enable info level logging:**
```bash
RUST_LOG=sthp=info sthp -p 8080 -s 127.0.0.1:1080
```

**Advanced logging configuration:**
```bash
# Enable debug for sthp but warn for other crates
RUST_LOG=sthp=debug,warn sthp -p 8080 -s 127.0.0.1:1080

# Log to file
RUST_LOG=sthp=info sthp -p 8080 -s 127.0.0.1:1080 > proxy.log 2>&1
```

### Performance Impact

- **warn/error**: Minimal performance impact, recommended for production
- **info**: Slight performance impact, good for monitoring
- **debug**: Noticeable performance impact, use only for troubleshooting

### What Gets Logged at Each Level

**Error Level:**
- Service startup failures
- Critical connection limits reached
- Severe system errors

**Warn Level (Default):**
- Connection errors and timeouts
- SOCKS5 authentication failures
- Domain access violations
- I/O errors during data transfer

**Info Level:**
- Service startup information
- Connection count warnings
- Large file transfer completions (>10MB)
- System status updates

**Debug Level:**
- Individual connection details
- Request/response timing
- Detailed error traces
- Connection lifecycle events
