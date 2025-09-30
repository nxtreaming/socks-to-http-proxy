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

See "Advanced Usage Examples" below for authentication and domain whitelist configurations.

### Advanced Usage Examples

- Require HTTP proxy auth and allow only example.com (apex + subdomains):
```bash
sthp -p 8080 -s 127.0.0.1:1080 \
  --http-basic user:pass --no-httpauth=0 \
  --allowed-domains .example.com
```

- Allow multiple domains (exact apex and subdomains):
```bash
sthp -p 8080 -s 127.0.0.1:1080 \
  --http-basic user:pass --no-httpauth=0 \
  --allowed-domains example.com,*.test.org
```

- Higher throughput (allow HTTP/1.1 keep-alive). Use with monitoring:

```bash
sthp -p 8080 -s 127.0.0.1:1080 --force-close=false
```
- Limit per-IP connections (e.g., 300):
```bash
sthp -p 8080 -s 127.0.0.1:1080 --conn-per-ip 300
```
- Auth + whitelist + per-IP limit:
```bash
sthp -p 8080 -s 127.0.0.1:1080 \
  --http-basic user:pass --no-httpauth=0 \
  --allowed-domains .example.com \
  --conn-per-ip 300
```
- Keep-alive + per-IP cap (throughput with guardrails):
```bash
sthp -p 8080 -s 127.0.0.1:1080 --force-close=false --conn-per-ip 300
```
- High-throughput with auth + whitelist + per-IP cap (keep-alive):
```bash
sthp -p 8080 -s 127.0.0.1:1080 \
  --force-close=false \
  --http-basic user:pass --no-httpauth=0 \
  --allowed-domains .example.com \
  --conn-per-ip 300
```

### Options

There are a few options for using `sthp`.

```text
Usage: sthp [OPTIONS]

Options:
  -p, --port <PORT>                        Port where HTTP proxy should listen [default: 8080]
      --listen-ip <LISTEN_IP>              [default: 0.0.0.0]
  -u, --username <USERNAME>                Socks5 username
  -P, --password <PASSWORD>                Socks5/vendor password (-P): SOAX=package_key; Connpnt=vendor password
      --http-basic <USER:PASSWD>           HTTP Basic Auth
      --no-httpauth <1/0>                  Ignore HTTP Basic Auth [default: 1]
  -s, --socks-address <SOCKS_ADDRESS>      Socks5 proxy address [default: 127.0.0.1:1080]
      --allowed-domains <ALLOWED_DOMAINS>  Comma-separated list of allowed domains (supports exact, *.domain, .domain, or *)
      --idle-timeout <IDLE_TIMEOUT>        Idle timeout in seconds for CONNECT tunnels and regular HTTP requests [default: 540]
      --force-close <FORCE_CLOSE>          Force 'Connection: close' on forwarded HTTP requests [default: true]
                                           Set to false to allow HTTP/1.1 keep-alive for higher throughput
      --conn-per-ip <CONN_PER_IP>          Maximum connections per client IP [default: 500]
      --stats-dir <STATS_DIR>              Directory to persist traffic stats files (per-port). Default: current dir
      --stats-interval <SECONDS>           Interval seconds to log and persist traffic stats [default: 60]

  -h, --help                               Print help information
  -V, --version                            Print version information
```

#### SOAX options (optional)

- `--soax-country <COUNTRY>`: SOAX target country (ISO 3166-1 alpha-2 code or full name), e.g., "US" or "United States".
- `--soax-region <REGION>`: SOAX target region/state/province within the country, e.g., "California" or "CA".
- `--soax-city <CITY>`: SOAX target city name, e.g., "Los Angeles".
- `--soax-isp <ISP>`: SOAX target ISP/carrier name, e.g., "AT&T".



#### Connpnt vendor mode (optional)

- `--connpnt-enable 1` to enable this vendor mode
- `--connpnt-user <BASE_USER>`: base username provided by vendor (e.g., `ku2605kbkxid`)
- `-P, --password <PASSWORD>`: vendor password (e.g., `kjjacvbu7huwd`)
- `--connpnt-country <CC>`: country code (e.g., `US`, `BR`)
- `--connpnt-keeptime <MINUTES>`: session keeptime in minutes (0 = unlimited)
- `--connpnt-project <NAME>`: optional project name; ipstr becomes `NAME$<random>` to isolate per-project IP traversal
- `--connpnt-entry-hosts <H1,H2,...>`: entry hosts list; default depends on country:
  - `US` → `pv3.connpnt134.com,pv2.connpnt134.com`
  - others → `pv5.connpnt134.com,pv4.connpnt134.com`
- `--connpnt-socks-port <PORT>`: SOCKS port (default: 9135)

Example:
```bash
# Start HTTP proxy that uses Connpnt SOCKS vendor under the hood
sthp \
  -p 8080 \
  --connpnt-enable 1 \
  --connpnt-user ku2605kbkxid \
  --connpnt-country BR \
  --connpnt-keeptime 0 \
  -P kjjacvbu7huwd

# Client traffic via local HTTP proxy on 8080
curl -x http://127.0.0.1:8080 https://ipinfo.io
```

Notes:
- Username is constructed per connection as `BASE-<ipstr>-<keeptime>-<country>-N`.
  - `<ipstr>` is randomized each connection; if `--connpnt-project NAME` is set, it becomes `NAME$<random>` to isolate projects.
  - When switching `country`, a new `<ipstr>` is generated automatically to ensure the change takes effect.
- One of the configured entry hosts is pseudo-randomly selected per connection; each entry host maps to an independent IP pool.

## Performance & Stability Recommendations

- Default for production: keep `--force-close=true` (historical default; now configurable). This forces `Connection: close` on forwarded HTTP requests and helps prevent lingering sockets/CLOSE_WAIT buildup. It slightly reduces throughput for large non-CONNECT HTTP transfers but yields more predictable resource usage.
- When to consider `--force-close=false`: in trusted, well-behaved upstream environments where you want higher throughput via HTTP/1.1 keep-alive. Monitor connection counts and memory closely; revert to `true` if you observe resource pressure.
- Pair with `--conn-per-ip` to bound per-client impact during spikes; start with 500 and tune based on upstream capacity and concurrency patterns.

- CONNECT (HTTPS tunneling) is unaffected by `--force-close` and will remain stable with the existing idle timeout.
- Keep the idle timeout (`--idle-timeout`, default 540s) aligned with your operational requirements. For CONNECT tunnels it acts as an idle timer (resets on traffic; closes after a quiet window). For normal HTTP (non-CONNECT) requests it acts as a per-request timeout: exceeding it aborts the upstream connection and returns 504 Gateway Timeout. Lower the value to reclaim idle/stuck connections more aggressively in resource-constrained environments.

### Examples

- Production (recommended):
```bash
sthp -p 8080 -s 127.0.0.1:1080 --force-close=true
```

- Higher throughput experiment (only if you can tolerate longer-lived HTTP/1.1 connections):
```bash
sthp -p 8080 -s 127.0.0.1:1080 --force-close=false
```

## HTTP Proxy Authentication

- Configure credentials with `--http-basic <USER:PASSWD>`.
- Control whether authentication is enforced with `--no-httpauth <1/0>` (default: `1`, meaning HTTP auth is ignored/disabled). Set to `0` to require authentication.
- Behavior when authentication is required (`--no-httpauth=0`):
  - Missing or incorrect `Proxy-Authorization` header results in `407 Proxy Authentication Required` and includes `Proxy-Authenticate: Basic realm="proxy"`.

### Examples

- Require authentication:
```bash
sthp -p 8080 -s 127.0.0.1:1080 --http-basic user:pass --no-httpauth=0
```

- Client usage with curl:
```bash
curl -x http://127.0.0.1:8080 --proxy-user user:pass http://example.com/
# or explicitly set header
curl -x http://127.0.0.1:8080 -H "Proxy-Authorization: Basic $(printf 'user:pass' | base64)" http://example.com/
```

## Allowed Domains (Whitelist)

Use `--allowed-domains` with a comma-separated list. Supported patterns:
- `example.com` — exact match of the apex only
- `*.example.com` — any subdomain of example.com (a.example.com, a.b.example.com), not the apex
- `.example.com` — apex and any subdomain (example.com, a.example.com)
- `*` — allow all domains


Note: The whitelist is applied to both normal HTTP requests and CONNECT tunnels. Matching is based on the request Host only.

### Examples
```bash
# Allow only example.com and its subdomains
sthp -p 8080 -s 127.0.0.1:1080 --allowed-domains .example.com

# Allow multiple domains
sthp -p 8080 -s 127.0.0.1:1080 --allowed-domains example.com,*.test.org

# Allow all (not recommended unless you trust the environment)
sthp -p 8080 -s 127.0.0.1:1080 --allowed-domains "*"
```

## Connection Management

- `--force-close` (default: true): Forces `Connection: close` on forwarded HTTP (non-CONNECT) requests. This has been the historical default; the flag simply makes it configurable. It favors stability and resource predictability over maximum throughput.
- `--idle-timeout` (default: 540s): Applies to both CONNECT tunnels and normal HTTP requests.
  - CONNECT: idle timer resets on traffic; when no bytes flow in either direction for the timeout window, the tunnel is closed.
  - HTTP (non-CONNECT): acts as a per-request timeout; when exceeded, the upstream connection is aborted and a 504 Gateway Timeout is returned.
- `--conn-per-ip` (default: 500): Enforces a per-client IP cap. New connections beyond the cap are immediately closed on accept.

Recommendations:
- Keep `--force-close=true` in production unless you have measured benefits and sufficient headroom to allow keep-alive.
- Tune `--idle-timeout` according to workload (shorter for highly ephemeral tunnels, longer for long-lived ones).
- Adjust `--conn-per-ip` to reflect your multi-tenant policy and upstream capacity.



### Implementation notes (stability)

- RAII buffer management: pooled buffers are automatically returned on scope exit, including error and early-return paths. This reduces memory churn and avoids leaks when many tunnels are opened/closed.
- Per-IP connection limiting: enforcement uses an atomic check-and-increment under a single lock to prevent races that could temporarily exceed the configured cap.

## Traffic Statistics

- Per-port cumulative byte counters (RX from client, TX to client)
- Persistence: one file per listening port: `traffic_stats_{port}.txt` in `--stats-dir` (default: current directory)
- Periodic logging and persistence every `--stats-interval` seconds (default: 60)
- Management endpoints (apply the same HTTP auth policy as the proxy itself):
  - `GET /stats` → `{"port":<u16>,"rx":<u64>,"tx":<u64>}`
  - `POST /stats/reset` → `{"ok":true}` and immediately persists zeros

Examples:
```bash
# If authentication is required (recommended), include Proxy-Authorization
curl -s http://127.0.0.1:8080/stats \
  -H "Proxy-Authorization: Basic $(printf 'user:pass' | base64)"

# Reset counters and persist immediately
curl -s -X POST http://127.0.0.1:8080/stats/reset \
  -H "Proxy-Authorization: Basic $(printf 'user:pass' | base64)"

# Start with custom stats directory and 30s interval
sthp -p 8080 -s 127.0.0.1:1080 --stats-dir ./stats --stats-interval 30
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

## Troubleshooting

- Getting 407 Proxy Authentication Required:
  - If you configured credentials, ensure `--no-httpauth=0` and the client sends `Proxy-Authorization: Basic <base64(user:pass)>`.
  - With curl: `curl -x http://127.0.0.1:8080 --proxy-user user:pass http://example.com/`
- Request blocked or 403 due to domain whitelist:
  - Verify `--allowed-domains` patterns. Use `.example.com` for apex+subdomains, `*.example.com` for subdomains only, `example.com` for apex only, or `*` to allow all.
  - Matching is based on the HTTP Host (for CONNECT, the target host).
- Connection closes immediately on accept:
  - Per-IP limit reached. Increase `--conn-per-ip` or reduce client concurrency. See warn logs for IP counts.
- Long-lived or stuck connections consuming resources:
  - Prefer `--force-close=true` (default) for non-CONNECT requests. Tune `--idle-timeout` (applies to both CONNECT tunnels and normal HTTP requests).
- Bind error / port already in use:
  - Choose a different port with `-p <PORT>` or adjust `--listen-ip`.
- Need more details to diagnose:
  - Temporarily increase log verbosity:
    - Unix-like: `RUST_LOG=sthp=debug sthp -p 8080 -s 127.0.0.1:1080`
    - Windows PowerShell: `$env:RUST_LOG="sthp=debug"; sthp -p 8080 -s 127.0.0.1:1080`
  - Lower overhead alternative: `sthp=info`
  - Save to file: `RUST_LOG=sthp=info sthp -p 8080 -s 127.0.0.1:1080 > proxy.log 2>&1`

