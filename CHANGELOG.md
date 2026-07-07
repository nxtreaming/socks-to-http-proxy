# Changelog

## 0.9.8

- Extra SOCKS listener bind failures are now fatal when `--socks-port` is explicitly configured, preventing the process from continuing in a half-ready HTTP-only state.
- Normalize non-CONNECT HTTP forwarding: only `http://...` absolute-form requests are accepted, `https://...` requests are rejected with 400 and should use CONNECT, accepted HTTP request targets are rewritten to origin-form before forwarding upstream, and Host is preserved or synthesized from the original authority when absent.
- Validate `--allowed-domains` entries at startup using the existing domain pattern validator. Patterns are now trimmed and lowercased before storage, and invalid or empty entries fail fast instead of silently never matching.
- Security/behavior change: `--http-basic user:pass` now enables HTTP proxy authentication by default. In earlier versions, credentials were accepted but authentication stayed disabled unless `--no-httpauth=0` was also provided. Existing deployments that intentionally keep HTTP auth disabled while passing credentials must now set `--no-httpauth=1` explicitly.
