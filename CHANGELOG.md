# Changelog

## 0.9.8

- Security/behavior change: `--http-basic user:pass` now enables HTTP proxy authentication by default. In earlier versions, credentials were accepted but authentication stayed disabled unless `--no-httpauth=0` was also provided. Existing deployments that intentionally keep HTTP auth disabled while passing credentials must now set `--no-httpauth=1` explicitly.
