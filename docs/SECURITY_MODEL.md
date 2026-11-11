# Security model

## Roles

- `viewer`: dashboard read, logs read, and Explorer access within the configured workspace.
- `operator`: currently the same scope as viewer. New capabilities require an explicit policy change and tests.
- `admin`: all capabilities, including service/container/power control, terminal, saved commands, credentials, settings, and user management.

Unknown roles fail closed. The server resolves roles from authenticated identity; never trust a role supplied by the browser.

## Administrator-only capabilities

`services:control`, `containers:control`, `power:control`, `terminal:access`, `commands:execute`, `credentials:reveal`, `settings:manage`, and `users:manage`.

## Request protections

- 2 MiB maximum request body by default.
- Session-bound CSRF token required for POST, PUT, PATCH, and DELETE.
- Mutating requests with an Origin header must match the request origin or a configured trusted origin.
- Per-client sliding-window rate limit for the single-process deployment.
- HttpOnly, SameSite=Lax cookies; Secure enabled by default. Discord's embedded Activity deployment must explicitly use SameSite=None; Secure and a narrowly configured CSP frame-ancestors allowlist for Discord origins.
- Production requires a stable secret key from private configuration.
- Baseline response security headers.

The in-process limiter and session storage are only suitable for the initial single-process local deployment. Multi-worker or remote deployment requires shared storage and a deployment-specific review.

## LAN exposure

Loopback is the default. `NEXUSONE_ALLOW_LAN=1` opts into a non-loopback bind. Do not expose the service directly to the internet. LAN use requires HTTPS termination, firewall restrictions, strong authentication, and review of enabled integrations. Discord embedding must be enabled through a narrow CSP frame-ancestors configuration; do not add a conflicting X-Frame-Options SAMEORIGIN header.

## Explorer

Explorer remains supported. Its adapter must canonicalize paths and verify that the resolved target remains under the configured workspace. Tests must cover parent traversal, absolute paths, symlinks outside the workspace, and normal read/write operations.

## Secrets

Never commit `.env`, real tokens, passwords, private keys, local databases, or runtime memory. Use private environment files with restrictive permissions or a local secret store. Rotate any secret that has entered a public repository or chat transcript.
