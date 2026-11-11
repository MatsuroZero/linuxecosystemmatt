# Source audit: initial findings

Scope: the reference repository `MatsuroZero/linuxsetupteststest` and uploaded `discord-control-bot.zip`. This is a source-level review plus an isolated Discord test run. No live installation was modified and no production service was restarted.

## Discord Control Activity

- Source is split into authz, control, registry, memory, AI, and server modules.
- It has a Discord user-ID allowlist, session cookies, origin checks on mutating endpoints, bounded JSON parsing, action allowlists, action cooldowns, and a PIN lockout.
- The included Node suite passed: **31 tests, 0 failures**, under Node.js 22. The test run used a temporary source/test-only extraction and did not load the archive's `.env` or `node_modules`.
- The server's `listen()` call does not specify a host, so it can bind beyond loopback. NexusOne's initial server explicitly defaults to `127.0.0.1`.
- There is no general request-rate limiter. Saved registry commands execute configured argv without shell interpretation, but still permit arbitrary actions as the service account. Keep them administrator-only and auditable.
- Credential reveal returns dashboard credentials to the browser after Discord session and PIN checks. The unified service must additionally require the admin capability, re-authentication, short display lifetime, and audit events.
- The OAuth access token is passed to Discord's Embedded App SDK `authenticate()` call. This is part of the SDK handshake; do not log or persist it unnecessarily.
- Sessions are in-memory and single-process only.

## Sensitive material in the uploaded archive

The archive contains a populated `.env` with non-placeholder Discord credentials and a control-bridge secret. Values are intentionally omitted. Treat them as exposed because the archive was also committed to a public repository.

Required owner actions:
1. Rotate the Discord bot token.
2. Rotate the Discord application client secret.
3. Replace the control-bridge secret anywhere configured.
4. Review Discord application activity and recent bot usage.
5. Remove the secret-bearing archive from the public repository and purge it from Git history after rotation. Deleting only the current file does not remove old Git objects.
6. Keep any original secret-bearing archive only in private, access-controlled storage.

The archive also includes `node_modules`, generated bundles, and backup variants. These are not copied into the canonical source tree.

## System Dashboard

The Flask dashboard is a large monolith. The inspected source showed:
- Default bind to `0.0.0.0`.
- Terminal API available to any authenticated dashboard user; this must be administrator-only.
- Inconsistent route-level authorization rather than a central capability policy.
- Request-size limits are unset.
- No consistent CSRF protection found in inspected routes.
- Explorer path resolution is intended to keep access inside the user's home directory. Preserve Explorer and add traversal/symlink boundary tests.
- Wallpaper upstream filtering is inconsistent. An age gate intended to unlock explicit material is out of scope; only non-explicit content preferences are planned.

## Nexus Control CLI

The CLI is a useful service-management and diagnostics foundation. It uses argument arrays for subprocess calls and has a pytest setup. Hard-coded paths and duplicated service definitions should move into shared configuration and adapters.

## Telegram Control Bot

The bot has a numeric user allowlist and PIN-gated credential reveal. Keep the chosen PIN in private deployment configuration, not source code. Add throttling, audit events, and private-chat checks. Preserve existing service and Docker allowlists while moving privileged operations behind the shared API.

## Repository hygiene

The reference repository contains timestamped backup files, ZIP snapshots, Python cache artifacts, and dependency/build artifacts. Preserve backups in an immutable archive with provenance and checksums. Ignore local environment files, caches, dependencies, and generated bundles.

## Confidence and limitations

This is not a penetration test. Discord tests do not prove Activity launch in the actual Discord client, HTTPS mapping, reverse-proxy configuration, or behavior on the user's live host. Existing services have not yet been migrated or replaced.
