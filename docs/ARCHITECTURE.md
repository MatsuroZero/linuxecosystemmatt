# NexusOne architecture

## Target model

```text
Browser UI
   |
   v
NexusOne Web/API
   |
   +-- Security: sessions, roles, CSRF, limits, audit
   +-- Core: service registry, task runner, events, settings
   +-- Adapters: systemd | Docker | Ollama | desktop | Explorer
   +-- Integrations: Telegram client | Discord Activity client
   +-- Storage: SQLite settings, jobs, audit events, sessions
```

## Runtime boundaries

- Run as the normal desktop user, never root.
- Bind to loopback by default; LAN mode is explicit and requires HTTPS, firewall restrictions, and strong authentication.
- System-level service actions require a narrow privileged helper or polkit rule.
- Validate every action against a fixed adapter registry. Never accept arbitrary shell strings from a web endpoint.
- Require explicit confirmation for destructive actions and record privileged actions in an audit log.
- Telegram and Discord call the shared core; they do not duplicate privileged control logic.

## Modules

- **Security:** identity/session validation, role-to-capability policy, CSRF, origin validation, request limits, rate limiting, audit.
- **Core:** typed service registry, action orchestration, health checks, event publication, settings.
- **Adapters:** systemd, Docker, Ollama, desktop controls, and Explorer.
- **Service controls (first slice):** fixed systemd unit allowlist; all services expose status, while only approved user-scope units can be started/stopped/restarted from the web UI. System-scope units remain status-only until a narrowly scoped polkit helper is designed and installed.
- **Explorer:** preserve access to the user's own workspace. Canonicalize paths and reject traversal and symlink escapes.
- **Integrations:** keep Telegram and Discord independently restartable so one integration cannot crash the dashboard.

SQLite is the initial store for settings, jobs, and audit events. Server-Sent Events can publish lightweight status changes. Avoid Redis, PostgreSQL, or a heavy frontend build chain until measured need justifies them.

## Migration

1. Establish security primitives and tests.
2. Wrap existing dashboard routes with explicit capabilities. The current compatibility middleware re-reads the legacy dashboard account database on each request when it exists, so deleted accounts and role changes take effect immediately.
3. Extract service definitions and health checks into adapters.
4. Make Telegram and Discord consume the shared API.
5. Archive snapshots with provenance and checksums.
6. Switch launchers/systemd units only after smoke tests pass.
