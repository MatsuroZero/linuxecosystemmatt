# NexusOne

NexusOne is a lightweight, local-first control plane for the Linux workstation ecosystem.

It is being assembled from the existing System Dashboard, Nexus Control CLI, Telegram Control Bot, and Discord Control Activity. The goal is one localhost web interface with a shared, permission-aware core while keeping each integration independently testable and restartable.

> **Status: foundation in progress.** This repository is not yet a drop-in replacement for the existing tools. Keep current installations and backups until migration is verified.

## Design principles

- Localhost-only by default; LAN access is an explicit deployment choice.
- Default dashboard address is `http://127.0.0.1:7171`; the port is configurable.
- One authorization policy shared by every interface.
- Administrator-only access for terminal, power, service, Docker, credential, configuration, and saved-command controls.
- CSRF protection, bounded requests, rate limits, and auditable state changes.
- Small modules with independent tests.
- Existing Explorer access remains available, constrained to the configured user workspace.
- Explorer supports large streaming and resumable uploads without a small arbitrary file-size cap; available disk space and configurable resource safeguards remain authoritative.
- A central administrator-only Configuration tab manages Telegram/Discord credentials, IDs, allowlists, and integration status without exposing stored secrets to the browser.
- Preserve historical snapshots in an immutable archive. Never delete source backups as part of migration.
- No secrets, environment files, dependency folders, caches, or generated bundles in source control.

## Planned structure

```text
nexusone/
  app/             Web application and API
  security/        Authentication, roles, CSRF, rate limiting
  core/            Service registry, events, audit, task orchestration
  adapters/        systemd, Docker, Ollama, desktop controls
  integrations/    Telegram and Discord adapters
  tests/
  config/
  deploy/
  docs/
  archive/         Preserved historical snapshots and provenance
```

## Migration phases

1. **Audit and baseline:** inventory source projects, identify canonical versions, inspect backups and dependencies, and record risks.
2. **Security foundation:** central roles, CSRF, request limits, rate limiting, localhost-first binding, and permission tests.
3. **Modularization:** extract shared services and split the dashboard into independently tested modules.
4. **Integration:** make Telegram and Discord clients of the shared core without duplicating privileged logic.
5. **Release:** verify migration, installation, tests, documentation, and deployment before replacing anything.

## Current audit notes

The source audit found an existing Flask dashboard, a useful Nexus CLI foundation, a Telegram bot with a user allowlist, and a Discord Activity with a single-user allowlist and 31 passing Node tests in an isolated run.

The uploaded Discord archive contains a populated `.env` and bundled `node_modules`. Neither is suitable for publication. Treat credentials in that archive as exposed and rotate them before deployment. The original archive is retained as audit input; it is not copied into this repository.

Additional owner-confirmed requirements are recorded in [docs/USER_REQUIREMENTS_ADDENDUM.md](docs/USER_REQUIREMENTS_ADDENDUM.md). The first Explorer upload and integration-settings implementation notes are in [docs/EXPLORER_AND_CONFIG.md](docs/EXPLORER_AND_CONFIG.md). The current foundation exposes an admin-only `/settings` page and an authenticated `/explorer` file manager with resumable chunk uploads. Upload sessions persist across server restarts and are scoped to the signed-in dashboard username.

## Development

The first implementation slice establishes shared security primitives and tests. Existing services remain the source of truth until each migration step has passed its tests and a manual smoke test on the target workstation.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m nexusone.app
```

The web app binds to `127.0.0.1:7171` by default. Set `NEXUSONE_PORT` to override the port. Production requires `NEXUSONE_SECRET_KEY`. Do not enable LAN binding until authentication, firewall rules, and secure transport have been configured.

A phone cannot reach a service bound only to `127.0.0.1` on the PC. To upload from a phone, explicitly enable the documented LAN mode and use the PC's LAN address; keep the firewall restricted to the trusted local network.

Never run the web process as root. Use narrowly scoped system permissions only where a specific adapter requires them.
