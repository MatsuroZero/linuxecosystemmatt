# NexusOne user requirements addendum

This document records additional product requirements confirmed by the owner. These requirements extend the migration plan and must be included in implementation and acceptance testing.

## 1. Dashboard address and port

- Default bind address: `127.0.0.1`.
- Default HTTP port: `7171`.
- Port must be configurable through deployment configuration (for example, `NEXUSONE_PORT`) without editing source.
- The dashboard must report a clear startup error if the requested port is already occupied.
- LAN/phone access is an explicit opt-in deployment mode. Localhost binding alone is not reachable from a phone; LAN mode must require authenticated access, firewall guidance, an explicit bind address, and secure transport when used beyond a trusted isolated network.

## 2. Explorer large-file uploads

The Explorer is a personal file-management feature and must remain available after dashboard modularization.

### Functional requirements

- Support large files without an arbitrary small application-level maximum.
- Stream incoming data to disk; never buffer an entire upload in application memory.
- Support chunked/resumable uploads so a temporary phone/network interruption does not require restarting a very large transfer.
- Display upload progress, destination, transfer state, and actionable errors.
- Allow cancellation and safe cleanup of incomplete temporary uploads.
- Support multiple files and ordinary phone-to-PC browser uploads.
- Preserve the existing workspace/home-directory boundary and path traversal protections.
- Require authenticated access; destructive overwrite/delete operations require appropriate authorization and confirmation.

### Resource and safety requirements

- “No fixed file-size cap” does not mean bypassing all resource controls. Enforce available disk-space checks, per-user concurrent-transfer limits, upload-session expiry, and configurable storage quotas if enabled.
- Use unique temporary names and atomic finalization after a completed upload.
- Validate each chunk's upload/session ownership and expected sequence/offset; reject path changes and mismatched chunks.
- Do not trust client-provided filenames or content types. Normalize filenames and prevent traversal, symlink escapes, and accidental writes outside the configured Explorer root.
- Keep upload metadata separate from user-supplied filesystem paths.
- Configure reverse proxies (if any) not to impose a conflicting body-size limit, and document proxy buffering/timeouts. The default local deployment should avoid a reverse proxy unless needed.
- Add tests for large streaming behavior, interrupted/resumed transfers, concurrent uploads, disk-full handling, path traversal, overwrite behavior, and unauthorized access.

## 3. Central Configuration section

Add an administrator-only Configuration tab to the main NexusOne website. It is the single place to configure integration credentials, identifiers, and access allowlists.

### Telegram settings

Provide fields for applicable values such as:
- Bot token.
- Authorized Telegram user IDs (add/remove multiple numeric IDs).
- Optional chat/group IDs and integration-specific settings required by the existing bot.
- Existing credential-reveal PIN setting, retaining the requested default/configuration value of `7171` only where that legacy workflow still requires it. It must not be treated as the sole authorization control.

### Discord settings

Provide fields for applicable values such as:
- Bot token.
- Application/client ID and client secret.
- Guild/server IDs and any channel IDs required by enabled features.
- Authorized Discord user IDs (add/remove multiple numeric IDs).
- Discord Activity application/origin configuration and allowed origins.

The final field list must be derived from the audited integrations rather than inventing unsupported settings. Validate identifier formats and test connectivity without displaying secret values.

### Security and UX requirements

- Only administrators can view or change integration configuration.
- Secret inputs are write-only by default. On page load, show only configured/not-configured status and a masked indicator, never the stored value.
- Saving a new secret replaces the old value; an empty field leaves the existing secret unchanged. Provide a deliberate clear action with confirmation.
- Store secrets outside the Git repository with restrictive filesystem permissions (for example, a dedicated configuration directory with mode 0700 and secret files mode 0600), or use authenticated encryption at rest with a protected key. Never store credentials in browser local storage, frontend bundles, logs, SQLite plaintext, or committed `.env` files.
- Keep non-secret identifiers and allowlists in a structured configuration store with schema validation.
- Apply changes atomically, validate before activation, and support safe rollback to the previous valid configuration.
- Audit configuration changes without recording secret values.
- Restart/reload only the affected integration where feasible; report whether a change is pending restart or active.
- Provide clear per-integration health/configuration status.

## 4. Acceptance criteria

- A phone on the same trusted LAN can upload a large file through the Explorer when the owner explicitly enables LAN access and authenticates. The default localhost-only mode remains inaccessible from other devices.
- Uploads stream to disk and can resume after a simulated connection interruption.
- A completed upload appears only within the configured Explorer workspace.
- The dashboard starts on `http://127.0.0.1:7171` by default, unless deployment configuration overrides it.
- Administrators can configure Telegram and Discord credentials and allowlisted IDs from the Configuration tab.
- Non-administrators cannot access the Configuration UI or its API endpoints.
- No API response, log entry, HTML page, frontend state, or Git commit reveals stored secrets.
- All new behavior has automated tests and documented operational setup.

## 5. Implementation sequencing

1. Keep the default deployment localhost-only on port 7171.
2. Implement secure settings storage and central configuration schema.
3. Implement the admin-only Configuration UI and API, initially without wiring every integration action.
4. Implement streaming/resumable Explorer uploads and resource safeguards.
5. Integrate Telegram and Discord configuration through adapters, validate/reload behavior, and add end-to-end tests.
6. Document LAN access for phone transfers as an explicit opt-in, not a default exposure.
