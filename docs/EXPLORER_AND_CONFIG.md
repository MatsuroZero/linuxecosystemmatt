# Explorer transfer and integration settings implementation notes

This document describes the current foundation slice. It is not a claim that the legacy dashboard has already been replaced.

## Explorer upload flow

The current standalone upload page is served at `/explorer/uploads` and requires an authenticated session with `explorer:read`. Upload API writes require `explorer:write`.

1. `POST /api/explorer/uploads` creates an upload session with filename, relative destination, and declared byte size.
2. `PUT /api/explorer/uploads/<upload_id>?offset=<bytes>` streams one binary chunk. The default chunk size is 8 MiB.
3. `GET /api/explorer/uploads/<upload_id>` returns the current offset so the browser can resume after a temporary connection interruption.
4. `POST /api/explorer/uploads/<upload_id>/finish` atomically finalizes the file without overwriting an existing destination.
5. `DELETE /api/explorer/uploads/<upload_id>` cancels and removes the staged upload.

The normal API request limit remains 2 MiB. The upload endpoint has its own per-chunk limit, so the application does not need to buffer an entire file in RAM or set an unlimited global request body size.

There is no arbitrary total-file-size cap in the upload manager. Available disk space, a reserved free-space margin, the maximum number of simultaneous sessions, filesystem limits, and browser/device limits still apply. The current default allows three active uploads and reserves 32 MiB of free space.

### Current limitations to close before release

- Upload session metadata currently lives in process memory. A temporary network interruption can resume while NexusOne remains running, but a NexusOne restart loses the session mapping. Persistent session metadata and stale staging cleanup are required before claiming restart-safe resume.
- The upload page is currently a separate foundation route. It still needs to be integrated into the main dashboard's existing Explorer navigation and visual design.
- The browser upload page currently processes selected files sequentially. Parallel multi-file scheduling and explicit cancel controls can be added after the core path is integrated.
- The Explorer root defaults to the current user's home directory. The final migration must preserve the existing Explorer path policy and test symlink and traversal handling against the real dashboard adapter.

## Phone-to-PC access

The default server address is `127.0.0.1:7171`. That is intentionally not reachable from a phone.

Phone transfers require explicitly enabling LAN mode and binding to the PC's LAN interface. Do not expose the development server directly to the internet. Before enabling LAN mode, integrate the existing login flow, use HTTPS with a certificate trusted by the phone, restrict the host firewall to the trusted local network, and configure allowed origins. Secure session cookies are enabled by default when LAN mode is enabled; localhost development defaults to non-Secure cookies so the local HTTP dashboard can work. LAN mode must use HTTPS.

## Integration Configuration

The admin-only page is served at `/settings`; API endpoints are `GET /api/config` and `PUT /api/config`. The current schema includes Telegram token, reveal PIN, authorized user IDs and chat IDs; Discord bot token, client ID, application ID, client secret, bridge secret, guild IDs, channel IDs, authorized user IDs, and Activity origin.

- Secrets are write-only at the API boundary. The public configuration response returns only a configured/not-configured flag.
- Blank secret fields preserve existing values. Separate clear checkboxes deliberately remove a stored secret.
- Configuration is written atomically outside the repository, with directory mode 0700 and file mode 0600.
- Configuration changes are not yet wired to restart or reconfigure the legacy bot processes. That work belongs to the integration-adapter phase.
- The foundation app does not create its own login accounts. During staged migration it can validate the existing dashboard Flask session: by default it reads `~/.config/system-dashboard/secret_key`, uses the standard `session` cookie name, and maps the legacy `user` role to the `viewer` capability set. It fails closed when no authenticated session is present. The old dashboard and NexusOne cannot both bind port 7171 simultaneously; deployment must integrate them behind one listener or migrate the dashboard routes before switching services.

The credentials file is protected by filesystem permissions, not application-level encryption. The operating-system account and disk security remain part of the trust boundary. Never commit the configuration file or copy secrets into issue reports or logs.
