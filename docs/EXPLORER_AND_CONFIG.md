# Explorer transfer and integration settings implementation notes

This document describes the current foundation slice. It is not a claim that the legacy dashboard has already been replaced.

## Explorer upload flow

The full Explorer page is served at `/explorer` and requires an authenticated session with `explorer:read`. It restores workspace listing, navigation, download, folder creation, rename, delete, copy/cut/paste, and chunked uploads. The upload-only utility remains available at `/explorer/uploads`. File-management writes and upload API writes require `explorer:write`.

1. `POST /api/explorer/uploads` creates an upload session with filename, relative destination, and declared byte size.
2. `PUT /api/explorer/uploads/<upload_id>?offset=<bytes>` streams one binary chunk. The default chunk size is 8 MiB.
3. `GET /api/explorer/uploads/<upload_id>` returns the current offset so the browser can resume after a temporary connection interruption.
4. `POST /api/explorer/uploads/<upload_id>/finish` atomically finalizes the file without overwriting an existing destination.
5. `DELETE /api/explorer/uploads/<upload_id>` cancels and removes the staged upload.

The normal API request limit remains 2 MiB. The upload endpoint has its own per-chunk limit, so the application does not need to buffer an entire file in RAM or set an unlimited global request body size.

There is no arbitrary total-file-size cap in the upload manager. Available disk space, a reserved free-space margin, the maximum number of simultaneous sessions, filesystem limits, and browser/device limits still apply. The current default allows three active uploads per authenticated user and reserves 32 MiB of free space. The Explorer page provides a cancel action; canceled sessions remove their staging files. Resume keys include the file modification time to avoid accidentally continuing a different same-size file with the same name.

### Current limitations to close before release

- Upload session metadata is persisted in private sidecar files inside the staging directory. Sessions can resume after a NexusOne restart and expire after 24 hours. The staging directory is owner-only; sessions are bound to the authenticated dashboard username.
- The new Explorer UI is a first integrated replacement page, but it still needs visual integration with the legacy dashboard theme and a parity review against all existing Explorer edge cases.
- The browser Explorer currently processes selected files sequentially. Drag-and-drop and parallel multi-file scheduling remain optional future improvements.
- The Explorer root defaults to the current user's home directory. The final migration must preserve the existing Explorer path policy and test symlink and traversal handling against the real dashboard adapter.

## Phone-to-PC access

The default server address is `127.0.0.1:7171`. That is intentionally not reachable from a phone.

Phone transfers require explicitly enabling LAN mode and binding to the PC's LAN interface. Do not expose the development server directly to the internet. Before enabling LAN mode, integrate the existing login flow, use HTTPS with a certificate trusted by the phone, restrict the host firewall to the trusted local network, and configure allowed origins. Secure session cookies are enabled by default when LAN mode is enabled; localhost development defaults to non-Secure cookies so the local HTTP dashboard can work. LAN mode must use HTTPS.

## Integration Configuration

The admin-only page is served at `/settings`; API endpoints are `GET /api/config` and `PUT /api/config`. The current schema includes Telegram token, reveal PIN, authorized user IDs and chat IDs; the existing bot's dashboard, Odysseus, Jellyfin, Uptime Kuma, Gemini, and Ollama settings; Discord bot token, client ID, application ID, client secret, bridge secret, guild IDs, channel IDs, authorized user IDs, and Activity origin.

- Secrets are write-only at the API boundary. The public configuration response returns only a configured/not-configured flag.
- Blank secret fields preserve existing values. Separate clear checkboxes deliberately remove a stored secret.
- Configuration is written atomically outside the repository, with directory mode 0700 and file mode 0600.
- Configuration changes are audited without recording secret values. Saving settings exports private environment files at `~/.config/nexusone/telegram.env` and `~/.config/nexusone/discord.env`, using only the audited variable names consumed by the existing integrations.
- Install the Telegram example systemd drop-in at `deploy/systemd/telegram-control-bot.service.d/nexusone.conf.example` as `~/.config/systemd/user/telegram-control-bot.service.d/nexusone.conf`. Install the Discord example at `deploy/systemd/discord-control-activity.service.d/nexusone.conf.example` as `~/.config/systemd/user/discord-control-activity.service.d/nexusone.conf`. Then run `systemctl --user daemon-reload`.
- After saving configuration and installing the relevant drop-in, use the administrator-only **Services** page to restart `telegram-control-bot.service` or `discord-control-activity.service`. Both are now explicit user-service allowlist entries. The service manager invokes fixed `systemctl --user restart <known-unit>` argument arrays; it does not accept unit names or shell commands from the browser. Restarting is an explicit administrator action and is not automatic on save.
- The updated Telegram adapter reads `TELEGRAM_ALLOWED_USER_IDS` as a comma- or whitespace-separated allowlist and falls back to `TELEGRAM_ALLOWED_USER_ID` for older installations. NexusOne exports both variables for compatibility. The adapter change is in the open Telegram reliability PR and must be merged or installed before multiple IDs become active on the PC.
- The Discord Activity adapter has multi-user support on the open `discord-nexus-build` branch: it reads comma-separated `DISCORD_ALLOWED_USER_IDS` and falls back to the legacy `DISCORD_ALLOWED_USER_ID`. The Discord adapter branch currently has 34 passing Node tests; it remains a draft PR and is not deployed.
- Discord guild and channel IDs are stored by NexusOne for configuration continuity, but the current Activity does not enforce those context allowlists yet. The server must first receive and verify trusted Activity context rather than trusting client-supplied IDs.
- The foundation app does not create its own login accounts. During staged migration it validates the existing dashboard Flask session: by default it reads `~/.config/system-dashboard/secret_key`, uses the standard `session` cookie name, and maps the legacy `user` role to the `viewer` capability set. When the legacy user database exists, the current role and account existence are re-read on every request so role revocations and account deletions take effect immediately. It fails closed when no authenticated session is present. The old dashboard and NexusOne cannot both bind port 7171 simultaneously; deployment must integrate them behind one listener or migrate the dashboard routes before switching services.

The credentials file is protected by filesystem permissions, not application-level encryption. The operating-system account and disk security remain part of the trust boundary. Never commit the configuration file or copy secrets into issue reports or logs.
