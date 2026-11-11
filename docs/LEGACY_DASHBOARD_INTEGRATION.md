# Staged integration with the existing System Dashboard

NexusOne can be mounted behind the existing Flask dashboard without replacing its login page or changing its current routes. The WSGI gateway keeps the dashboard at `/`, mounts the NexusOne pages at `/nexusone/`, and exposes NexusOne APIs through the same origin at `/nexusone-api/`.

This is the preferred migration path for the current stage: one listener, one browser origin, no reverse-proxy dependency, and no need to run two competing servers on port 7171.

## What the gateway does

- Leaves all existing dashboard routes in place. Legacy requests are passed to the original WSGI application unchanged.
- Mounts NexusOne pages at `/nexusone/`.
- Mounts NexusOne API endpoints at `/nexusone-api/`. The Explorer API therefore does not collide with the legacy dashboard's existing `/api/files` routes.
- Keeps non-HTML responses streaming, so large Explorer downloads are not buffered into memory by the gateway.
- Shares the legacy dashboard's signed Flask session cookie and signing key. NexusOne still checks the live dashboard users database on each request.
- Rewrites internal links and root-relative API fetches in NexusOne HTML so the pages remain inside the mounts.
- Blocks non-loopback clients across both legacy and NexusOne routes by default. Requests carrying forwarded-client headers are also treated as remote, even when a local proxy makes `REMOTE_ADDR` look like loopback. If LAN access is explicitly enabled, the gateway requires the WSGI request scheme to be HTTPS and forces both the legacy and NexusOne shared session cookies to use the `Secure` attribute.
- Does not change the dashboard's existing login or logout routes.

## Install procedure

1. Keep the existing dashboard service running while preparing the integration. Do not stop it yet.
2. Activate the same Python environment used by the dashboard and install NexusOne from its repository checkout:

   ```bash
   python -m pip install -e /path/to/linuxecosystemmatt
   ```

3. Run the reversible installer against the existing dashboard source:

   ```bash
   python /path/to/linuxecosystemmatt/deploy/integrate_legacy_dashboard.py \
     --dashboard-app /path/to/system-dashboard/app.py
   ```

   The installer validates the expected dashboard entry point and the audited
   `DASHBOARD_AUTH_DB` and `_SHARING_HOME` variables. It refuses duplicate or
   ambiguous integration, creates a timestamped source backup, and atomically
   inserts the gateway call after all existing routes and before the server
   starts. It does not restart or stop any service.

4. Record the printed backup path. To roll back, run:

   ```bash
   python /path/to/linuxecosystemmatt/deploy/integrate_legacy_dashboard.py \
     --dashboard-app /path/to/system-dashboard/app.py \
     --restore-backup /path/to/app.py.pre-nexusone-TIMESTAMP.bak
   ```

   Rollback also preserves the currently installed source in a separate
   recovery backup before restoring the selected original.

5. Review the inserted block and run a syntax check before scheduling a
   maintenance window. The generated integration calls:

   ```python
   from nexusone.legacy_gateway import install_nexusone_gateway

   install_nexusone_gateway(app, {
       "DASHBOARD_AUTH_DB": str(DASHBOARD_AUTH_DB),
       "EXPLORER_ROOT": str(_SHARING_HOME),
   })
   ```

   The helper takes the existing Flask app's `secret_key` and session cookie
   name automatically. Passing the actual `DASHBOARD_AUTH_DB` path is
   mandatory: the gateway refuses to install without it, rather than silently
   trusting a signed cookie without checking account existence and current role.

6. The legacy security bridge restores the existing dashboard's section
   navigation and adds File Transfer and administrator-only Integrations tabs.
   These tabs embed the NexusOne pages on the same origin; the taskbar also gets
   direct Explorer and administrator-only Configuration shortcuts. An optional
   general NexusOne overview link can be added with
   `<a href="/nexusone/">NexusOne</a>`.

7. Only after reviewing the backup and syntax check, restart the dashboard
   service during a maintenance window. The gateway defaults to loopback-only
   access even if the underlying Flask server is bound to all interfaces.
   NexusOne pages are available under `/nexusone/`.

8. Verify login, logout, viewer/admin access, every legacy section tab, the
   embedded File Transfer and Integrations tabs, streamed downloads, and the
   legacy dashboard's existing APIs before enabling any new service controls.

## Security bridge installed by the gateway

The current `install_nexusone_gateway(...)` helper also installs
`nexusone.legacy_security` on the existing Flask app after its original login
hook. This closes the gap where mounting NexusOne alone would leave legacy
machine-control routes governed only by the old route-level checks.

- The bridge refreshes non-reserved users from the configured SQLite account
  database on each authenticated request and invalidates deleted accounts.
- The reserved `marwan` dashboard identity remains the sole administrator.
- Terminal access, package actions, power/network changes, remote keyboard and
  mouse input, screen viewing/capture, process termination, Serpantinum changes,
  and local-agent execution are administrator-only. The injected navigation
  hides privileged control tabs from non-admin users; the server-side checks
  remain authoritative.
- Explorer and ordinary dashboard reads remain available to authenticated
  users. The existing Explorer workspace boundary is unchanged.
- Unsafe legacy requests require a same-origin Origin/Referer and a session-bound
  CSRF token. The response bootstrap adds the token to same-origin Fetch and
  XMLHttpRequest mutations, including the existing sharing upload flow and
  logout forms. Upload bodies are not parsed by the CSRF middleware.
- The middleware is intentionally installed only through the gateway helper;
  do not mount the raw legacy Flask app on a LAN listener without this bridge.

The bridge is a migration guard, not a substitute for route-by-route capability
tests. New legacy endpoints must be classified before they are exposed.

## Security boundaries

- Do not set `allow_lan=True` on the gateway for plain HTTP. The gateway rejects non-loopback requests to every legacy and NexusOne route unless LAN mode is explicitly enabled, and then rejects them unless the WSGI scheme is HTTPS.
- If TLS is terminated by a reverse proxy, configure that proxy and WSGI server to convey the HTTPS scheme through a trusted mechanism, and restrict direct access to the WSGI listener. Do not trust arbitrary client-supplied forwarded-proto headers.
- Keep the existing Flask secret key private and stable during migration. Rotating it logs out existing dashboard sessions.
- The web process must continue running as the normal desktop user, never root.
- System-scope service actions remain status-only until a narrowly scoped polkit helper exists.
- Keep the old dashboard source and service configuration backed up. Do not remove the legacy routes until parity tests and workstation smoke tests pass.

## Current limitations

The gateway provides a same-origin route mount and an initial unified navigation
shell, not a completed dashboard redesign. The legacy dashboard remains the
identity provider and retains its existing monitoring, terminal, and desktop
control sections. NexusOne File Transfer and Integrations render inside same-origin
tabs, while the underlying NexusOne pages still retain their own visual templates.
The remaining work is visual unification and capability-by-capability migration,
not rebuilding the existing monitoring widgets from scratch.

The first gateway tests exercise shared sessions, route isolation, CSRF, and the loopback/HTTPS boundary. They do not replace a workstation smoke test on the user's CachyOS installation.
