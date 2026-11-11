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
- Blocks non-loopback clients by default. Requests carrying forwarded-client headers are also treated as remote, even when a local proxy makes `REMOTE_ADDR` look like loopback. If LAN access is explicitly enabled, the gateway requires the WSGI request scheme to be HTTPS and forces the NexusOne session cookie to use the `Secure` attribute.
- Does not change the dashboard's existing login or logout routes.

## Install procedure

1. Keep the existing dashboard service running while preparing the integration.
2. Install the NexusOne package into the same Python environment used by the dashboard process.
3. In the legacy dashboard's `app.py`, add the import and call below **after all existing routes are registered and before the server starts**:

```python
from nexusone.legacy_gateway import install_nexusone_gateway

install_nexusone_gateway(app, {
    "DASHBOARD_AUTH_DB": str(DASHBOARD_AUTH_DB),
    "EXPLORER_ROOT": str(_SHARING_HOME),
})
```

The helper takes the existing Flask app's `secret_key` and session cookie name automatically. Passing the actual `DASHBOARD_AUTH_DB` path is mandatory: the gateway refuses to install without it, rather than silently trusting a signed cookie without checking account existence and current role.

4. Add a link to the existing dashboard navigation:

```html
<a href="/nexusone/">NexusOne</a>
```

5. Restart the dashboard service during a maintenance window. The dashboard remains at its normal root URL; NexusOne is available at `/nexusone/`.
6. Verify login, logout, viewer/admin access, Explorer operations, and the legacy dashboard's existing APIs before enabling any new service controls.

## Security boundaries

- Do not set `allow_lan=True` on the gateway for plain HTTP. The gateway rejects non-loopback requests unless LAN mode is explicitly enabled, and then rejects them unless the WSGI scheme is HTTPS.
- If TLS is terminated by a reverse proxy, configure that proxy and WSGI server to convey the HTTPS scheme through a trusted mechanism, and restrict direct access to the WSGI listener. Do not trust arbitrary client-supplied forwarded-proto headers.
- Keep the existing Flask secret key private and stable during migration. Rotating it logs out existing dashboard sessions.
- The web process must continue running as the normal desktop user, never root.
- System-scope service actions remain status-only until a narrowly scoped polkit helper exists.
- Keep the old dashboard source and service configuration backed up. Do not remove the legacy routes until parity tests and workstation smoke tests pass.

## Current limitations

The gateway provides a same-origin route mount, not a completed dashboard redesign. The legacy dashboard remains the identity provider and retains its existing home page. NexusOne's Explorer and Configuration pages are available through the new navigation link, but the legacy dashboard's visual components, monitoring widgets, terminal, and remaining Docker controls still need to be migrated into the shared UI.

The first gateway tests exercise shared sessions, route isolation, CSRF, and the loopback/HTTPS boundary. They do not replace a workstation smoke test on the user's CachyOS installation.
