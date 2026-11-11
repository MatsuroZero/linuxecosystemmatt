"""Shared NexusOne application shell with Material You / Matugen theming."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import secrets

from flask import Response, g, request, session

from nexusone.security.rbac import Capability, has_capability


_SHELL_CSS = r"""
:root {
  color-scheme: dark;
  --n1-primary: var(--md-sys-color-primary, #c5b5f5);
  --n1-on-primary: var(--md-sys-color-on-primary, #30264a);
  --n1-primary-container: var(--md-sys-color-primary-container, #493f62);
  --n1-on-primary-container: var(--md-sys-color-on-primary-container, #eadfff);
  --n1-bg: var(--md-sys-color-background, var(--md-sys-color-surface, #141318));
  --n1-surface: var(--md-sys-color-surface-container, #201f25);
  --n1-surface-high: var(--md-sys-color-surface-container-high, #2b2930);
  --n1-text: var(--md-sys-color-on-surface, #e7e1e9);
  --n1-muted: var(--md-sys-color-on-surface-variant, #c9c3d0);
  --n1-outline: var(--md-sys-color-outline, #938d9a);
  --n1-danger: var(--md-sys-color-error, #f2b8b5);
  --n1-radius: 18px;
}
* { box-sizing: border-box; }
html { min-height: 100%; background: var(--n1-bg); }
body {
  display:block !important; width:100% !important; max-width:none !important;
  min-height:100vh; margin:0 !important; padding:0 !important;
  background:var(--n1-bg) !important; color:var(--n1-text) !important;
  font:14px/1.55 Inter,"Noto Sans",system-ui,sans-serif !important;
}
a { color:var(--n1-primary) !important; text-decoration:none; }
.n1-shell { min-height:100vh; }
.n1-sidebar {
  position:fixed; inset:0 auto 0 0; z-index:20; width:252px;
  display:flex; flex-direction:column; gap:24px; padding:25px 16px;
  background:var(--md-sys-color-surface-container-low,var(--n1-surface));
  border-right:1px solid color-mix(in srgb,var(--n1-outline) 22%,transparent);
}
.n1-brand { display:flex; align-items:center; gap:12px; padding:3px 9px 18px; }
.n1-brand-mark {
  display:grid; place-items:center; width:40px; height:40px; border-radius:14px;
  color:var(--n1-on-primary); background:var(--n1-primary); font-size:20px; font-weight:800;
}
.n1-brand strong { display:block; font-size:17px; letter-spacing:.02em; }
.n1-brand small { color:var(--n1-muted); font-size:11px; }
.n1-nav-label { padding:0 11px; color:var(--n1-muted); font-size:10px; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }
.n1-nav { display:grid; gap:5px; }
.n1-nav a {
  display:flex; align-items:center; gap:12px; min-height:43px; padding:9px 12px;
  border-radius:13px; color:var(--n1-muted) !important; font-weight:550;
}
.n1-nav a:hover { background:var(--n1-surface-high); }
.n1-nav a[aria-current="page"] { color:var(--n1-on-primary-container) !important; background:var(--n1-primary-container); font-weight:700; }
.n1-nav .n1-icon { width:21px; text-align:center; font-size:16px; }
.n1-sidebar-foot { margin-top:auto; padding:13px 11px; border-top:1px solid color-mix(in srgb,var(--n1-outline) 22%,transparent); color:var(--n1-muted); font-size:11px; }
.n1-workspace { min-height:100vh; margin-left:252px; padding:0 34px 42px; }
.n1-topbar { display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:76px; margin:0 -2px 25px; border-bottom:1px solid color-mix(in srgb,var(--n1-outline) 20%,transparent); }
.n1-topbar-title { color:var(--n1-muted); font-size:12px; letter-spacing:.06em; }
.n1-user { display:flex; align-items:center; gap:10px; color:var(--n1-muted); font-size:12px; }
.n1-avatar { display:grid; place-items:center; width:34px; height:34px; border-radius:50%; background:var(--n1-primary-container); color:var(--n1-on-primary-container); font-weight:700; }
.n1-page { width:min(1500px,100%); margin:0 auto; }
.n1-page > header { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:16px; margin:0 0 24px !important; }
.n1-page h1 { margin:0 0 5px; font-size:clamp(25px,3vw,34px); line-height:1.2; letter-spacing:-.035em; }
.n1-page h2 { font-size:17px; }
.n1-page p,.n1-page .muted,.n1-page small { color:var(--n1-muted) !important; }
.n1-page article,.n1-page section,.n1-page .tile,.n1-page main {
  background:var(--n1-surface) !important;
  border:1px solid color-mix(in srgb,var(--n1-outline) 22%,transparent) !important;
  border-radius:var(--n1-radius) !important; color:var(--n1-text);
}
.n1-page .tiles,.n1-page .grid { gap:14px !important; }
.n1-page .tile { min-height:145px; padding:20px !important; }
.n1-page button,.n1-page input,.n1-page textarea,.n1-page select { font:inherit; border-radius:11px; border:1px solid var(--n1-outline); }
.n1-page button { padding:9px 14px; color:var(--n1-text); background:var(--n1-surface-high); cursor:pointer; }
.n1-page button.primary,.n1-page button[type="submit"] { background:var(--n1-primary) !important; color:var(--n1-on-primary) !important; border-color:transparent; }
.n1-page input:not([type=checkbox]):not([type=radio]),.n1-page textarea,.n1-page select { padding:10px 12px; color:var(--n1-text); background:var(--n1-bg); border-color:var(--n1-outline); }
.n1-page input[type=checkbox] { accent-color:var(--n1-primary); }
.n1-page td,.n1-page th { border-bottom:1px solid color-mix(in srgb,var(--n1-outline) 22%,transparent); }
.n1-page .status,.n1-page #status { color:var(--n1-primary); }
.n1-page .inactive { color:var(--n1-danger) !important; }
.n1-page progress { accent-color:var(--n1-primary); }
@media(max-width:850px) {
  .n1-sidebar { width:76px; padding:20px 9px; gap:18px; }
  .n1-brand { justify-content:center; padding:0 0 12px; }
  .n1-brand-copy,.n1-nav-label,.n1-nav .n1-label,.n1-sidebar-foot { display:none; }
  .n1-nav a { justify-content:center; padding:11px 5px; }
  .n1-nav .n1-icon { font-size:19px; }
  .n1-workspace { margin-left:76px; padding:0 18px 30px; }
}
@media(max-width:560px) {
  .n1-sidebar { inset:auto 0 0; width:auto; height:68px; padding:6px 8px; border-right:0; border-top:1px solid var(--n1-outline); }
  .n1-brand,.n1-nav-label,.n1-sidebar-foot { display:none; }
  .n1-nav { display:flex; justify-content:space-around; gap:2px; }
  .n1-nav a { flex:1; min-width:0; min-height:54px; flex-direction:column; justify-content:center; gap:1px; padding:3px 1px; font-size:9px; }
  .n1-nav .n1-icon { font-size:17px; line-height:1.2; }
  .n1-nav .n1-label { display:block; }
  .n1-workspace { margin:0; padding:0 14px 90px; }
  .n1-topbar { min-height:58px; margin-bottom:20px; }
  .n1-user { font-size:0; }
}
"""

_SHELL_JS = r"""
(() => {
  const meta = document.querySelector('meta[name="n1-shell-config"]');
  if (!meta || !document.body || document.querySelector(".n1-shell")) return;
  let config;
  try { config = JSON.parse(meta.content); } catch { return; }
  const shell = document.createElement("div");
  shell.className = "n1-shell";
  const aside = document.createElement("aside");
  aside.className = "n1-sidebar";
  const brand = document.createElement("div");
  brand.className = "n1-brand";
  brand.innerHTML = '<span class="n1-brand-mark">N</span><span class="n1-brand-copy"><strong>NexusOne</strong><small>WORKSTATION CONTROL</small></span>';
  const label = document.createElement("div");
  label.className = "n1-nav-label";
  label.textContent = "Workspace";
  const nav = document.createElement("nav");
  nav.className = "n1-nav";
  for (const item of config.nav) {
    const link = document.createElement("a");
    link.href = item.href;
    if (item.active) link.setAttribute("aria-current", "page");
    const icon = document.createElement("span");
    icon.className = "n1-icon";
    icon.textContent = item.icon;
    const text = document.createElement("span");
    text.className = "n1-label";
    text.textContent = item.label;
    link.append(icon, text);
    nav.append(link);
  }
  const foot = document.createElement("div");
  foot.className = "n1-sidebar-foot";
  foot.textContent = "Local-first · Secure by design";
  aside.append(brand, label, nav, foot);
  const workspace = document.createElement("div");
  workspace.className = "n1-workspace";
  const top = document.createElement("div");
  top.className = "n1-topbar";
  const heading = document.createElement("div");
  heading.className = "n1-topbar-title";
  heading.textContent = "YOUR WORKSTATION / NEXUSONE";
  const user = document.createElement("div");
  user.className = "n1-user";
  const name = document.createElement("span");
  name.textContent = config.username;
  const avatar = document.createElement("span");
  avatar.className = "n1-avatar";
  avatar.textContent = config.initial;
  user.append(name, avatar);
  top.append(heading, user);
  const page = document.createElement("div");
  page.className = "n1-page";
  while (document.body.firstChild) page.append(document.body.firstChild);
  workspace.append(top, page);
  shell.append(aside, workspace);
  document.body.append(shell);
})();
"""


def install_ui_shell(app) -> None:
    """Wrap every NexusOne HTML page in one responsive, Matugen-aware shell."""

    @app.get("/theme/shell.css")
    def shell_stylesheet():
        return Response(_SHELL_CSS, mimetype="text/css", headers={"Cache-Control": "no-store"})

    @app.get("/theme/shell.js")
    def shell_script():
        return Response(_SHELL_JS, mimetype="application/javascript",
                        headers={"Cache-Control": "no-store"})

    @app.get("/theme/matugen.css")
    def matugen_stylesheet():
        configured = os.environ.get("NEXUSONE_MATUGEN_CSS") or app.config.get("MATUGEN_CSS_FILE")
        candidates = [Path(configured).expanduser()] if configured else [
            Path("~/.config/matugen/colors.css").expanduser(),
            Path("~/.cache/matugen/colors.css").expanduser(),
        ]
        for path in candidates:
            try:
                if path.is_file() and path.stat().st_size <= 512 * 1024:
                    return Response(path.read_text(encoding="utf-8"), mimetype="text/css",
                                    headers={"Cache-Control": "no-store"})
            except (OSError, UnicodeError):
                continue
        return Response(":root{}\n", mimetype="text/css", headers={"Cache-Control": "no-store"})

    @app.after_request
    def apply_ui_shell(response):
        if not response.content_type or "text/html" not in response.content_type.lower():
            return response
        if request.path.startswith(("/api/", "/theme/")):
            return response
        try:
            document = response.get_data(as_text=True)
        except (RuntimeError, UnicodeError):
            return response
        nonce = secrets.token_urlsafe(18)
        g.csp_nonce = nonce
        document = re.sub(
            r"<(script|style)(?=[\\s>])",
            lambda match: f'<{match.group(1)} nonce="{nonce}"',
            document,
            flags=re.IGNORECASE,
        )
        if "n1-shell-config" in document or '<meta charset="utf-8">' not in document:
            response.set_data(document)
            return response

        role = session.get("role", "viewer")
        if role == "user":
            role = "viewer"
        admin = has_capability(role, Capability.SETTINGS_MANAGE)
        current = request.path.rstrip("/") or "/"
        nav = []
        items = (
            ("/", "◫", "Overview", False),
            ("/services", "◉", "Services", False),
            ("/explorer", "▤", "File Explorer", False),
            ("/settings", "⚙", "Integrations", True),
            ("/activity", "≋", "Activity", True),
        )
        for href, icon, label, admin_only in items:
            if admin_only and not admin:
                continue
            nav.append({"href": href, "icon": icon, "label": label,
                        "active": current == href or (href != "/" and current.startswith(href + "/"))})
        username = str(session.get("username") or "User")[:40]
        config = {
            "nav": nav,
            "username": username,
            "initial": (username[:1] or "U").upper(),
        }
        base = request.script_root.rstrip("/")
        bootstrap = (
            f'<meta name="n1-shell-config" content="{html.escape(json.dumps(config), quote=True)}">'
            f'<link rel="stylesheet" href="{base}/theme/matugen.css">'
            f'<link rel="stylesheet" href="{base}/theme/shell.css">'
            f'<script defer src="{base}/theme/shell.js"></script>'
        )
        document = document.replace('<meta charset="utf-8">', '<meta charset="utf-8">' + bootstrap, 1)
        response.set_data(document)
        return response
