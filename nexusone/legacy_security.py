"""Security boundary for legacy System Dashboard routes during NexusOne migration.

This adapter is installed after the legacy app's own login hook. It refreshes
account roles, requires same-origin CSRF protection for unsafe requests, and
keeps machine-control endpoints administrator-only while leaving Explorer and
ordinary dashboard reads available to authenticated users.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, request, session

from nexusone.security.csrf import issue_csrf_token, verify_csrf_token

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ADMIN_ONLY_EXACT = frozenset({
    "/api/terminal",
    "/api/auth/terminal",
    "/api/power",
    "/api/wifi",
    "/api/wifi/connect",
    "/api/wifi/disconnect",
    "/api/package/action",
    "/api/desktop-app",
    "/api/app",
    "/api/scrcpy",
    "/api/hypr/workspaces/switch",
    "/api/process/kill",
    "/api/serpantinum/reload",
    "/api/serpantinum/action",
    "/api/wallpaper/apply",
    "/api/agent/run",
    "/api/agent/approve",
    "/api/screen/stream",
    "/api/screen/live",
    "/api/screen/capture",
    "/api/screen/screenshots",
    "/api/admin/users",
    "/api/admin/restart",
    "/api/audit/log",
})
_ADMIN_ONLY_BY_METHOD = {
    "/api/serpantinum/settings": frozenset({"PUT"}),
    "/api/power-profile": frozenset({"POST"}),
    "/api/keep-awake": frozenset({"POST"}),
    "/api/bluetooth": frozenset({"POST"}),
    "/api/airplane": frozenset({"POST"}),
    "/api/eye-protection": frozenset({"POST"}),
    "/api/equalizer": frozenset({"POST"}),
    "/api/ollama/server": frozenset({"POST"}),
    "/api/sharing/server-name": frozenset({"POST"}),
    "/api/sharing/channels": frozenset({"POST"}),
}
_ADMIN_ONLY_PREFIXES = (
    "/api/mouse/",
    "/api/keyboard/",
    "/api/screen/files/",
    "/api/admin/users/",
    "/api/sharing/channels/",
)
_ADMIN_ONLY_METHOD_PREFIXES = (
    ("/api/sharing/messages/", frozenset({"DELETE"})),
)


def _origin_matches(value: str, *, scheme: str, host: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme == scheme
        and parsed.netloc == host
        and parsed.username is None
        and parsed.password is None
    )


def _trusted_request_origin(trusted_origins: set[str]) -> bool:
    origin = request.headers.get("Origin")
    if origin:
        if origin.rstrip("/") in trusted_origins:
            return True
        return _origin_matches(origin, scheme=request.scheme, host=request.host)

    referer = request.headers.get("Referer")
    if referer:
        try:
            parsed = urlsplit(referer)
        except ValueError:
            return False
        origin_from_referer = f"{parsed.scheme}://{parsed.netloc}"
        if origin_from_referer.rstrip("/") in trusted_origins:
            return True
        return _origin_matches(
            origin_from_referer, scheme=request.scheme, host=request.host
        )
    return False


def _requires_admin(path: str, method: str) -> bool:
    if path in _ADMIN_ONLY_EXACT:
        return True
    if method in _ADMIN_ONLY_BY_METHOD.get(path, frozenset()):
        return True
    if any(path.startswith(prefix) for prefix in _ADMIN_ONLY_PREFIXES):
        return True
    return any(
        path.startswith(prefix) and method in methods
        for prefix, methods in _ADMIN_ONLY_METHOD_PREFIXES
    )


def _refresh_legacy_role(auth_db: Path) -> str | None:
    username = str(session.get("username", "")).strip()
    if not username:
        return None
    if username.casefold() == "marwan":
        session["role"] = "admin"
        return "admin"

    if auth_db.is_file():
        try:
            uri = auth_db.resolve().as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as db:
                row = db.execute(
                    "SELECT role FROM users WHERE lower(username)=lower(?)",
                    (username,),
                ).fetchone()
        except sqlite3.Error:
            abort(503, description="Account authorization is temporarily unavailable")
        if row is None:
            session.clear()
            abort(401, description="Account is no longer active")
        session["role"] = str(row[0])
    role = session.get("role")
    return role if isinstance(role, str) else None


def install_legacy_security(
    legacy_app: Flask,
    *,
    auth_db_path: str | Path,
    trusted_origins: tuple[str, ...] | list[str] = (),
) -> None:
    """Install migration-time policy on the legacy Flask app exactly once."""
    if legacy_app.extensions.get("nexusone_legacy_security"):
        return

    auth_db = Path(auth_db_path).expanduser()
    trusted = {str(item).rstrip("/") for item in trusted_origins if str(item).strip()}

    @legacy_app.before_request
    def nexusone_legacy_request_policy():
        if request.endpoint in {"login"} or request.path.startswith("/static/"):
            return

        # The existing dashboard's login hook runs before this hook. Re-check
        # the live account role so stale cookies cannot retain admin controls.
        if not session.get("authenticated"):
            return

        role = _refresh_legacy_role(auth_db)
        username = str(session.get("username", "")).strip()
        is_admin = username.casefold() == "marwan" and role == "admin"

        if _requires_admin(request.path, request.method) and not is_admin:
            abort(403, description="Administrator access required")

        if request.method not in _SAFE_METHODS:
            if not _trusted_request_origin(trusted):
                abort(403, description="Untrusted request origin")
            supplied = request.headers.get("X-CSRF-Token")
            if not verify_csrf_token(session, supplied):
                abort(403, description="CSRF validation failed")
        else:
            issue_csrf_token(session)

    @legacy_app.after_request
    def nexusone_legacy_csrf_bootstrap(response):
        if (
            response.mimetype != "text/html"
            or response.status_code >= 400
            or not session.get("authenticated")
        ):
            return response

        token = issue_csrf_token(session)
        is_admin = (
            str(session.get("username", "")).casefold() == "marwan"
            and session.get("role") == "admin"
        )
        admin_flag = "true" if is_admin else "false"
        bootstrap = (
            '<meta name="nexusone-csrf-token" content="' + token + '">'
            '<meta name="nexusone-admin" content="' + admin_flag + '">'
            '<script>(function(){'
            'const token=document.querySelector("meta[name=nexusone-csrf-token]")?.content;'
            'if(!token)return;'
            'const nativeFetch=window.fetch.bind(window);'
            'window.fetch=function(input,init={}){'
            'const req=input instanceof Request?input:null;'
            'const method=String(init.method||(req&&req.method)||"GET").toUpperCase();'
            'const raw=req?req.url:String(input);'
            'let url;try{url=new URL(raw,window.location.href)}catch(e){return nativeFetch(input,init)}'
            'if(url.origin===window.location.origin&&!["GET","HEAD","OPTIONS"].includes(method)){'
            'const headers=new Headers(req?req.headers:undefined);'
            'new Headers(init.headers||{}).forEach((v,k)=>headers.set(k,v));'
            'headers.set("X-CSRF-Token",token);'
            'init={...init,headers};'
            '}return nativeFetch(input,init);'
            '};'
            'const xhrOpen=XMLHttpRequest.prototype.open;'
            'XMLHttpRequest.prototype.open=function(method,url){'
            'this.__nexusMethod=String(method||"GET").toUpperCase();'
            'try{this.__nexusUrl=new URL(url,window.location.href)}catch(e){this.__nexusUrl=null}'
            'return xhrOpen.apply(this,arguments);'
            '};'
            'const xhrSend=XMLHttpRequest.prototype.send;'
            'XMLHttpRequest.prototype.send=function(body){'
            'if(this.__nexusUrl&&this.__nexusUrl.origin===window.location.origin&&'
            '!["GET","HEAD","OPTIONS"].includes(this.__nexusMethod)){'
            'this.setRequestHeader("X-CSRF-Token",token)}'
            'return xhrSend.call(this,body);'
            '};'
            'document.addEventListener("submit",function(event){'
            'const form=event.target;if(!(form instanceof HTMLFormElement))return;'
            'let target;try{target=new URL(form.action,window.location.href)}catch(e){return}'
            'if(target.origin!==window.location.origin||target.pathname!=="/logout")return;'
            'event.preventDefault();'
            'window.fetch(form.action,{method:"POST",credentials:"same-origin"})'
            '.then(()=>window.location.assign("/login"));'
            '},true);'
            'const addNexusLink=(id,href,label,title)=>{'
            'const right=document.querySelector(".task-right");'
            'if(!right||document.getElementById(id))return;'
            'const link=document.createElement("a");link.id=id;link.href=href;'
            'link.className="task-btn";link.textContent=label;link.title=title;'
            'link.setAttribute("aria-label",title);link.style.textDecoration="none";'
            'link.style.display="inline-grid";link.style.placeItems="center";link.style.color="inherit";'
            'const power=document.getElementById("top-power");'
            'if(power)right.insertBefore(link,power);else right.append(link);'
            '};'
            'const injectNexusLinks=()=>{'
            'addNexusLink("nexusone-explorer-link","/nexusone/explorer","📁","File Explorer");'
            'const admin=document.querySelector("meta[name=nexusone-admin]")?.content==="true";'
            'if(admin)addNexusLink("nexusone-settings-link","/nexusone/settings","⚙️","Integration Configuration");'
            'const layout=document.querySelector(".dashboard-layout");'
            'const main=document.getElementById("dashboard-main");'
            'if(!layout||!main)return;'
            'let nav=layout.querySelector(".tabs");'
            'if(!nav){nav=document.createElement("nav");nav.className="tabs";'
            'nav.setAttribute("aria-label","Dashboard sections");layout.insertBefore(nav,main);}'
            'const addFrame=(id,src,title)=>{'
            'if(document.getElementById(id))return;'
            'const section=document.createElement("section");section.id=id;section.className="tab-content";'
            'const frame=document.createElement("iframe");frame.src=src;frame.title=title;'
            'frame.loading="lazy";frame.referrerPolicy="same-origin";'
            'frame.style.cssText="display:block;width:100%;height:calc(100dvh - 145px);min-height:520px;border:0;border-radius:16px;background:#111827";'
            'section.append(frame);main.append(section);'
            '};'
            'addFrame("nexusone-explorer","/nexusone/explorer","NexusOne File Explorer");'
            'if(admin)addFrame("nexusone-settings","/nexusone/settings","Telegram and Discord Configuration");'
            'const entries=['
            '["stats","📊 Overview"],["apps","🚀 Applications"],["packages","📦 Packages"],'
            '["processes","⚙️ Processes"],["wallpapers","🖼️ Wallpapers"],["files","📂 Files"],'
            '["terminal","⌨️ Terminal"],["serpantinum","🎨 Serpantinum"],'
            '["screen-viewer","🖥️ Screen"],["sharing","💬 Community Hub"],["network","🌐 Network"],'
            '["nexusone-explorer","📁 File Transfer"]'
            '];'
            'if(admin)entries.push(["nexusone-settings","⚙️ Integrations"]);'
            'for(const [id,label] of entries){'
            'if(nav.querySelector("[data-tab=\\\""+id+"\\\"]"))continue;'
            'const button=document.createElement("button");button.type="button";'
            'button.className="tab-btn";button.dataset.tab=id;button.textContent=label;'
            'button.setAttribute("aria-controls",id);nav.append(button);'
            '}'
            'nav.addEventListener("click",event=>{'
            'const button=event.target.closest(".tab-btn");if(!button||!nav.contains(button))return;'
            'const id=button.dataset.tab,target=document.getElementById(id);if(!target)return;'
            'document.querySelectorAll(".tab-content").forEach(item=>item.classList.remove("active"));'
            'document.querySelectorAll(".tab-btn").forEach(item=>item.classList.remove("active"));'
            'target.classList.add("active");button.classList.add("active");'
            'if(id==="stats"&&typeof updateStats==="function")updateStats();'
            'if(id==="processes"&&typeof updateProcesses==="function")updateProcesses();'
            'if(id==="network"){if(typeof updateNetwork==="function")updateNetwork();'
            'if(typeof updateWifiNetworks==="function")updateWifiNetworks(true);'
            'if(typeof updateBluetooth==="function")updateBluetooth();}'
            'if(id==="screen-viewer"&&typeof updateScreenWorkspaces==="function")updateScreenWorkspaces();'
            'if(id==="serpantinum"&&typeof syncSerpQuickStates==="function")syncSerpQuickStates();'
            'if(id==="files"&&typeof loadFiles==="function")loadFiles();'
            'if(id==="sharing"&&typeof sharingEnsureInitialized==="function")sharingEnsureInitialized();'
            '},true);'
            'const active=main.querySelector(".tab-content.active")?.id||"sharing";'
            'nav.querySelectorAll(".tab-btn").forEach(button=>button.classList.toggle("active",button.dataset.tab===active));'
            '};'
            'if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",injectNexusLinks,{once:true});'
            'else injectNexusLinks();'
            '})();</script>'
        )
        html = response.get_data(as_text=True)
        if 'name="nexusone-csrf-token"' not in html:
            if "</head>" in html:
                html = html.replace("</head>", bootstrap + "</head>", 1)
            elif "<body" in html:
                index = html.find(">", html.find("<body"))
                if index >= 0:
                    html = html[: index + 1] + bootstrap + html[index + 1 :]
                else:
                    html += bootstrap
            else:
                html = bootstrap + html
            response.set_data(html)
        return response

    legacy_app.extensions["nexusone_legacy_security"] = {
        "auth_db_path": str(auth_db),
        "admin_only_routes": len(_ADMIN_ONLY_EXACT),
    }
