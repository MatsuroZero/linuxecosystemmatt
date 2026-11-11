"""Minimal Flask app with NexusOne's shared security defaults and local APIs."""

import os
import secrets
from pathlib import Path

from flask import Flask, abort, jsonify, render_template_string, request, session

from nexusone.config_store import ConfigStore, ConfigurationError
from nexusone.security.csrf import issue_csrf_token, verify_csrf_token
from nexusone.security.rate_limit import RateLimiter
from nexusone.security.rbac import Capability, has_capability
from nexusone.uploads import UploadError, UploadManager

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CONFIG_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne Configuration</title>
<style>
body{font:16px system-ui;max-width:850px;margin:3rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
section{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1.2rem;margin:1rem 0}
label{display:block;margin:.7rem 0 .25rem}input,textarea{box-sizing:border-box;width:100%;padding:.7rem;background:#111827;color:white;border:1px solid #4b5563;border-radius:6px}
button{margin-top:1rem;padding:.7rem 1rem;border:0;border-radius:6px;background:#8b5cf6;color:white;font-weight:600}
small{color:#9ca3af}#status{white-space:pre-wrap}
</style>
<h1>NexusOne · Configuration</h1>
<p>Administrator settings. Secrets are write-only and never returned to this page.</p>
<div id="status" role="status">Loading…</div>
<form id="settings">
<section><h2>Telegram</h2>
<label><input type="checkbox" id="tg_enabled"> Enabled</label>
<label>Bot token <input type="password" id="tg_token" autocomplete="new-password" placeholder="Leave blank to keep the saved token"></label>
<small id="tg_token_state"></small><label><input type="checkbox" id="tg_clear_token"> Clear saved token</label>
<label>Authorized Telegram user IDs, one per line</label><textarea id="tg_users" rows="3"></textarea>
<label>Chat/group IDs, one per line</label><textarea id="tg_chats" rows="2"></textarea>
<label>Credential reveal PIN <input type="password" id="tg_pin" autocomplete="new-password" placeholder="Leave blank to keep current"></label><label><input type="checkbox" id="tg_clear_pin"> Clear saved PIN</label>
</section>
<section><h2>Discord</h2>
<label><input type="checkbox" id="dc_enabled"> Enabled</label>
<label>Bot token <input type="password" id="dc_token" autocomplete="new-password" placeholder="Leave blank to keep the saved token"></label>
<small id="dc_token_state"></small><label><input type="checkbox" id="dc_clear_token"> Clear saved token</label>
<label>Application ID <input id="dc_app"></label>
<label>Client ID <input id="dc_client"></label>
<label>Client secret <input type="password" id="dc_secret" autocomplete="new-password" placeholder="Leave blank to keep current"></label>
<small id="dc_secret_state"></small><label><input type="checkbox" id="dc_clear_secret"> Clear saved client secret</label>
<label>Bridge secret <input type="password" id="dc_bridge" autocomplete="new-password" placeholder="Leave blank to keep current"></label>
<small id="dc_bridge_state"></small><label><input type="checkbox" id="dc_clear_bridge"> Clear saved bridge secret</label>
<label>Guild/server IDs, one per line</label><textarea id="dc_guilds" rows="2"></textarea>
<label>Authorized Discord user IDs, one per line</label><textarea id="dc_users" rows="3"></textarea>
<label>Channel IDs, one per line</label><textarea id="dc_channels" rows="2"></textarea>
<label>Activity origin <input id="dc_origin" placeholder="https://…"></label>
</section>
<button type="submit">Save configuration</button>
</form>
<script>
let csrf="";
const byId=id=>document.getElementById(id);
const lines=id=>byId(id).value.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);
async function api(url,opts={}){return fetch(url,{...opts,headers:{...(opts.headers||{}),"X-CSRF-Token":csrf}})}
async function load(){
 const token=await fetch("/api/security/csrf"); csrf=(await token.json()).token;
 const r=await fetch("/api/config"); if(!r.ok) throw Error((await r.text())||r.status);
 const d=await r.json(),t=d.telegram||{},c=d.discord||{};
 byId("tg_enabled").checked=!!t.enabled; byId("tg_users").value=(t.authorized_user_ids||[]).join("\\n");
 byId("tg_chats").value=(t.chat_ids||[]).join("\\n"); byId("tg_token_state").textContent=t.bot_token_configured?"Token configured":"No token configured";
 byId("dc_enabled").checked=!!c.enabled; byId("dc_app").value=c.application_id||""; byId("dc_client").value=c.client_id||"";
 byId("dc_guilds").value=(c.guild_ids||[]).join("\\n"); byId("dc_users").value=(c.authorized_user_ids||[]).join("\\n");
 byId("dc_channels").value=(c.channel_ids||[]).join("\\n"); byId("dc_origin").value=c.activity_origin||"";
 for(const [id,key] of [["dc_token_state","bot_token"],["dc_secret_state","client_secret"],["dc_bridge_state","bridge_secret"]]) byId(id).textContent=c[key+"_configured"]?"Configured":"Not configured";
}
byId("settings").addEventListener("submit",async e=>{
 e.preventDefault(); const payload={telegram:{enabled:byId("tg_enabled").checked,authorized_user_ids:lines("tg_users"),chat_ids:lines("tg_chats"),bot_token:byId("tg_clear_token").checked?null:byId("tg_token").value,links_pin:byId("tg_clear_pin").checked?null:byId("tg_pin").value},
 discord:{enabled:byId("dc_enabled").checked,authorized_user_ids:lines("dc_users"),guild_ids:lines("dc_guilds"),channel_ids:lines("dc_channels"),application_id:byId("dc_app").value,client_id:byId("dc_client").value,activity_origin:byId("dc_origin").value,bot_token:byId("dc_clear_token").checked?null:byId("dc_token").value,client_secret:byId("dc_clear_secret").checked?null:byId("dc_secret").value,bridge_secret:byId("dc_clear_bridge").checked?null:byId("dc_bridge").value}};
 const r=await api("/api/config",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
 byId("status").textContent=r.ok?"Saved. Integration processes may need restarting.":("Save failed: "+(await r.text()));
 if(r.ok){for(const id of ["tg_token","tg_pin","dc_token","dc_secret","dc_bridge"])byId(id).value="";for(const id of ["tg_clear_token","tg_clear_pin","dc_clear_token","dc_clear_secret","dc_clear_bridge"])byId(id).checked=false;await load();}
});
load().catch(e=>byId("status").textContent="Configuration unavailable: "+e.message);
</script></html>"""

_HOME_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne</title>
<style>
:root{color-scheme:dark}body{font:16px system-ui;max-width:1000px;margin:3rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
nav{display:flex;gap:.6rem;flex-wrap:wrap}a{color:#c4b5fd;text-decoration:none}nav a,.tile{background:#1f2937;border:1px solid #374151;border-radius:10px;padding:.85rem 1rem}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1rem;margin-top:2rem}
.tile{display:block;min-height:130px}.tile strong{display:block;font-size:1.1rem;margin-bottom:.5rem}.muted{color:#9ca3af}
</style>
<header><div><h1>NexusOne</h1><p class="muted">Local workstation control center</p></div>
<nav><a href="/">Overview</a><a href="/explorer/uploads">Explorer</a>{% if is_admin %}<a href="/settings">Configuration</a>{% endif %}</nav></header>
<div class="tiles">
<a class="tile" href="/explorer/uploads"><strong>📁 Explorer</strong>Upload files to your PC with chunked transfers and resume support.<p class="muted">Workspace: {{ explorer_root }}</p></a>
{% if is_admin %}<a class="tile" href="/settings"><strong>⚙️ Configuration</strong>Manage Telegram and Discord credentials, IDs, and authorized users. Secrets remain write-only.</a>{% endif %}
<div class="tile"><strong>🛡️ Security</strong>Authenticated sessions, role checks, CSRF protection, request limits, and audit-ready APIs.<p class="muted">Localhost-first · Port 7171</p></div>
<div class="tile"><strong>🔌 Integrations</strong>Telegram and Discord settings are scaffolded. Process reload and live connectivity checks are part of the integration phase.</div>
</div>
</html>"""


_EXPLORER_UPLOAD_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne Explorer · Upload</title>
<style>
body{font:16px system-ui;max-width:850px;margin:3rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
main{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1.4rem}
input,button{padding:.7rem;margin:.35rem 0}input[type=text],input[type=file]{box-sizing:border-box;width:100%;background:#111827;color:white;border:1px solid #4b5563;border-radius:6px}
button{border:0;border-radius:6px;background:#8b5cf6;color:white;font-weight:600;cursor:pointer}
progress{width:100%;height:1.2rem}small{color:#9ca3af}.item{border-top:1px solid #374151;padding:.8rem 0}
</style>
<h1>NexusOne · Explorer uploads</h1>
<main>
<p>Upload files into your configured Explorer workspace. Large files are sent in streamed chunks. If the connection drops, select the same file again to resume while the server is still running.</p>
<label>Destination folder (relative to Explorer root)
<input id="destination" type="text" value="Phone" placeholder="e.g. Phone/Camera"></label>
<label>Select files
<input id="files" type="file" multiple></label>
<button id="upload">Upload selected files</button>
<div id="status" role="status"></div>
<div id="items"></div>
</main>
<script>
let csrf="",activeController=null;
const byId=id=>document.getElementById(id);
async function init(){const r=await fetch("/api/security/csrf");csrf=(await r.json()).token;}
async function call(url,options={}){return fetch(url,{...options,headers:{...(options.headers||{}),"X-CSRF-Token":csrf}});}
function keyFor(file,dest){return "nexusone-upload:"+encodeURIComponent(dest)+":"+encodeURIComponent(file.name)+":"+file.size;}
async function uploadFile(file,dest){
 const key=keyFor(file,dest);let saved=null,uploadId=null,offset=0,chunkLimit=8*1024*1024;
 try{saved=JSON.parse(localStorage.getItem(key)||"null");}catch{}
 if(saved){
  const check=await fetch("/api/explorer/uploads/"+saved.upload_id);
  if(check.ok){const state=await check.json();if(state.filename===file.name&&state.size===file.size&&saved.destination===dest){uploadId=saved.upload_id;offset=state.offset;chunkLimit=state.chunk_limit;}}
  if(!uploadId)localStorage.removeItem(key);
 }
 if(!uploadId){
  const started=await call("/api/explorer/uploads",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:file.name,destination:dest,size:file.size})});
  if(!started.ok)throw Error(await started.text());
  const state=await started.json();uploadId=state.upload_id;offset=state.offset;chunkLimit=state.chunk_limit;
  localStorage.setItem(key,JSON.stringify({upload_id:uploadId,destination:dest}));
 }
 const item=document.createElement("div");item.className="item";const title=document.createElement("div");title.textContent=file.name+" · "+file.size.toLocaleString()+" bytes";const bar=document.createElement("progress");bar.max=100;bar.value=file.size?offset/file.size*100:100;const detail=document.createElement("small");detail.textContent="Resuming at "+offset.toLocaleString()+" bytes";item.append(title,bar,detail);byId("items").append(item);
 while(offset<file.size){
  const next=Math.min(offset+chunkLimit,file.size),blob=file.slice(offset,next);
  activeController=new AbortController();
  const response=await call("/api/explorer/uploads/"+uploadId+"?offset="+offset,{method:"PUT",body:blob,signal:activeController.signal,headers:{"Content-Type":"application/octet-stream"}});
  if(!response.ok)throw Error(await response.text());
  const progress=await response.json();offset=progress.offset;bar.value=offset/file.size*100;detail.textContent=offset.toLocaleString()+" / "+file.size.toLocaleString()+" bytes";
 }
 const finished=await call("/api/explorer/uploads/"+uploadId+"/finish",{method:"POST"});
 if(!finished.ok)throw Error(await finished.text());
 localStorage.removeItem(key);bar.value=100;detail.textContent="Complete";
}
byId("upload").addEventListener("click",async()=>{
 byId("status").textContent="";byId("items").replaceChildren();
 const files=[...byId("files").files],dest=byId("destination").value.trim();
 if(!files.length){byId("status").textContent="Choose at least one file.";return;}
 byId("upload").disabled=true;
 try{await init();for(const file of files){await uploadFile(file,dest);}byId("status").textContent="All selected files uploaded successfully.";}
 catch(e){byId("status").textContent="Upload paused: "+e.message+" Select the same file again to resume.";}
 finally{byId("upload").disabled=false;activeController=null;}
});
</script></html>"""



def resolve_bind_host(environ=None) -> str:
    values = os.environ if environ is None else environ
    if values.get("NEXUSONE_ALLOW_LAN", "").strip().lower() not in {"1", "true", "yes"}:
        return "127.0.0.1"
    return values.get("NEXUSONE_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"


def _role_required(capability: Capability):
    def check():
        role = session.get("role")
        if role == "user":
            role = "viewer"
        if not has_capability(role, capability):
            abort(403, description="Insufficient permissions")
    return check


def create_app(config=None) -> Flask:
    app = Flask(__name__)
    supplied = dict(config or {})
    secret = supplied.pop("SECRET_KEY", None) or os.environ.get("NEXUSONE_SECRET_KEY")
    if not secret:
        # Reuse the legacy dashboard key so its signed Flask login session can
        # be recognized during the staged migration.
        key_path = Path(os.environ.get("NEXUSONE_SESSION_KEY_FILE", "~/.config/system-dashboard/secret_key")).expanduser()
        try:
            if key_path.is_file():
                secret = key_path.read_text(encoding="utf-8").strip() or None
                if secret:
                    os.chmod(key_path, 0o600)
        except OSError:
            secret = None
    if not secret:
        if os.environ.get("NEXUSONE_ENV", "development").lower() == "production":
            raise RuntimeError("NEXUSONE_SECRET_KEY or a readable legacy dashboard session key is required in production")
        secret = secrets.token_hex(32)

    config_dir = Path(os.environ.get("NEXUSONE_CONFIG_DIR", "~/.config/nexusone")).expanduser()
    app.config.update(
        SECRET_KEY=secret, MAX_CONTENT_LENGTH=None, MAX_REQUEST_BYTES=2 * 1024 * 1024,
        UPLOAD_CHUNK_BYTES=8 * 1024 * 1024, UPLOAD_MAX_ACTIVE=3,
        EXPLORER_ROOT=os.environ.get("NEXUSONE_EXPLORER_ROOT", "~/"),
        CONFIG_FILE=str(config_dir / "integrations.json"),
        SESSION_COOKIE_NAME="session", SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(os.environ.get("NEXUSONE_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes"}
                               if os.environ.get("NEXUSONE_COOKIE_SECURE") is not None
                               else os.environ.get("NEXUSONE_ALLOW_LAN", "").strip().lower() in {"1", "true", "yes"}),
        TRUSTED_ORIGINS=(), RATE_LIMIT=120, RATE_WINDOW_SECONDS=60,
        CONTENT_SECURITY_POLICY="default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    )
    app.config.update(supplied)
    limiter = RateLimiter(int(app.config["RATE_LIMIT"]), float(app.config["RATE_WINDOW_SECONDS"]))
    app.extensions["nexusone_config"] = ConfigStore(app.config["CONFIG_FILE"])
    app.extensions["nexusone_uploads"] = UploadManager(
        app.config["EXPLORER_ROOT"], chunk_limit=int(app.config["UPLOAD_CHUNK_BYTES"]),
        max_active=int(app.config["UPLOAD_MAX_ACTIVE"]),
    )

    @app.before_request
    def enforce_request_security():
        if not limiter.allow(request.remote_addr or "unknown"):
            abort(429, description="Too many requests")
        if request.endpoint == "upload_chunk":
            if request.content_length is not None and request.content_length > app.config["UPLOAD_CHUNK_BYTES"]:
                abort(413, description="Upload chunk is too large")
        elif request.content_length is not None and request.content_length > app.config["MAX_REQUEST_BYTES"]:
            abort(413, description="Request body is too large")
        if request.endpoint == "health":
            return
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"), 401
            return ("Authentication required. Sign in through the dashboard first.", 401)
        if request.method not in _MUTATING:
            return
        origin = request.headers.get("Origin")
        if (origin and origin.rstrip("/") != request.host_url.rstrip("/")
                and origin.rstrip("/") not in set(app.config["TRUSTED_ORIGINS"])):
            abort(403, description="Untrusted request origin")
        if not verify_csrf_token(session, request.headers.get("X-CSRF-Token")):
            abort(403, description="CSRF validation failed")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", app.config["CONTENT_SECURITY_POLICY"])
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Request body is too large"), 413

    @app.errorhandler(429)
    def rate_limited(_error):
        return jsonify(error="Too many requests"), 429

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify(error=getattr(error, "description", "Forbidden")), 403

    @app.errorhandler(ConfigurationError)
    @app.errorhandler(UploadError)
    def invalid_request(error):
        return jsonify(error=str(error)), 400

    @app.get("/api/health")
    def health():
        return jsonify(ok=True, service="nexusone")

    @app.get("/api/security/csrf")
    def csrf():
        return jsonify(token=issue_csrf_token(session))

    @app.get("/")
    def home_page():
        _role_required(Capability.DASHBOARD_READ)()
        role = session.get("role")
        if role == "user":
            role = "viewer"
        return render_template_string(
            _HOME_PAGE,
            is_admin=has_capability(role, Capability.SETTINGS_MANAGE),
            explorer_root=app.config["EXPLORER_ROOT"],
        )

    @app.get("/explorer/uploads")
    def explorer_upload_page():
        _role_required(Capability.EXPLORER_READ)()
        return render_template_string(_EXPLORER_UPLOAD_PAGE)

    @app.get("/settings")
    def settings_page():
        _role_required(Capability.SETTINGS_MANAGE)()
        return render_template_string(_CONFIG_PAGE)

    @app.get("/api/config")
    def get_config():
        _role_required(Capability.SETTINGS_MANAGE)()
        return jsonify(app.extensions["nexusone_config"].public_view())

    @app.put("/api/config")
    def put_config():
        _role_required(Capability.SETTINGS_MANAGE)()
        result = app.extensions["nexusone_config"].update(request.get_json(silent=False))
        return jsonify(result)

    @app.post("/api/explorer/uploads")
    def upload_start():
        _role_required(Capability.EXPLORER_WRITE)()
        data = request.get_json(silent=False) or {}
        result = app.extensions["nexusone_uploads"].start(
            data.get("filename"), data.get("destination", ""), data.get("size"),
            owner=str(session.get("username", "")),
        )
        return jsonify(result), 201

    @app.get("/api/explorer/uploads/<upload_id>")
    def upload_status(upload_id):
        _role_required(Capability.EXPLORER_READ)()
        return jsonify(app.extensions["nexusone_uploads"].status(
            upload_id, owner=str(session.get("username", ""))
        ))

    @app.put("/api/explorer/uploads/<upload_id>")
    def upload_chunk(upload_id):
        _role_required(Capability.EXPLORER_WRITE)()
        offset = request.args.get("offset", type=int)
        if offset is None:
            abort(400, description="An upload offset is required")
        result = app.extensions["nexusone_uploads"].append(
            upload_id, offset, request.stream, owner=str(session.get("username", ""))
        )
        return jsonify(result)

    @app.post("/api/explorer/uploads/<upload_id>/finish")
    def upload_finish(upload_id):
        _role_required(Capability.EXPLORER_WRITE)()
        return jsonify(app.extensions["nexusone_uploads"].finish(
            upload_id, owner=str(session.get("username", ""))
        ))

    @app.delete("/api/explorer/uploads/<upload_id>")
    def upload_cancel(upload_id):
        _role_required(Capability.EXPLORER_WRITE)()
        app.extensions["nexusone_uploads"].cancel(
            upload_id, owner=str(session.get("username", ""))
        )
        return jsonify(ok=True)

    return app


def main():
    app = create_app()
    host = resolve_bind_host()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        app.logger.warning("LAN binding is enabled; use HTTPS, firewall restrictions, and strong authentication.")
    app.run(host=host, port=int(os.environ.get("NEXUSONE_PORT", "7171")), debug=False)


if __name__ == "__main__":
    main()
