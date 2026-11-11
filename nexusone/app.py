"""Minimal Flask app with NexusOne's shared security defaults and local APIs."""

import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, jsonify, render_template_string, request, session

from nexusone.audit import AuditLog
from nexusone.config_store import ConfigStore, ConfigurationError
from nexusone.docker_manager import control_project, project_status
from nexusone.explorer import create_explorer_blueprint
from nexusone.integration_env import write_discord_environment, write_telegram_environment
from nexusone.security.csrf import issue_csrf_token, verify_csrf_token
from nexusone.security.rate_limit import RateLimiter
from nexusone.security.rbac import Capability, has_capability
from nexusone.service_manager import control_service, list_services
from nexusone.uploads import UploadError, UploadManager
from nexusone.ui_shell import install_ui_shell

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
<label>Authorized Telegram user IDs, one per line</label><textarea id="tg_users" rows="3"></textarea><small>The updated Telegram adapter supports all listed IDs. Authorization changes take effect only after that bot version is installed and its service is restarted.</small>
<label>Chat/group IDs, one per line</label><textarea id="tg_chats" rows="2"></textarea>
<label>Credential reveal PIN <input type="password" id="tg_pin" autocomplete="new-password" placeholder="7171, if retaining the legacy reveal flow"></label><label><input type="checkbox" id="tg_clear_pin"> Clear saved PIN</label>
</section>
<section><h2>Connected services & AI</h2>
<p><small>These are the credentials and endpoints used by the existing Telegram bot. Secret values remain write-only.</small></p>
<label>System dashboard username <input id="tg_sys_user"></label>
<label>System dashboard password <input type="password" id="tg_sys_pass" autocomplete="new-password"></label><small id="tg_sys_pass_state"></small><label><input type="checkbox" id="tg_clear_sys_pass"> Clear saved password</label>
<label>Odysseus username <input id="tg_ody_user"></label>
<label>Odysseus password <input type="password" id="tg_ody_pass" autocomplete="new-password"></label><small id="tg_ody_pass_state"></small><label><input type="checkbox" id="tg_clear_ody_pass"> Clear saved password</label>
<label>Jellyfin username <input id="tg_jelly_user"></label>
<label>Jellyfin password <input type="password" id="tg_jelly_pass" autocomplete="new-password"></label><small id="tg_jelly_pass_state"></small><label><input type="checkbox" id="tg_clear_jelly_pass"> Clear saved password</label>
<label>Uptime Kuma username <input id="tg_kuma_user"></label>
<label>Uptime Kuma password <input type="password" id="tg_kuma_pass" autocomplete="new-password"></label><small id="tg_kuma_pass_state"></small><label><input type="checkbox" id="tg_clear_kuma_pass"> Clear saved password</label>
<label>Gemini API key <input type="password" id="tg_gemini_key" autocomplete="new-password"></label><small id="tg_gemini_key_state"></small><label><input type="checkbox" id="tg_clear_gemini_key"> Clear saved API key</label>
<label>System dashboard URL <input id="tg_sys_url"></label>
<label>Odysseus URL <input id="tg_ody_url"></label><label>Jellyfin URL <input id="tg_jelly_url"></label><label>Uptime Kuma URL <input id="tg_kuma_url"></label>
<label>Nexus registry path <input id="tg_registry_path"></label>
<label>Gemini base URL <input id="tg_gemini_url"></label><label>Gemini timeout (seconds) <input id="tg_gemini_timeout" type="number" min="1" max="3600"></label>
<label>Ollama base URL <input id="tg_ollama_url"></label><label>Ollama timeout (seconds) <input id="tg_ollama_timeout" type="number" min="1" max="3600"></label>
<label>Ollama memory model <input id="tg_ollama_model"></label><label>Ollama memory path <input id="tg_ollama_path"></label>
</section>
<section><h2>Discord Activity</h2>
<label><input type="checkbox" id="dc_enabled"> Enabled</label>
<label>Bot token <input type="password" id="dc_token" autocomplete="new-password" placeholder="Leave blank to keep the saved token"></label>
<small id="dc_token_state"></small><label><input type="checkbox" id="dc_clear_token"> Clear saved token</label>
<label>Discord application ID <input id="dc_app"></label>
<label>OAuth client ID <input id="dc_client"></label>
<label>Guild/server IDs, one per line</label><textarea id="dc_guilds" rows="2"></textarea>
<small>Stored for future Activity context restrictions; the current server does not enforce these IDs yet.</small>
<label>Channel IDs, one per line</label><textarea id="dc_channels" rows="2"></textarea>
<small>Stored for future Activity context restrictions; the current server does not enforce these IDs yet.</small>
<label>Client secret <input type="password" id="dc_secret" autocomplete="new-password" placeholder="Leave blank to keep current"></label>
<small id="dc_secret_state"></small><label><input type="checkbox" id="dc_clear_secret"> Clear saved client secret</label>
<label>OAuth redirect URI <input id="dc_redirect" placeholder="https://your-activity.example/…"></label>
<label>Authorized Discord user IDs, one per line</label><textarea id="dc_users" rows="3"></textarea>
<small>Multiple IDs are supported by the pending Discord adapter update (PR #7); until that version is deployed, only the first ID is active.</small>
<label>Activity origin <input id="dc_origin" placeholder="https://your-activity.example"></label>
<label>Additional allowed origins, one per line</label><textarea id="dc_origins" rows="3"></textarea>
<label>Control bridge secret <input type="password" id="dc_bridge" autocomplete="new-password" placeholder="Leave blank to keep current"></label>
<small id="dc_bridge_state"></small><label><input type="checkbox" id="dc_clear_bridge"> Clear saved bridge secret</label>
<label>Discord credential reveal PIN (6+ characters) <input type="password" id="dc_pin" autocomplete="new-password" placeholder="Separate from Telegram's 7171 PIN"></label>
<small id="dc_pin_state"></small><label><input type="checkbox" id="dc_clear_pin"> Clear saved Discord PIN</label>
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
 for(const [id,key] of [["tg_sys_user","system_dashboard_username"],["tg_ody_user","odysseus_username"],["tg_jelly_user","jellyfin_username"],["tg_kuma_user","uptime_kuma_username"],["tg_sys_url","system_dashboard_url"],["tg_ody_url","odysseus_url"],["tg_jelly_url","jellyfin_url"],["tg_kuma_url","uptime_kuma_url"],["tg_registry_path","nexus_registry_path"],["tg_gemini_url","gemini_base_url"],["tg_gemini_timeout","gemini_timeout"],["tg_ollama_url","ollama_base_url"],["tg_ollama_timeout","ollama_timeout"],["tg_ollama_model","ollama_memory_model"],["tg_ollama_path","ollama_memory_path"]]) byId(id).value=t[key]||"";
 for(const [id,key] of [["tg_sys_pass_state","system_dashboard_password"],["tg_ody_pass_state","odysseus_password"],["tg_jelly_pass_state","jellyfin_password"],["tg_kuma_pass_state","uptime_kuma_password"],["tg_gemini_key_state","gemini_api_key"]]) byId(id).textContent=t[key+"_configured"]?"Configured":"Not configured";
 byId("dc_enabled").checked=!!c.enabled; byId("dc_app").value=c.application_id||"";
 byId("dc_client").value=c.client_id||""; byId("dc_guilds").value=(c.guild_ids||[]).join("\\n");
 byId("dc_channels").value=(c.channel_ids||[]).join("\\n");
 byId("dc_redirect").value=c.redirect_uri||""; byId("dc_users").value=(c.authorized_user_ids||[]).join("\\n");
 byId("dc_origin").value=c.activity_origin||""; byId("dc_origins").value=(c.allowed_origins||"").split(",").filter(Boolean).join("\\n");
 for(const [id,key] of [["dc_token_state","bot_token"],["dc_secret_state","client_secret"],["dc_bridge_state","bridge_secret"],["dc_pin_state","links_pin"]]) byId(id).textContent=c[key+"_configured"]?"Configured":"Not configured";
}
byId("settings").addEventListener("submit",async e=>{
 e.preventDefault(); const telegram={enabled:byId("tg_enabled").checked,authorized_user_ids:lines("tg_users"),chat_ids:lines("tg_chats"),bot_token:byId("tg_clear_token").checked?null:byId("tg_token").value,links_pin:byId("tg_clear_pin").checked?null:byId("tg_pin").value};
 for(const [id,key] of [["tg_sys_user","system_dashboard_username"],["tg_ody_user","odysseus_username"],["tg_jelly_user","jellyfin_username"],["tg_kuma_user","uptime_kuma_username"],["tg_sys_url","system_dashboard_url"],["tg_ody_url","odysseus_url"],["tg_jelly_url","jellyfin_url"],["tg_kuma_url","uptime_kuma_url"],["tg_registry_path","nexus_registry_path"],["tg_gemini_url","gemini_base_url"],["tg_gemini_timeout","gemini_timeout"],["tg_ollama_url","ollama_base_url"],["tg_ollama_timeout","ollama_timeout"],["tg_ollama_model","ollama_memory_model"],["tg_ollama_path","ollama_memory_path"]]) telegram[key]=byId(id).value;
 for(const [id,key,clearId] of [["tg_sys_pass","system_dashboard_password","tg_clear_sys_pass"],["tg_ody_pass","odysseus_password","tg_clear_ody_pass"],["tg_jelly_pass","jellyfin_password","tg_clear_jelly_pass"],["tg_kuma_pass","uptime_kuma_password","tg_clear_kuma_pass"],["tg_gemini_key","gemini_api_key","tg_clear_gemini_key"]]) telegram[key]=byId(clearId).checked?null:byId(id).value;
 const payload={telegram,discord:{enabled:byId("dc_enabled").checked,authorized_user_ids:lines("dc_users"),application_id:byId("dc_app").value,client_id:byId("dc_client").value,guild_ids:lines("dc_guilds"),channel_ids:lines("dc_channels"),redirect_uri:byId("dc_redirect").value,activity_origin:byId("dc_origin").value,allowed_origins:lines("dc_origins").join(","),bot_token:byId("dc_clear_token").checked?null:byId("dc_token").value,client_secret:byId("dc_clear_secret").checked?null:byId("dc_secret").value,bridge_secret:byId("dc_clear_bridge").checked?null:byId("dc_bridge").value,links_pin:byId("dc_clear_pin").checked?null:byId("dc_pin").value}};
 const r=await api("/api/config",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
 byId("status").textContent=r.ok?((r.telegram_environment?.written&&r.discord_environment?.written)?"Saved. Telegram and Discord environment files updated; restart their services to activate changes.":"Saved, but one or more environment exports need attention."):"Save failed: "+(await r.text());
 if(r.ok){for(const id of ["tg_token","tg_pin","tg_sys_pass","tg_ody_pass","tg_jelly_pass","tg_kuma_pass","tg_gemini_key","dc_token","dc_secret","dc_bridge","dc_pin"])byId(id).value="";for(const id of ["tg_clear_token","tg_clear_pin","tg_clear_sys_pass","tg_clear_ody_pass","tg_clear_jelly_pass","tg_clear_kuma_pass","tg_clear_gemini_key","dc_clear_token","dc_clear_secret","dc_clear_bridge","dc_clear_pin"])byId(id).checked=false;await load();}
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
<nav><a href="/">Overview</a><a href="/services">Services</a><a href="/explorer">Explorer</a>{% if is_admin %}<a href="/activity">Activity</a><a href="/settings">Configuration</a>{% endif %}</nav></header>
<div class="tiles">
<a class="tile" href="/activity"><strong>🧾 Activity log</strong>Review recent configuration and privileged service actions. Secret values are never recorded.<p class="muted">Administrator only.</p></a>
<a class="tile" href="/services"><strong>🔌 Services</strong>Inspect systemd service status; administrators can control approved user services.<p class="muted">System services are read-only until polkit integration.</p></a>
<a class="tile" href="/explorer"><strong>📁 Explorer</strong>Upload files to your PC with chunked transfers and resume support.<p class="muted">Workspace: {{ explorer_root }}</p></a>
{% if is_admin %}<a class="tile" href="/settings"><strong>⚙️ Configuration</strong>Manage Telegram and Discord credentials, IDs, and authorized users. Secrets remain write-only.</a>{% endif %}
<div class="tile"><strong>🛡️ Security</strong>Authenticated sessions, role checks, CSRF protection, request limits, and audit-ready APIs.<p class="muted">Localhost-first · Port 7171</p></div>
<div class="tile"><strong>🔌 Integrations</strong>Telegram and Discord settings are scaffolded. Process reload and live connectivity checks are part of the integration phase.</div>
</div>
</html>"""




_AUDIT_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne · Activity</title>
<style>
:root{color-scheme:dark}body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}a{color:#c4b5fd;text-decoration:none}
main{overflow:auto;background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1rem;margin-top:1rem}
button{padding:.6rem .9rem;background:#374151;color:white;border:0;border-radius:7px;cursor:pointer}
table{width:100%;border-collapse:collapse;min-width:700px}td,th{text-align:left;padding:.65rem;border-bottom:1px solid #374151}
.muted{color:#9ca3af}#status{white-space:pre-wrap;color:#c4b5fd}
</style>
<header><div><h1>🧾 Activity log</h1><p class="muted">Recent privileged configuration and service actions. Secret values are never recorded.</p></div><a href="/">← NexusOne</a></header>
<button id="refresh">↻ Refresh</button><p id="status" role="status"></p>
<main><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Source</th></tr></thead><tbody id="events"></tbody></table></main>
<script>
async function load(){const status=document.getElementById("status");try{const r=await fetch("/api/audit?limit=100");if(!r.ok)throw Error((await r.text())||r.status);const data=await r.json(),body=document.getElementById("events");body.replaceChildren();for(const event of data.events){const row=document.createElement("tr");for(const key of ["created_at","actor","action","target","outcome","source_ip"]){const cell=document.createElement("td");cell.textContent=event[key]||"—";row.append(cell);}body.append(row);}status.textContent="Showing "+data.events.length+" recent events.";}catch(e){status.textContent="Activity log unavailable: "+e.message;}}
document.getElementById("refresh").onclick=load;load();
</script></html>"""


_SERVICES_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne · Services</title>
<style>
:root{color-scheme:dark}body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}a{color:#c4b5fd;text-decoration:none}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-top:1rem}
article{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1rem}
.muted{color:#9ca3af}.state{font-weight:700}.active{color:#86efac}.inactive{color:#fca5a5}
button{border:0;border-radius:7px;padding:.55rem .8rem;background:#374151;color:white;cursor:pointer;margin:.2rem}
button:disabled{opacity:.45;cursor:not-allowed}.primary{background:#7c3aed}.status{white-space:pre-wrap;color:#c4b5fd}
</style>
<header><div><h1>🔌 Services</h1><p class="muted">Allowlisted systemd services on this workstation.</p></div><nav><a href="/">← NexusOne overview</a></nav></header>
<p class="status" id="status" role="status"></p><button id="refresh">↻ Refresh status</button>
<div class="grid" id="services">Loading…</div>
<script>
const isAdmin={{ "true" if is_admin else "false" }};
let csrf="";
async function api(url,options={}){const r=await fetch(url,{...options,headers:{...(options.headers||{}),"X-CSRF-Token":csrf}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||("HTTP "+r.status));return d;}
function actionButton(service,action){const b=document.createElement("button");b.textContent=action[0].toUpperCase()+action.slice(1);b.disabled=!isAdmin||!service.controllable;b.onclick=async()=>{if((action==="stop"||action==="restart")&&!confirm(action+" "+service.name+"?"))return;b.disabled=true;try{await api("/api/services/"+encodeURIComponent(service.name)+"/"+action,{method:"POST"});await load();}catch(e){document.getElementById("status").textContent=e.message;b.disabled=false;}};return b;}
function dockerButton(action){const b=document.createElement("button");b.textContent=action==="start"?"Start stack":action[0].toUpperCase()+action.slice(1);b.className="primary";b.disabled=!isAdmin;b.onclick=async()=>{if((action==="stop"||action==="restart")&&!confirm(action+" the Odysseus stack?"))return;b.disabled=true;try{await api("/api/docker/projects/odysseus/"+action,{method:"POST"});await load();}catch(e){document.getElementById("status").textContent=e.message;b.disabled=false;}};return b;}
async function load(){try{const data=await api("/api/services");const root=document.getElementById("services");root.replaceChildren();for(const service of data.services){const card=document.createElement("article"),title=document.createElement("h2"),state=document.createElement("p"),meta=document.createElement("p"),controls=document.createElement("div");title.textContent=service.name;state.className="state "+(service.active==="active"?"active":"inactive");state.textContent="● "+service.active;meta.className="muted";meta.textContent=service.scope+" · "+service.unit+" · autostart: "+service.enabled;for(const action of ["start","stop","restart"])controls.append(actionButton(service,action));if(!service.controllable){const note=document.createElement("p");note.className="muted";note.textContent="Status only. System-level control requires a dedicated polkit helper.";card.append(title,state,meta,note,controls);}else card.append(title,state,meta,controls);root.append(card);}
 const dockerCard=document.createElement("article"),dockerTitle=document.createElement("h2"),dockerMeta=document.createElement("p"),dockerControls=document.createElement("div");dockerTitle.textContent="Odysseus · Docker Compose";dockerMeta.className="muted";try{const docker=await api("/api/docker/projects");dockerMeta.textContent=docker.project.count+" container(s) · "+docker.project.containers.map(x=>(x.Name||x.Service||"container")+": "+(x.State||x.Status||"unknown")).join(" · ");}catch(e){dockerMeta.textContent="Status unavailable: "+e.message;}for(const action of ["start","stop","restart"])dockerControls.append(dockerButton(action));dockerCard.append(dockerTitle,dockerMeta,dockerControls);root.append(dockerCard);
 document.getElementById("status").textContent="Updated."; }catch(e){document.getElementById("status").textContent=e.message;}}
async function init(){const r=await fetch("/api/security/csrf");if(!r.ok)throw Error("Authentication required");csrf=(await r.json()).token;await load();}
document.getElementById("refresh").onclick=load;init().catch(e=>document.getElementById("status").textContent=e.message);
</script></html>"""


_EXPLORER_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexusOne · Explorer</title>
<style>
:root{color-scheme:dark}body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}.muted{color:#9ca3af}
main{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1rem;margin-top:1rem}
.toolbar{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}button{padding:.6rem .85rem;border:0;border-radius:7px;background:#374151;color:white;cursor:pointer}button.primary{background:#7c3aed}button.danger{background:#b91c1c}button:disabled{opacity:.45;cursor:not-allowed}
input[type=text]{padding:.65rem;background:#111827;color:white;border:1px solid #4b5563;border-radius:6px;width:min(360px,100%)}
.crumbs{display:flex;gap:.4rem;flex-wrap:wrap;margin:.8rem 0}.crumbs button{background:#273449}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.65rem;border-bottom:1px solid #374151}td.actions{white-space:nowrap}progress{width:100%;height:1rem}.status{white-space:pre-wrap;margin:.6rem 0;color:#c4b5fd}.upload{border-top:1px solid #374151;padding:.6rem 0}
@media(max-width:650px){td.size,th.size{display:none}td,th{padding:.45rem;font-size:.9rem}button{padding:.55rem}}
</style>
<header><div><h1>📁 Explorer</h1><p class="muted">Your workspace, with large resumable uploads.</p></div><a href="/">← NexusOne</a></header>
<main>
<div class="muted" id="current-path">Loading workspace…</div>
<div class="crumbs" id="breadcrumbs"></div>
<div class="toolbar">
<button id="up">⬆ Up</button><button id="refresh">↻ Refresh</button><button id="new-folder">＋ Folder</button>
<button class="primary" id="upload">⬆ Upload files</button><input id="file-input" type="file" multiple hidden>
<button id="copy">Copy</button><button id="cut">Cut</button><button id="paste">Paste</button><button class="danger" id="delete">Delete</button>
</div>
<div class="status" id="status" role="status"></div>
<div id="upload-progress"></div>
<table><thead><tr><th></th><th>Name</th><th class="size">Size</th><th>Actions</th></tr></thead><tbody id="entries"><tr><td colspan="4">Loading…</td></tr></tbody></table>
</main>
<script>
let currentPath=".",parentPath=null,entries=[],clipboard=null,csrf="";
const byId=id=>document.getElementById(id),selected=new Set();
async function api(url,options={}){
 const response=await fetch(url,{...options,headers:{...(options.headers||{}),"X-CSRF-Token":csrf}});
 let data={};try{data=await response.json();}catch{}
 if(!response.ok){const error=new Error(data.error||("HTTP "+response.status));error.data=data;throw error;}
 return data;
}
async function init(){const response=await fetch("/api/security/csrf");if(!response.ok)throw Error("Authentication required");csrf=(await response.json()).token;await loadFiles(".");}
function setStatus(message){byId("status").textContent=message||"";}
function formatSize(size){if(size==null)return "Folder";let n=size,units=["B","KB","MB","GB","TB"],i=0;while(n>=1024&&i<units.length-1){n/=1024;i++;}return (i?n.toFixed(1):n)+" "+units[i];}
function render(){
 byId("current-path").textContent="/"+(currentPath==="."?"":currentPath);
 const crumbs=byId("breadcrumbs");crumbs.replaceChildren();let parts=currentPath==="."?[]:currentPath.split("/"),acc="";
 const home=document.createElement("button");home.textContent="Home";home.onclick=()=>loadFiles(".");crumbs.append(home);
 for(const part of parts){acc=acc?acc+"/"+part:part;const value=acc,b=document.createElement("button");b.textContent=part;b.onclick=()=>loadFiles(value);crumbs.append(b);}
 const body=byId("entries");body.replaceChildren();
 if(!entries.length){const row=document.createElement("tr"),cell=document.createElement("td");cell.colSpan=4;cell.textContent="This folder is empty.";row.append(cell);body.append(row);}
 for(const item of entries){
  const row=document.createElement("tr"),selectCell=document.createElement("td"),check=document.createElement("input");
  check.type="checkbox";check.checked=selected.has(item.path);check.onchange=()=>{check.checked?selected.add(item.path):selected.delete(item.path);};selectCell.append(check);
  const nameCell=document.createElement("td"),name=document.createElement("button");name.textContent=(item.type==="directory"?"📁 ":"📄 ")+item.name;name.onclick=()=>item.type==="directory"?loadFiles(item.path):download(item.path);nameCell.append(name);
  const size=document.createElement("td");size.className="size";size.textContent=formatSize(item.size);
  const actions=document.createElement("td");actions.className="actions";
  if(item.type==="file"){const dl=document.createElement("button");dl.textContent="Download";dl.onclick=()=>download(item.path);actions.append(dl);}
  const rename=document.createElement("button");rename.textContent="Rename";rename.onclick=()=>renameItem(item);actions.append(rename);
  row.append(selectCell,nameCell,size,actions);body.append(row);
 }
 byId("up").disabled=parentPath===null;
 byId("paste").disabled=!clipboard;
}
async function loadFiles(path=currentPath){
 try{const data=await api("/api/files?path="+encodeURIComponent(path));currentPath=data.path;parentPath=data.parent;entries=data.entries||[];clipboard=data.clipboard||null;selected.clear();render();setStatus("");}
 catch(error){setStatus("Explorer error: "+error.message);}
}
function download(path){const apiPrefix=window.location.pathname.startsWith("/nexusone/")?"/nexusone-api":"";window.location.href=apiPrefix+"/api/files/download?path="+encodeURIComponent(path);}
function selectedPaths(){return [...selected];}
async function renameItem(item){const name=prompt("Rename:",item.name);if(name===null||!name.trim())return;try{await api("/api/files/rename",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:item.path,name:name.trim()})});await loadFiles();}catch(e){setStatus("Rename failed: "+e.message);}}
byId("up").onclick=()=>{if(parentPath!==null)loadFiles(parentPath);};
byId("refresh").onclick=()=>loadFiles();
byId("new-folder").onclick=async()=>{const name=prompt("New folder name:");if(!name||!name.trim())return;try{await api("/api/files/folder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:currentPath,name:name.trim()})});await loadFiles();}catch(e){setStatus("Folder creation failed: "+e.message);}};
byId("copy").onclick=()=>setClipboard("copy");byId("cut").onclick=()=>setClipboard("cut");
async function setClipboard(mode){const paths=selectedPaths();if(!paths.length){setStatus("Select one or more items first.");return;}try{const data=await api("/api/files/clipboard",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths,mode})});clipboard=data.clipboard;render();setStatus(mode+" clipboard: "+paths.length+" item(s)");}catch(e){setStatus(e.message);}}
byId("paste").onclick=async()=>{
 try{let data;try{data=await api("/api/files/paste",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:currentPath})});}
 catch(error){if(!error.data?.conflict)throw error;const choice=prompt("Some items already exist. Type R to replace or N to rename incoming files. Cancel leaves the clipboard unchanged.","N");if(choice===null)return;const conflict=choice.trim().toLowerCase();if(!["r","replace","n","rename"].includes(conflict)){setStatus("Choose R or N.");return;}data=await api("/api/files/paste",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:currentPath,conflict:["r","replace"].includes(conflict)?"replace":"rename"})});}
 clipboard=data.clipboard||null;await loadFiles();setStatus("Pasted "+(data.count||0)+" item(s).");
 }catch(e){setStatus("Paste failed: "+e.message);}
};
byId("delete").onclick=async()=>{const paths=selectedPaths();if(!paths.length){setStatus("Select items to delete.");return;}if(!confirm("Delete "+paths.length+" selected item(s)? Folder contents are deleted too."))return;try{const data=await api("/api/files/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths})});clipboard=data.clipboard||null;await loadFiles();setStatus("Deleted "+paths.length+" item(s).");}catch(e){setStatus("Delete failed: "+e.message);}};
byId("upload").onclick=()=>byId("file-input").click();
byId("file-input").onchange=async event=>{const files=[...event.target.files];event.target.value="";for(const file of files){try{await uploadFile(file);}catch(e){setStatus(e.message==="Upload canceled"?"Upload canceled.":"Upload paused: "+e.message+" Select the same file again to resume.");break;}}await loadFiles();};
function uploadKey(file){return "nexusone-upload:"+encodeURIComponent(currentPath)+":"+encodeURIComponent(file.name)+":"+file.size+":"+file.lastModified;}
async function uploadFile(file){
 const key=uploadKey(file);let saved=null,uploadId=null,offset=0,chunkLimit=8*1024*1024;
 try{saved=JSON.parse(localStorage.getItem(key)||"null");}catch{}
 if(saved){const check=await fetch("/api/explorer/uploads/"+saved.upload_id);if(check.ok){const state=await check.json();if(state.filename===file.name&&state.size===file.size){uploadId=saved.upload_id;offset=state.offset;chunkLimit=state.chunk_limit;}}if(!uploadId)localStorage.removeItem(key);}
 if(!uploadId){const started=await api("/api/explorer/uploads",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:file.name,destination:currentPath,size:file.size})});uploadId=started.upload_id;offset=started.offset;chunkLimit=started.chunk_limit;localStorage.setItem(key,JSON.stringify({upload_id:uploadId}));}
 const wrap=document.createElement("div");wrap.className="upload";const label=document.createElement("div");label.textContent=file.name;const bar=document.createElement("progress");bar.max=100;bar.value=file.size?offset/file.size*100:100;const meta=document.createElement("small");meta.textContent=offset+" / "+file.size+" bytes";const cancel=document.createElement("button");cancel.textContent="Cancel";let cancelled=false,controller=null;cancel.onclick=async()=>{cancelled=true;if(controller)controller.abort();try{await api("/api/explorer/uploads/"+uploadId,{method:"DELETE"});}catch{}localStorage.removeItem(key);meta.textContent="Canceled";cancel.disabled=true;};wrap.append(label,bar,meta,cancel);byId("upload-progress").append(wrap);
 while(offset<file.size){if(cancelled)throw new Error("Upload canceled");const blob=file.slice(offset,Math.min(offset+chunkLimit,file.size));controller=new AbortController();const response=await api("/api/explorer/uploads/"+uploadId+"?offset="+offset,{method:"PUT",body:blob,signal:controller.signal,headers:{"Content-Type":"application/octet-stream"}});offset=response.offset;bar.value=file.size?offset/file.size*100:100;meta.textContent=offset.toLocaleString()+" / "+file.size.toLocaleString()+" bytes";}
 if(cancelled)throw new Error("Upload canceled");await api("/api/explorer/uploads/"+uploadId+"/finish",{method:"POST"});localStorage.removeItem(key);bar.value=100;meta.textContent="Complete";cancel.disabled=true;
}
init().catch(error=>setStatus(error.message));
</script></html>"""


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
function keyFor(file,dest){return "nexusone-upload:"+encodeURIComponent(dest)+":"+encodeURIComponent(file.name)+":"+file.size+":"+file.lastModified;}
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
    if (
        os.environ.get("NEXUSONE_ENV", "development").strip().lower() == "production"
        and not os.environ.get("NEXUSONE_SECRET_KEY", "").strip()
    ):
        raise RuntimeError("NEXUSONE_SECRET_KEY is required in production")

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
        ODYSSEUS_COMPOSE_FILE=os.environ.get("NEXUSONE_ODYSSEUS_COMPOSE_FILE", "~/Projects/odysseus/docker-compose.yml"),
        CONFIG_FILE=str(config_dir / "integrations.json"),
        TELEGRAM_ENV_FILE=os.environ.get("NEXUSONE_TELEGRAM_ENV_FILE", str(config_dir / "telegram.env")),
        DISCORD_ENV_FILE=os.environ.get("NEXUSONE_DISCORD_ENV_FILE", str(config_dir / "discord.env")),
        AUDIT_FILE=os.environ.get("NEXUSONE_AUDIT_FILE", "~/.local/state/nexusone/audit.sqlite3"),
        DASHBOARD_AUTH_DB=(
            supplied.get("DASHBOARD_AUTH_DB", "")
            if supplied.get("TESTING")
            else os.environ.get(
                "NEXUSONE_DASHBOARD_AUTH_DB",
                "~/.local/share/system-dashboard/dashboard-users.sqlite3",
            )
        ),
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
    app.extensions["nexusone_audit"] = AuditLog(app.config["AUDIT_FILE"])
    app.extensions["nexusone_uploads"] = UploadManager(
        app.config["EXPLORER_ROOT"], chunk_limit=int(app.config["UPLOAD_CHUNK_BYTES"]),
        max_active=int(app.config["UPLOAD_MAX_ACTIVE"]),
    )
    app.register_blueprint(create_explorer_blueprint(app.config["EXPLORER_ROOT"]))

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
        if session.get("authenticated"):
            username = str(session.get("username", "")).strip()
            auth_db = Path(app.config["DASHBOARD_AUTH_DB"]).expanduser()
            # The legacy dashboard is the identity provider during migration.
            # Re-read its role on every request so a removed account or revoked
            # administrator role cannot keep privileged access through an old cookie.
            if auth_db.is_file():
                if username.casefold() == "marwan":
                    session["role"] = "admin"
                else:
                    try:
                        with sqlite3.connect(auth_db.resolve().as_uri() + "?mode=ro", uri=True, timeout=2) as db:
                            row = db.execute(
                                "SELECT role FROM users WHERE lower(username)=lower(?)", (username,)
                            ).fetchone()
                    except sqlite3.Error:
                        app.logger.exception("Unable to validate dashboard account role")
                        return jsonify(error="Account authorization is temporarily unavailable"), 503
                    if row is None:
                        session.clear()
                        return jsonify(error="Account is no longer active"), 401
                    session["role"] = str(row[0])
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
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            response.headers["Content-Security-Policy"] = (
                app.config["CONTENT_SECURITY_POLICY"]
                + f"; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'"
            )
        else:
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

    @app.get("/activity")
    def activity_page():
        _role_required(Capability.SETTINGS_MANAGE)()
        return render_template_string(_AUDIT_PAGE)

    @app.get("/services")
    def services_page():
        _role_required(Capability.DASHBOARD_READ)()
        role = session.get("role")
        if role == "user":
            role = "viewer"
        return render_template_string(
            _SERVICES_PAGE,
            is_admin=has_capability(role, Capability.SERVICES_CONTROL),
        )

    @app.get("/explorer")
    def explorer_page():
        _role_required(Capability.EXPLORER_READ)()
        return render_template_string(_EXPLORER_PAGE)

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
        config_store = app.extensions["nexusone_config"]
        telegram_settings = config_store.runtime_integration("telegram")
        discord_settings = config_store.runtime_integration("discord")
        telegram_env = {"written": False, "restart_required": True}
        discord_env = {"written": False, "restart_required": True}
        try:
            env_result = write_telegram_environment(telegram_settings, app.config["TELEGRAM_ENV_FILE"])
            telegram_env.update(written=True, **env_result)
        except OSError:
            app.logger.exception("Telegram environment export failed")
        try:
            env_result = write_discord_environment(
                telegram_settings, discord_settings, app.config["DISCORD_ENV_FILE"]
            )
            discord_env.update(written=True, **env_result)
        except OSError:
            app.logger.exception("Discord environment export failed")
        app.extensions["nexusone_audit"].record(
            str(session.get("username", "")), "configuration.update", "telegram,discord",
            source_ip=request.remote_addr or "",
        )
        result["telegram_environment"] = telegram_env
        result["discord_environment"] = discord_env
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

    @app.get("/api/services")
    def get_services():
        _role_required(Capability.DASHBOARD_READ)()
        return jsonify(services=list_services())

    @app.get("/api/docker/projects")
    def get_docker_projects():
        _role_required(Capability.DASHBOARD_READ)()
        try:
            return jsonify(project=project_status(app.config["ODYSSEUS_COMPOSE_FILE"]))
        except RuntimeError as error:
            return jsonify(error=str(error)), 502

    @app.post("/api/docker/projects/odysseus/<action>")
    def post_docker_project_action(action):
        _role_required(Capability.CONTAINERS_CONTROL)()
        actor = str(session.get("username", ""))
        audit = app.extensions["nexusone_audit"]
        try:
            result = control_project(app.config["ODYSSEUS_COMPOSE_FILE"], action)
        except ValueError as error:
            audit.record(actor, "docker." + action, "odysseus", "invalid", request.remote_addr or "")
            return jsonify(error=str(error)), 400
        except RuntimeError as error:
            audit.record(actor, "docker." + action, "odysseus", "failed", request.remote_addr or "")
            return jsonify(error=str(error)), 502
        audit.record(actor, "docker." + action, "odysseus", source_ip=request.remote_addr or "")
        return jsonify(ok=True, **result)

    @app.post("/api/services/<name>/<action>")
    def post_service_action(name, action):
        _role_required(Capability.SERVICES_CONTROL)()
        actor = str(session.get("username", ""))
        audit = app.extensions["nexusone_audit"]
        try:
            result = control_service(name, action)
        except PermissionError as error:
            audit.record(actor, "service." + action, name, "denied", request.remote_addr or "")
            return jsonify(error=str(error)), 403
        except ValueError as error:
            audit.record(actor, "service." + action, name, "invalid", request.remote_addr or "")
            return jsonify(error=str(error)), 400
        except RuntimeError as error:
            audit.record(actor, "service." + action, name, "failed", request.remote_addr or "")
            return jsonify(error=str(error)), 502
        audit.record(actor, "service." + action, name, source_ip=request.remote_addr or "")
        return jsonify(ok=True, **result)

    @app.get("/api/audit")
    def get_audit():
        _role_required(Capability.SETTINGS_MANAGE)()
        return jsonify(events=app.extensions["nexusone_audit"].recent(
            request.args.get("limit", default=100, type=int) or 100
        ))

    install_ui_shell(app)
    return app


def main():
    app = create_app()
    host = resolve_bind_host()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        app.logger.warning("LAN binding is enabled; use HTTPS, firewall restrictions, and strong authentication.")
    app.run(host=host, port=int(os.environ.get("NEXUSONE_PORT", "7171")), debug=False)


if __name__ == "__main__":
    main()
