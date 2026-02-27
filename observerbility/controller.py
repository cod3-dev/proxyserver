import asyncio
import json
import os
import secrets
import ssl
import time
from datetime import datetime, timezone

from aiohttp import WSMsgType, web

from observerbility.alerts import AlertManager


AGENTS = {}
AGENT_CREDENTIALS = {}
ALERTS = AlertManager()

HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30
HEARTBEAT_SWEEP_INTERVAL = 5
FLAP_WINDOW = 120
FLAP_THRESHOLD = 3
DEFAULT_SCOPES = ["proxy:connect", "agent:heartbeat"]
FLAP_STATE = {}


def _now_monotonic():
    return time.monotonic()


def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_agent_record(agent_id):
    return {
        "ws": None,
        "meta": {"id": agent_id, "region": "unknown", "port": None},
        "status": "provisioned",
        "last_seen": None,
        "last_pong": None,
        "last_heartbeat": None,
    }


def _ensure_agent_stub(agent_id):
    info = AGENTS.get(agent_id)
    if info is None:
        info = _default_agent_record(agent_id)
        AGENTS[agent_id] = info
    return info


def _agent_context(agent_id, info, reason):
    meta = info.get("meta", {})
    return {
        "agent_id": agent_id,
        "region": meta.get("region"),
        "port": meta.get("port"),
        "reason": reason,
    }


def _record_flap(agent_id, info, reason):
    now = _now_monotonic()
    state = FLAP_STATE.setdefault(agent_id, {"events": [], "last_alert": 0.0})
    events = state["events"]
    events.append(now)
    cutoff = now - FLAP_WINDOW
    while events and events[0] < cutoff:
        events.pop(0)
    if len(events) >= FLAP_THRESHOLD and (now - state["last_alert"]) >= FLAP_WINDOW:
        ALERTS.raise_alert("MEDIUM", "Agent flapping", _agent_context(agent_id, info, reason))
        state["last_alert"] = now


async def _evict_agent(agent_id, info, reason):
    if info.get("evicted"):
        return
    info["evicted"] = True
    info["evict_reason"] = reason
    ALERTS.raise_alert("HIGH", "Agent evicted", _agent_context(agent_id, info, reason))
    _record_flap(agent_id, info, reason)
    ws = info.get("ws")
    if ws and not ws.closed:
        await ws.close(code=1001)
    AGENTS.pop(agent_id, None)


def _mask_secret(secret):
    if not secret:
        return None
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


def _normalize_scopes(raw):
    if raw is None:
        return list(DEFAULT_SCOPES)
    if isinstance(raw, str):
        items = [p.strip() for p in raw.split(",")]
    elif isinstance(raw, list):
        items = [str(p).strip() for p in raw]
    else:
        raise ValueError("scopes must be list or comma string")
    out = []
    seen = set()
    for item in items:
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out or list(DEFAULT_SCOPES)


def _credential_public_view(agent_id, info):
    return {
        "agent_id": agent_id,
        "status": info.get("status", "unknown"),
        "scopes": list(info.get("scopes", [])),
        "label": info.get("label"),
        "created_at": info.get("created_at"),
        "updated_at": info.get("updated_at"),
        "revoked_at": info.get("revoked_at"),
        "token_preview": _mask_secret(info.get("token")),
    }


def _provision_credential(agent_id, scopes, label=None):
    now = _now_iso()
    record = {
        "token": "agt_" + secrets.token_urlsafe(24),
        "status": "active",
        "scopes": list(scopes),
        "label": label,
        "created_at": now,
        "updated_at": now,
        "revoked_at": None,
    }
    AGENT_CREDENTIALS[agent_id] = record
    return record


def _rotate_credential(agent_id, scopes=None, label=None):
    record = AGENT_CREDENTIALS.get(agent_id)
    if not record:
        return None
    now = _now_iso()
    if scopes is not None:
        record["scopes"] = list(scopes)
    if label is not None:
        record["label"] = label
    record["token"] = "agt_" + secrets.token_urlsafe(24)
    record["status"] = "active"
    record["updated_at"] = now
    record["revoked_at"] = None
    AGENT_CREDENTIALS[agent_id] = record
    return record


def _revoke_credential(agent_id):
    record = AGENT_CREDENTIALS.get(agent_id)
    if not record:
        return None
    now = _now_iso()
    record["status"] = "revoked"
    record["token"] = None
    record["updated_at"] = now
    record["revoked_at"] = now
    AGENT_CREDENTIALS[agent_id] = record
    return record


def _parse_port(value):
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("port must be integer")
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def _apply_agent_patch(info, payload):
    if "status" in payload and payload.get("status") is not None:
        info["status"] = str(payload.get("status")).strip() or info.get("status")
    meta = info.setdefault("meta", {})
    if "region" in payload and payload.get("region") is not None:
        meta["region"] = str(payload.get("region")).strip() or "unknown"
    if "name" in payload and payload.get("name") is not None:
        meta["name"] = str(payload.get("name")).strip() or None
    if "port" in payload:
        meta["port"] = _parse_port(payload.get("port"))
    info["last_seen"] = _now_monotonic()
    return info


def _agent_view(agent_id, info, now=None):
    now = now or _now_monotonic()
    meta = info.get("meta", {})
    last_seen = info.get("last_seen")
    if last_seen is None:
        health = "unknown"
        age = None
    else:
        age = round(now - last_seen, 1)
        health = "ok" if age <= HEARTBEAT_TIMEOUT else "stale"
    cred = AGENT_CREDENTIALS.get(agent_id)
    return {
        "id": agent_id,
        "name": meta.get("name"),
        "region": meta.get("region"),
        "port": meta.get("port"),
        "status": info.get("status"),
        "health": health,
        "last_seen_seconds_ago": age,
        "credential_status": cred.get("status") if cred else "none",
        "scopes": list(cred.get("scopes", [])) if cred else [],
    }


async def _heartbeat_loop(app):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = _now_monotonic()
        for agent_id, info in list(AGENTS.items()):
            ws = info.get("ws")
            if not ws or ws.closed:
                continue
            try:
                await ws.send_json({"type": "ping", "ts": time.time()})
                info["last_ping"] = now
            except Exception:
                await _evict_agent(agent_id, info, "ping_failed")


async def _sweep_loop(app):
    while True:
        await asyncio.sleep(HEARTBEAT_SWEEP_INTERVAL)
        now = _now_monotonic()
        for agent_id, info in list(AGENTS.items()):
            last_seen = info.get("last_seen")
            if last_seen and (now - last_seen) > HEARTBEAT_TIMEOUT:
                await _evict_agent(agent_id, info, "heartbeat_timeout")


async def _start_background_tasks(app):
    app["heartbeat_task"] = asyncio.create_task(_heartbeat_loop(app))
    app["sweep_task"] = asyncio.create_task(_sweep_loop(app))


async def _cleanup_background_tasks(app):
    for name in ("heartbeat_task", "sweep_task"):
        task = app.get(name)
        if task:
            task.cancel()
    await asyncio.gather(*(t for t in (app.get("heartbeat_task"), app.get("sweep_task")) if t), return_exceptions=True)


async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    agent_id = request.query.get("id") or f"agent-{len(AGENTS) + 1}"
    existing = AGENTS.get(agent_id, {})
    AGENTS[agent_id] = {
        "ws": ws,
        "meta": existing.get("meta", {"id": agent_id, "region": "unknown", "port": None}),
        "status": "connected",
        "last_seen": _now_monotonic(),
        "last_pong": existing.get("last_pong"),
        "last_heartbeat": existing.get("last_heartbeat"),
    }
    info = AGENTS[agent_id]

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except Exception:
                    continue
                msg_type = data.get("type")
                if msg_type == "register":
                    info["meta"] = {
                        "id": data.get("id", agent_id),
                        "name": data.get("name"),
                        "port": data.get("port"),
                        "region": data.get("region", "unknown"),
                    }
                    info["status"] = "registered"
                    info["last_seen"] = _now_monotonic()
                    await ws.send_json({"type": "registered", "id": agent_id})
                elif msg_type == "heartbeat":
                    now = _now_monotonic()
                    info["last_heartbeat"] = now
                    info["last_seen"] = now
                    if data.get("port") is not None:
                        info.setdefault("meta", {})["port"] = data.get("port")
                    if data.get("region") is not None:
                        info.setdefault("meta", {})["region"] = data.get("region")
                elif msg_type == "pong":
                    now = _now_monotonic()
                    info["last_pong"] = now
                    info["last_seen"] = now
            elif msg.type == WSMsgType.ERROR:
                print("ws exception", ws.exception())
    finally:
        info = AGENTS.get(agent_id)
        if info:
            _record_flap(agent_id, info, info.get("evict_reason", "disconnect"))
            AGENTS.pop(agent_id, None)
    return ws


async def dashboard_ui(request):
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")


async def list_agents(request):
    now = _now_monotonic()
    return web.json_response([_agent_view(aid, info, now) for aid, info in sorted(AGENTS.items())])


async def register_agent(request):
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)
    agent_id = str(payload.get("id") or payload.get("name") or f"agent-{len(AGENTS) + 1}").strip()
    if not agent_id:
        return web.json_response({"error": "missing_agent_id"}, status=400)
    info = _ensure_agent_stub(agent_id)
    try:
        _apply_agent_patch(info, payload)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    info["status"] = "registered"
    AGENTS[agent_id] = info
    return web.json_response(_agent_view(agent_id, info), status=201)


async def get_agent(request):
    agent_id = request.match_info["agent_id"]
    info = AGENTS.get(agent_id)
    if not info:
        return web.json_response({"error": "not_found"}, status=404)
    return web.json_response(_agent_view(agent_id, info))


async def update_agent_status(request):
    agent_id = request.match_info["agent_id"]
    info = AGENTS.get(agent_id)
    if not info:
        return web.json_response({"error": "not_found"}, status=404)
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)
    try:
        _apply_agent_patch(info, payload)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    AGENTS[agent_id] = info
    return web.json_response(_agent_view(agent_id, info))


async def patch_agent(request):
    return await update_agent_status(request)


async def list_credentials(request):
    return web.json_response([_credential_public_view(aid, info) for aid, info in sorted(AGENT_CREDENTIALS.items())])


async def provision_credential(request):
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id:
        return web.json_response({"error": "missing_agent_id"}, status=400)
    try:
        scopes = _normalize_scopes(payload.get("scopes"))
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    label = payload.get("label")
    label = str(label).strip() if label is not None else None
    label = label or None
    _ensure_agent_stub(agent_id)
    record = _provision_credential(agent_id, scopes, label)
    return web.json_response({"agent_id": agent_id, "token": record["token"], "credential": _credential_public_view(agent_id, record)}, status=201)


async def rotate_credential(request):
    agent_id = request.match_info["agent_id"]
    if agent_id not in AGENT_CREDENTIALS:
        return web.json_response({"error": "not_found"}, status=404)
    payload = {}
    if request.can_read_body:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid_json"}, status=400)
    scopes = None
    if "scopes" in payload:
        try:
            scopes = _normalize_scopes(payload.get("scopes"))
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)
    label = payload.get("label")
    label = str(label).strip() if label is not None else None
    label = label or None
    record = _rotate_credential(agent_id, scopes=scopes, label=label)
    return web.json_response({"agent_id": agent_id, "token": record["token"], "credential": _credential_public_view(agent_id, record)})


async def revoke_credential(request):
    agent_id = request.match_info["agent_id"]
    record = _revoke_credential(agent_id)
    if not record:
        return web.json_response({"error": "not_found"}, status=404)
    return web.json_response(_credential_public_view(agent_id, record))


async def health(request):
    return web.json_response({"status": "UP", "service": "controller"})


def _resolve_tls_paths(certfile, keyfile):
    return certfile or os.environ.get("CONTROLLER_TLS_CERT"), keyfile or os.environ.get("CONTROLLER_TLS_KEY")


def _build_ssl_context(certfile, keyfile):
    if not certfile and not keyfile:
        return None
    if not certfile or not keyfile:
        raise ValueError("Both certfile and keyfile are required for TLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


async def start_controller(host="0.0.0.0", port=9100, certfile=None, keyfile=None):
    certfile, keyfile = _resolve_tls_paths(certfile, keyfile)
    ssl_context = _build_ssl_context(certfile, keyfile)
    app = web.Application()
    app.router.add_get("/", dashboard_ui)
    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/agents", list_agents)
    app.router.add_post("/agents/register", register_agent)
    app.router.add_get("/agents/{agent_id}", get_agent)
    app.router.add_put("/agents/{agent_id}/status", update_agent_status)
    app.router.add_get("/api/agents", list_agents)
    app.router.add_patch("/api/agents/{agent_id}", patch_agent)
    app.router.add_get("/api/credentials", list_credentials)
    app.router.add_post("/api/credentials", provision_credential)
    app.router.add_post("/api/credentials/{agent_id}/rotate", rotate_credential)
    app.router.add_delete("/api/credentials/{agent_id}", revoke_credential)
    app.on_startup.append(_start_background_tasks)
    app.on_cleanup.append(_cleanup_background_tasks)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
    print(f"Controller listening on {'https' if ssl_context else 'http'}://{host}:{port}")
    await site.start()
    while True:
        await asyncio.sleep(3600)


DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Control Plane</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700&family=Space+Mono:wght@400;700&display=swap');
:root{--bg:#081924;--bg2:#10344a;--card:#0f2534cc;--line:#7ec4ec3d;--text:#e5f5ff;--muted:#9fc0d3;--ok:#6ee7b7;--warn:#ffd166;--bad:#ff7b8b;--blue:#41b8ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:18px;background:radial-gradient(80rem 30rem at 15% -10%,#2ea6d055,transparent 65%),linear-gradient(150deg,var(--bg2),var(--bg));color:var(--text);font-family:"Sora","Segoe UI",sans-serif}
.wrap{max-width:1200px;margin:0 auto;display:grid;gap:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;backdrop-filter:blur(6px)}
.head{padding:16px 18px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
h1,h2{margin:0}h1{font-size:1.45rem}h2{font-size:1rem}.muted{color:var(--muted);font-size:.84rem}.mono{font-family:"Space Mono",Consolas,monospace}
.stats{display:flex;gap:8px;flex-wrap:wrap}.chip{border:1px solid var(--line);border-radius:999px;padding:6px 10px;font-size:.8rem;background:#0d2a3fbf}
.grid{display:grid;gap:14px;grid-template-columns:1.45fr 1fr}.body{padding:0 12px 12px}
.table{width:100%;border-collapse:collapse;min-width:720px}.scroll{overflow:auto;border:1px solid #7ec4ec29;border-radius:10px}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid #7ec4ec29;font-size:.85rem}th{text-transform:uppercase;font-size:.72rem;letter-spacing:.06em;color:#cae9ff;background:#0b2436}
tr:last-child td{border-bottom:none}input,select,button{border-radius:9px;border:1px solid #7ec4ec4a;padding:7px 9px;background:#071722;color:var(--text);font-size:.82rem}
button{background:#1b6db0;border-color:#59bfff7a;font-weight:700;cursor:pointer}button:hover{background:#2884d0}.warn{background:#a16b1a}.danger{background:#9d3b50}
.badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:.7rem;font-weight:700;text-transform:uppercase}.ok{background:var(--ok);color:#053021}.stale{background:var(--warn);color:#3f2a04}.unknown{background:var(--bad);color:#460b14}
form{display:grid;gap:8px;padding:12px}.two{display:grid;gap:8px;grid-template-columns:1fr 1fr}
.secret{display:none;margin:0 12px 12px;padding:10px;border:1px solid #6ee7b74d;border-radius:10px;background:#0d2a25}
.status{padding:0 12px 12px;min-height:18px;font-size:.8rem;color:#9cdfff}
@media (max-width:1000px){.grid{grid-template-columns:1fr}}@media (max-width:700px){.two{grid-template-columns:1fr}body{padding:12px}}
</style>
</head>
<body>
<div class="wrap">
  <section class="card">
    <div class="head">
      <div>
        <h1>Agent Management and Credential Provisioning</h1>
        <div class="muted">Live control plane for agent metadata and access token lifecycle.</div>
      </div>
      <div class="stats mono">
        <span class="chip">agents <strong id="stat-agents">0</strong></span>
        <span class="chip">healthy <strong id="stat-healthy">0</strong></span>
        <span class="chip">active creds <strong id="stat-creds">0</strong></span>
      </div>
    </div>
  </section>
  <section class="grid">
    <article class="card">
      <div class="head"><h2>Agents</h2><span class="muted mono" id="agents-refresh">updating...</span></div>
      <div class="body">
        <div class="scroll">
          <table class="table" id="agents-table">
            <thead><tr><th>ID</th><th>Health</th><th>Status</th><th>Region</th><th>Port</th><th>Credential</th><th>Last Seen</th><th>Action</th></tr></thead>
            <tbody id="agents-body"></tbody>
          </table>
        </div>
      </div>
    </article>
    <article style="display:grid;gap:14px">
      <section class="card">
        <div class="head"><h2>Provision Credential</h2><span class="muted">Issue token for agent id</span></div>
        <form id="provision-form">
          <input id="agent-id" placeholder="agent-us-east-1" required>
          <div class="two">
            <input id="scope-list" placeholder="proxy:connect,agent:heartbeat">
            <input id="cred-label" placeholder="label (optional)">
          </div>
          <button type="submit">Provision</button>
        </form>
        <div class="secret mono" id="secret-box"></div>
        <div class="status mono" id="status-line"></div>
      </section>
      <section class="card">
        <div class="head"><h2>Credentials</h2><span class="muted mono" id="creds-refresh">updating...</span></div>
        <div class="body">
          <div class="scroll">
            <table class="table" id="creds-table">
              <thead><tr><th>Agent</th><th>Status</th><th>Scopes</th><th>Preview</th><th>Updated</th><th>Action</th></tr></thead>
              <tbody id="creds-body"></tbody>
            </table>
          </div>
        </div>
      </section>
    </article>
  </section>
</div>
<script>
const state={agents:[],credentials:[]};const STATUSES=["registered","connected","maintenance","disabled","provisioned"];
const esc=v=>String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
const badge=v=>{const x=String(v||"unknown").toLowerCase();if(x==="ok"||x==="active")return"ok";if(x==="stale"||x==="revoked")return"stale";return"unknown";}
const tick=()=>new Date().toLocaleTimeString();
const msg=t=>{document.getElementById("status-line").textContent=`[${tick()}] ${t}`;};
async function api(path,opts={}){const c={...opts,headers:{...(opts.headers||{})}};if(c.body&&!c.headers["Content-Type"])c.headers["Content-Type"]="application/json";const r=await fetch(path,c);const t=await r.text();let d={};try{d=t?JSON.parse(t):{};}catch{d={error:t}}if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);return d;}
function renderStats(){document.getElementById("stat-agents").textContent=state.agents.length;document.getElementById("stat-healthy").textContent=state.agents.filter(a=>a.health==="ok").length;document.getElementById("stat-creds").textContent=state.credentials.filter(c=>c.status==="active").length;}
function renderAgents(){const b=document.getElementById("agents-body");if(!state.agents.length){b.innerHTML='<tr><td colspan="8" class="muted">No agents found.</td></tr>';return;}
b.innerHTML=state.agents.map(a=>`<tr data-agent="${esc(a.id)}"><td class="mono">${esc(a.id)}</td><td><span class="badge ${badge(a.health)}">${esc(a.health)}</span></td><td><select class="status">${STATUSES.map(s=>`<option ${s===a.status?"selected":""}>${esc(s)}</option>`).join("")}</select></td><td><input class="region" value="${esc(a.region||"")}"></td><td><input class="port mono" value="${esc(a.port??"")}"></td><td><span class="badge ${badge(a.credential_status)}">${esc(a.credential_status)}</span></td><td class="mono">${a.last_seen_seconds_ago==null?"-":esc(a.last_seen_seconds_ago+"s")}</td><td><button class="save">Save</button></td></tr>`).join("");}
function renderCreds(){const b=document.getElementById("creds-body");if(!state.credentials.length){b.innerHTML='<tr><td colspan="6" class="muted">No credentials issued.</td></tr>';return;}
b.innerHTML=state.credentials.map(c=>`<tr data-agent="${esc(c.agent_id)}"><td class="mono">${esc(c.agent_id)}</td><td><span class="badge ${badge(c.status)}">${esc(c.status)}</span></td><td class="mono">${esc((c.scopes||[]).join(","))}</td><td class="mono">${esc(c.token_preview||"-")}</td><td class="mono">${esc(c.updated_at||"-")}</td><td><button class="warn rotate">Rotate</button> <button class="danger revoke">Revoke</button></td></tr>`).join("");}
function showSecret(agent,token){const box=document.getElementById("secret-box");box.style.display="block";box.innerHTML=`<strong>Token for ${esc(agent)}</strong><div>${esc(token)}</div>`;}
async function refresh(){const [a,c]=await Promise.all([api("/api/agents"),api("/api/credentials")]);state.agents=Array.isArray(a)?a:[];state.credentials=Array.isArray(c)?c:[];renderStats();renderAgents();renderCreds();document.getElementById("agents-refresh").textContent=`updated ${tick()}`;document.getElementById("creds-refresh").textContent=`updated ${tick()}`;}
document.getElementById("provision-form").addEventListener("submit",async e=>{e.preventDefault();const agent=document.getElementById("agent-id").value.trim();const scopes=document.getElementById("scope-list").value.trim();const label=document.getElementById("cred-label").value.trim();if(!agent){msg("agent id required");return;}const body={agent_id:agent};if(scopes)body.scopes=scopes.split(",").map(x=>x.trim()).filter(Boolean);if(label)body.label=label;try{const r=await api("/api/credentials",{method:"POST",body:JSON.stringify(body)});showSecret(r.agent_id,r.token);msg(`credential provisioned for ${r.agent_id}`);refresh();}catch(err){msg(`error: ${err.message}`);}});
document.getElementById("agents-table").addEventListener("click",async e=>{const b=e.target.closest(".save");if(!b)return;const row=e.target.closest("tr");const agent=row.getAttribute("data-agent");const status=row.querySelector(".status").value;const region=row.querySelector(".region").value.trim()||"unknown";const portText=row.querySelector(".port").value.trim();const port=portText===""?null:Number(portText);if(portText!==""&&Number.isNaN(port)){msg(`invalid port for ${agent}`);return;}try{await api(`/api/agents/${encodeURIComponent(agent)}`,{method:"PATCH",body:JSON.stringify({status,region,port})});msg(`agent ${agent} updated`);refresh();}catch(err){msg(`error: ${err.message}`);}});
document.getElementById("creds-table").addEventListener("click",async e=>{const row=e.target.closest("tr");if(!row)return;const agent=row.getAttribute("data-agent");
if(e.target.closest(".rotate")){try{const r=await api(`/api/credentials/${encodeURIComponent(agent)}/rotate`,{method:"POST",body:"{}"});showSecret(r.agent_id,r.token);msg(`credential rotated for ${agent}`);refresh();}catch(err){msg(`error: ${err.message}`);}}
if(e.target.closest(".revoke")){if(!confirm(`Revoke credential for ${agent}?`))return;try{await api(`/api/credentials/${encodeURIComponent(agent)}`,{method:"DELETE"});msg(`credential revoked for ${agent}`);refresh();}catch(err){msg(`error: ${err.message}`);}}});
refresh().catch(err=>msg(`initial load failed: ${err.message}`));setInterval(()=>refresh().catch(err=>msg(`refresh failed: ${err.message}`)),5000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    try:
        asyncio.run(start_controller())
    except KeyboardInterrupt:
        print("Shutting down")
