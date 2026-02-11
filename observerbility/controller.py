import asyncio
import json
import os
import ssl
import time
from aiohttp import web, WSMsgType
from observerbility.alerts import AlertManager

# Simple in-memory registry of agents
AGENTS = {}
ALERTS = AlertManager()

HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30
HEARTBEAT_SWEEP_INTERVAL = 5
FLAP_WINDOW = 120
FLAP_THRESHOLD = 3

FLAP_STATE = {}

def _now():
    return time.monotonic()

def _agent_context(agent_id, info, reason):
    meta = info.get("meta", {})
    return {
        "agent_id": agent_id,
        "region": meta.get("region"),
        "port": meta.get("port"),
        "reason": reason
    }

def _record_flap(agent_id, info, reason):
    now = _now()
    state = FLAP_STATE.setdefault(agent_id, {"events": [], "last_alert": 0.0})
    events = state["events"]
    events.append(now)
    cutoff = now - FLAP_WINDOW
    while events and events[0] < cutoff:
        events.pop(0)
    if len(events) >= FLAP_THRESHOLD:
        last_alert = state["last_alert"]
        if now - last_alert >= FLAP_WINDOW:
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

async def _heartbeat_loop(app):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = _now()
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
        now = _now()
        for agent_id, info in list(AGENTS.items()):
            last_seen = info.get("last_seen", 0.0)
            if last_seen and (now - last_seen) > HEARTBEAT_TIMEOUT:
                await _evict_agent(agent_id, info, "heartbeat_timeout")

async def _start_background_tasks(app):
    app["heartbeat_task"] = asyncio.create_task(_heartbeat_loop(app))
    app["sweep_task"] = asyncio.create_task(_sweep_loop(app))

async def _cleanup_background_tasks(app):
    for task_name in ("heartbeat_task", "sweep_task"):
        task = app.get(task_name)
        if task:
            task.cancel()
    await asyncio.gather(
        *(t for t in (app.get("heartbeat_task"), app.get("sweep_task")) if t),
        return_exceptions=True
    )

async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    agent_id = request.query.get('id') or f"agent-{len(AGENTS)+1}"
    print(f"Agent connecting: {agent_id}")

    AGENTS[agent_id] = {
        "ws": ws,
        "meta": {},
        "status": "connected",
        "last_seen": _now(),
        "last_pong": None,
        "last_heartbeat": None
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
                        "port": data.get("port"),
                        "region": data.get("region", "unknown")
                    }
                    info["status"] = "registered"
                    info["last_seen"] = _now()
                    print("Registered agent", info["meta"])
                    await ws.send_json({'type': 'registered', 'id': agent_id})

                elif msg_type == "heartbeat":
                    now = _now()
                    info["last_heartbeat"] = now
                    info["last_seen"] = now
                    if data.get("port") is not None:
                        info.setdefault("meta", {})["port"] = data.get("port")
                    if data.get("region") is not None:
                        info.setdefault("meta", {})["region"] = data.get("region")

                elif msg_type == "pong":
                    now = _now()
                    info["last_pong"] = now
                    info["last_seen"] = now

            elif msg.type == WSMsgType.ERROR:
                print('ws connection closed with exception', ws.exception())

    finally:
        print("Agent disconnected", agent_id)
        info = AGENTS.get(agent_id)
        if info:
            reason = info.get("evict_reason", "disconnect")
            _record_flap(agent_id, info, reason)
            AGENTS.pop(agent_id, None)

    return ws

async def list_agents(request):
    now = _now()
    out = []
    for aid, info in list(AGENTS.items()):
        meta = info.get('meta', {})
        last_seen = info.get("last_seen")
        last_seen_age = None if last_seen is None else round(now - last_seen, 1)
        health = "unknown"
        if last_seen_age is not None:
            health = "ok" if last_seen_age <= HEARTBEAT_TIMEOUT else "stale"
        out.append({
            'id': aid,
            'region': meta.get('region'),
            'port': meta.get('port'),
            'status': info.get("status"),
            'health': health,
            'last_seen_seconds_ago': last_seen_age
        })
    return web.json_response(out)

def _resolve_tls_paths(certfile, keyfile):
    if certfile is None:
        certfile = os.environ.get("CONTROLLER_TLS_CERT")
    if keyfile is None:
        keyfile = os.environ.get("CONTROLLER_TLS_KEY")
    return certfile, keyfile


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
    app.router.add_get('/ws', ws_handler)
    app.router.add_get('/agents', list_agents)
    app.on_startup.append(_start_background_tasks)
    app.on_cleanup.append(_cleanup_background_tasks)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
    scheme = "https" if ssl_context else "http"
    ws_scheme = "wss" if ssl_context else "ws"
    print(f"Controller listening on {scheme}://{host}:{port} ({ws_scheme} for /ws)")
    await site.start()

    # Keep running
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    try:
        asyncio.run(start_controller())
    except KeyboardInterrupt:
        print('Shutting down')
