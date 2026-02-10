import asyncio
import json
from aiohttp import web, WSMsgType

# Simple in-memory registry of agents
AGENTS = {}

async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    agent_id = request.query.get('id') or f"agent-{len(AGENTS)+1}"
    print(f"Agent connecting: {agent_id}")

    AGENTS[agent_id] = {"ws": ws, "meta": {}}

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except Exception:
                    continue

                if data.get('type') == 'register':
                    AGENTS[agent_id]['meta'] = {
                        'id': data.get('id', agent_id),
                        'port': data.get('port'),
                        'region': data.get('region', 'unknown')
                    }
                    print('Registered agent', AGENTS[agent_id]['meta'])
                    await ws.send_json({'type': 'registered', 'id': agent_id})

                elif data.get('type') == 'pong':
                    AGENTS[agent_id]['last_pong'] = asyncio.get_event_loop().time()

            elif msg.type == WSMsgType.ERROR:
                print('ws connection closed with exception', ws.exception())

    finally:
        print('Agent disconnected', agent_id)
        AGENTS.pop(agent_id, None)

    return ws

async def list_agents(request):
    out = []
    for aid, info in list(AGENTS.items()):
        meta = info.get('meta', {})
        out.append({
            'id': aid,
            'region': meta.get('region'),
            'port': meta.get('port')
        })
    return web.json_response(out)

async def start_controller():
    app = web.Application()
    app.router.add_get('/ws', ws_handler)
    app.router.add_get('/agents', list_agents)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9100)
    print('Controller listening on 0.0.0.0:9100')
    await site.start()

    # Keep running
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    try:
        asyncio.run(start_controller())
    except KeyboardInterrupt:
        print('Shutting down')
