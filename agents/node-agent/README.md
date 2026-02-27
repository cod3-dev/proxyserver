# Node Proxy Agent (PoC)

This is a minimal Node.js proxy agent that:

- Exposes a forward HTTP proxy on `PROXY_PORT` (default 3128)
- Supports HTTPS tunneling using the `CONNECT` method
- Exposes a SOCKS5 proxy listener (default `SOCKS5_PORT=1080`, no-auth, CONNECT command)
- Serves a small admin API on port 3000 (`/health`, `/metrics`)
- Connects to a controller WebSocket to register and receive commands

Environment variables:

- `PROXY_PORT` (default 3128)
- `ADMIN_PORT` (default 3000)
- `ENABLE_SOCKS5` (`true`/`false`, default `true`)
- `SOCKS5_PORT` (default 1080)
- `SOCKS5_CONNECT_TIMEOUT_MS` (default 10000)
- `CONTROL_WS` (default ws://127.0.0.1:9100/ws)
- `AGENT_ID` (optional id)
- `REGION` (optional, e.g. `us-east`)
- `HEARTBEAT_INTERVAL_MS` (default 10000)

Heartbeat behavior:

- Agent sends a WebSocket `heartbeat` message every `HEARTBEAT_INTERVAL_MS`.
- Payload includes `port`, `socks5_port`, `region`, `uptime`, and `heartbeat_interval_ms`.

Run locally:

```cmd
cd agents\node-agent
npm install
node agent.js
```

Or build and run with Docker:

```cmd
docker build -t proxy-agent:local .
docker run --rm -p 3128:3128 -p 1080:1080 -p 3000:3000 proxy-agent:local
```
