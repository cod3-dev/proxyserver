# Node Proxy Agent (PoC)

This is a minimal Node.js proxy agent that:

- Exposes a forward HTTP proxy on `PROXY_PORT` (default 3128)
- Supports HTTPS tunneling using the `CONNECT` method
- Serves a small admin API on port 3000 (`/health`, `/metrics`)
- Connects to a controller WebSocket to register and receive commands

Environment variables:

- `PROXY_PORT` (default 3128)
- `CONTROL_WS` (default ws://127.0.0.1:9100/ws)
- `AGENT_ID` (optional id)
- `REGION` (optional, e.g. `us-east`)

Run locally:

```cmd
cd agents\node-agent
npm install
node agent.js
```

Or build and run with Docker:

```cmd
docker build -t proxy-agent:local .
docker run --rm -p 3128:3128 -p 3000:3000 proxy-agent:local
```
