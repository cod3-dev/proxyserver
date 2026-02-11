# Project Overview - Security Proxy Server with Distributed Agent Architecture

## Executive Summary

You have built a **Security Proxy Server** with a **distributed agent architecture** that supports:
- Local HTTP/HTTPS forward proxy with security policies
- Distributed Node.js agent deployment for global proxy access
- Central Python controller for agent management
- Comprehensive security, monitoring, and observability layers

---

## 🏗️ Architecture Overview

### Option A: Central Controller + Remote Agents (Chosen)
- **Central Controller**: Python (aiohttp) on port 9100
- **Remote Agents**: Node.js HTTP proxy servers (port 3128)
- **Communication**: WebSocket between controller and agents
- **Scalability**: Deploy agents in multiple regions globally

---

## 📁 Directory Structure & Components

### 1. **Core Proxy (`core/`)**
Handles incoming client connections and request processing.

| File | Purpose | Key Classes |
|------|---------|------------|
| `listener.py` | Listens for client connections on port 8888 | `ProxyListener` |
| `connection.py` | Handles individual client connections | `ClientConnection` |
| `parser.py` | Parses HTTP requests from raw bytes | `HTTPParser`, `RequestContext` |
| `forwader.py` | Forwards traffic to target servers (HTTP & CONNECT) | `Forwarder` |
| `request.py` | Request object wrapper for tests | `ProxyRequest`, `ProxyRequests` |
| `server.py` | Main server orchestrator | - |

**What it does:**
- Receives HTTP requests on `127.0.0.1:8888`
- Parses HTTP/HTTPS traffic
- Applies security policies via `PolicyEngine`
- Forwards approved requests to target servers
- Tunnels HTTPS via `CONNECT` method

---

### 2. **Security Layer (`security/`)**
Enforces access policies and threat detection.

| File | Purpose | Key Classes |
|------|---------|------------|
| `policy_engine.py` | Central security decision maker | `PolicyEngine` |
| `decisions.py` | Security decision objects | `SecurityDecision` |
| `rate_limiter.py` | Per-IP rate limiting | `RateLimiter` |
| `reputation.py` | IP/domain reputation checks | `ReputationEngine` |
| `detector.py` | Behavioral threat detection | `ThreatDetector` |
| `rules.py` | Configurable security rules (YAML) | `SecurityRuleSet`, `RULES` |

**What it does:**
- Rate limiting (80 requests/60s per IP)
- IP reputation filtering
- Domain reputation checking
- Blocks dangerous HTTP methods (TRACE, TRACK)
- Blocks dangerous ports (22, 23, 445, 3389)
- Behavioral anomaly detection
- Returns `SecurityDecision` (action, reason, code, severity)

**Security Decisions:**
- `ALLOW` - Request approved (severity 0)
- `BLOCK` - Request denied with 403 Forbidden (severity 6-9)
- `ALERT` - Suspicious behavior logged (severity 4)

---

### 3. **Observability (`observerbility/`)**
Monitoring, logging, metrics, and dashboards.

| File | Purpose | Key Classes |
|------|---------|------------|
| `metrics.py` | Collects request metrics (counters) | `Metrics` (singleton) |
| `logger.py` | Structured JSON logging | `SecurityLogger` |
| `alerts.py` | Alert management | `AlertManager` |
| `api.py` | Admin HTTP API (port 9000) | `AdminHandler` |
| `dashboard.py` | Web dashboard UI + alerts | `DashboardHandler`, `DASHBOARD_HTML` |
| `controller.py` | Central agent controller (port 9100) | Agent registry, WebSocket handler |
| `__init__.py` | Compatibility shim for imports | - |

**Admin API Endpoints (9000):**
- `GET /health` - Service health status
- `GET /metrics` - Request metrics (counters, uptime)

**Dashboard (9100):**
- `GET /` - HTML dashboard with live metrics
- `GET /metrics` - JSON metrics
- `GET /alerts` - Recent alert history
- `GET /health` - Service health

**Controller (9100):**
- `WS /ws` - WebSocket for agent registration
- `GET /agents` - List connected agents

**Metrics Tracked:**
- `connections` - Total connections
- `blocked` - Blocked requests
- `alerts` - Suspicious requests
- `allowed` - Allowed requests
- `uptime` - Server uptime (seconds)

---

### 4. **Utilities (`utils/`)**
Helper functions for HTTP, sockets, and time operations.

| File | Purpose |
|------|---------|
| `http_utils.py` | HTTP header parsing/building |
| `socket_tools.py` | Socket utilities (tunneling, proxying) |
| `time_utils.py` | Time/rate limit helpers |

---

### 5. **Configuration (`config/`)**
Configuration files and settings.

| File | Purpose |
|------|---------|
| `rules.yaml` | Security rules (blocked IPs, domains, ports, methods) |
| `settings.yaml` | Server settings |
| `blocked.txt` | Blacklist data |

---

### 6. **Tests (`tests/`)**
Comprehensive unit and integration tests.

| File | Test Coverage |
|------|---|
| `test_policy_engine.py` | Policy engine decisions (BLOCK/ALLOW/ALERT) |
| `test_request_parser.py` | HTTP request parsing |
| `test_proxy_core.py` | Core proxy functionality |
| `test_metrics.py` | Metrics collection |
| `test_decisions.py` | SecurityDecision dataclass |
| `test_rules.py` | Rule loading and management |
| `test_admin_api.py` | Admin API endpoints |

**Run all tests:**
```cmd
python -m pytest tests/ -v
```

---

### 7. **Distributed Agent System (`agents/node-agent/`)**
Node.js agent for global proxy deployment.

| File | Purpose |
|------|---------|
| `agent.js` | HTTP forward proxy + WebSocket controller communication |
| `package.json` | Node.js dependencies (http-proxy, ws, express, axios) |
| `Dockerfile` | Container image (Node 20 Alpine) |
| `README.md` | Agent setup instructions |

**Agent Capabilities:**
- HTTP forward proxy on port 3128
- HTTPS CONNECT tunneling support
- Admin API on port 3000 (`/health`, `/metrics`)
- WebSocket registration with central controller
- Automatic reconnection on disconnect

**Environment Variables:**
- `PROXY_PORT` (default 3128)
- `CONTROL_WS` (default ws://127.0.0.1:9100/ws)
- `AGENT_ID` (default auto-generated)
- `REGION` (default "unknown")

---

### 8. **Docker & Deployment**
Containerized local testing and production deployment.

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Compose file for controller + agent |
| `docker/controller/Dockerfile` | Python controller image |
| `agents/node-agent/Dockerfile` | Node.js agent image |

**Docker Compose Services:**
- `controller` - Python aiohttp controller (port 9100)
- `node-agent` - Node.js HTTP proxy (ports 3128, 3000)

**Run with Docker Compose:**
```cmd
docker compose up --build
```

---

## 🚀 Running Your System

### Option 1: Standalone Python Proxy (Local Only)
```cmd
python proxy.py
```
or
```cmd
python main.py
```

**Services:**
- Proxy: `http://127.0.0.1:8888`
- Admin API: `http://127.0.0.1:9000`

### Option 2: Full Distributed System (Docker Compose)
```cmd
docker compose up --build
```

**Services:**
- Controller: `http://127.0.0.1:9100/agents` (REST) + `ws://127.0.0.1:9100/ws` (WebSocket)
- Node Agent Proxy: `http://127.0.0.1:3128`
- Node Agent Admin: `http://127.0.0.1:3000`

### Option 3: Controller Only (Manual)
```cmd
python observerbility/controller.py
```

### TLS (Optional)
Set environment variables to enable HTTPS:
- Admin API: `ADMIN_TLS_CERT`, `ADMIN_TLS_KEY`
- Controller: `CONTROLLER_TLS_CERT`, `CONTROLLER_TLS_KEY`

When TLS is enabled, use `https://` for controller endpoints and `wss://` for the WebSocket `/ws` route.

---

## 📊 Key Features Implemented

### ✅ Security Features
- [x] Rate limiting (80 req/60s per IP)
- [x] IP reputation filtering
- [x] Domain reputation filtering
- [x] Dangerous method blocking (TRACE, TRACK)
- [x] Dangerous port blocking (22, 23, 445, 3389)
- [x] Behavioral threat detection
- [x] Structured security logging
- [x] Alert system with history

### ✅ Core Proxy Features
- [x] HTTP forward proxy
- [x] HTTPS CONNECT tunneling
- [x] Request parsing and validation
- [x] Configurable security policies (YAML rules)
- [x] Metrics collection and tracking
- [x] Admin API for health/metrics

### ✅ Distributed Features
- [x] Central controller (Python/aiohttp)
- [x] Remote agent support (Node.js)
- [x] WebSocket agent registration
- [x] Agent health tracking
- [x] Region/geo-awareness (agents can specify region)
- [x] Automatic reconnection logic

### ✅ Observability
- [x] Structured JSON logging (security.log, alerts.log)
- [x] Real-time metrics endpoint
- [x] Web dashboard with live updates
- [x] Alert history tracking
- [x] Health check endpoints

### ✅ Testing & Code Quality
- [x] Unit tests for all major components
- [x] Test coverage: security, proxy, parsing, metrics, API
- [x] Docker Compose for integration testing
- [x] Python type hints and docstrings

---

## 📈 Data Flow

```
Client Request
    ↓
ProxyListener (port 8888)
    ↓
ClientConnection → HTTPParser
    ↓
PolicyEngine (Security Decision)
    ↓
    ├→ BLOCK → 403 Forbidden (log alert)
    ├→ ALERT → Forward + Log Alert
    └→ ALLOW → Forwarder
            ↓
         Target Server
            ↓
        Response → Client
            ↓
        Metrics Updated
```

---

## 🔧 Configuration & Customization

### Security Rules (config/rules.yaml)
```yaml
blocked_domains:
  - malicious.com
blocked_ips:
  - 192.168.1.100
blocked_ports:
  - 22
  - 3389
blocked_methods:
  - TRACE
  - TRACK
```

### Rate Limiting
Edit `security/policy_engine.py`:
```python
self.rate_limiter = RateLimiter(max_requests=80, window=60)
```

### Listen Addresses
Edit `core/listener.py`:
```python
proxy = ProxyListener(host="0.0.0.0", port=8888)
```

---

## 📝 Known Issues & Future Work

### Completed Fixes
- [x] Fixed observability package naming (observerbility typo shim)
- [x] Fixed import references in core modules
- [x] Created SecurityDecision dataclass
- [x] Fixed HTTP handler method signatures (do_GET vs do_get)
- [x] Created ProxyRequest compatibility class
- [x] Created entry points (main.py, proxy.py)

### Recommended Next Steps
1. **Add authentication** (mTLS or JWT) between controller and agents
2. **Persist agent registry** to Redis/Postgres (currently in-memory)
3. **Add agent heartbeat** monitoring and health checks
4. **Integrate policy_engine** with agents (push rules or query controller)
5. **Add TLS** for the agent admin API and dashboard (cert management)
6. **Add SOCKS5 support** for agents
7. **Add Prometheus metrics** format (Prom-compatible `/metrics`)
8. **Deploy agents** to actual regions (AWS, Azure, GCP)
9. **Add UI dashboard** (React) for agent management and credential provisioning

---

## 📦 Dependencies

### Python (requirement.txt)
```
aiohttp>=3.8.0
```

### Node.js (agents/node-agent/package.json)
```
http-proxy, ws, express, axios
```

### System Requirements
- Python 3.8+
- Node.js 20+
- Docker & Docker Compose (optional, for containerized deployment)

---

## 🎯 Summary

You have built a **production-ready PoC** of a **global distributed proxy system** with:
- ✅ Secure local proxy with comprehensive security policies
- ✅ Remote agent architecture for multi-region deployment
- ✅ Central controller for agent orchestration
- ✅ Real-time observability and monitoring
- ✅ Comprehensive testing and documentation

**Total Components:** 30+ Python/JS files, 7+ test modules, full containerization, and deployment infrastructure.

This is a solid foundation for scaling to a multi-region production system!
