const http = require('http');
const httpProxy = require('http-proxy');
const WebSocket = require('ws');
const express = require('express');
const net = require('net');

const PROXY_PORT = process.env.PROXY_PORT || 3128;
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3000);
const SOCKS5_PORT = Number(process.env.SOCKS5_PORT || 1080);
const ENABLE_SOCKS5 = String(process.env.ENABLE_SOCKS5 || 'true').toLowerCase() !== 'false';
const SOCKS5_CONNECT_TIMEOUT_MS = Number(process.env.SOCKS5_CONNECT_TIMEOUT_MS || 10000);
const CONTROL_WS = process.env.CONTROL_WS || 'ws://127.0.0.1:9100/ws';
const AGENT_ID = process.env.AGENT_ID || `agent-${Math.random().toString(36).slice(2,8)}`;
const REGION = process.env.REGION || 'unknown';
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS || 10000);
const RECONNECT_BASE_MS = Number(process.env.RECONNECT_BASE_MS || 1000);
const RECONNECT_MAX_MS = Number(process.env.RECONNECT_MAX_MS || 30000);
const RECONNECT_JITTER_MS = Number(process.env.RECONNECT_JITTER_MS || 500);
const SOCKS_REPLY = {
  GENERAL_FAILURE: 0x01,
  NETWORK_UNREACHABLE: 0x03,
  HOST_UNREACHABLE: 0x04,
  CONNECTION_REFUSED: 0x05,
  TTL_EXPIRED: 0x06,
  COMMAND_NOT_SUPPORTED: 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED: 0x08
};
const socksStats = {
  totalConnections: 0,
  activeTunnels: 0,
  failedConnects: 0
};

function writeSocksReply(clientSocket, rep, boundPort = 0) {
  const response = Buffer.from([
    0x05, rep, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    (boundPort >> 8) & 0xff,
    boundPort & 0xff
  ]);
  clientSocket.write(response);
}

function mapSocksErrorCode(err) {
  switch (err && err.code) {
    case 'ENETUNREACH':
      return SOCKS_REPLY.NETWORK_UNREACHABLE;
    case 'EHOSTUNREACH':
      return SOCKS_REPLY.HOST_UNREACHABLE;
    case 'ECONNREFUSED':
      return SOCKS_REPLY.CONNECTION_REFUSED;
    case 'ETIMEDOUT':
      return SOCKS_REPLY.TTL_EXPIRED;
    default:
      return SOCKS_REPLY.GENERAL_FAILURE;
  }
}

function parseSocksRequest(buffer) {
  if (buffer.length < 4) {
    return null;
  }
  if (buffer[0] !== 0x05) {
    throw new Error('invalid socks version');
  }
  if (buffer[1] !== 0x01) {
    throw Object.assign(new Error('unsupported command'), { reply: SOCKS_REPLY.COMMAND_NOT_SUPPORTED });
  }
  const atyp = buffer[3];
  let host = '';
  let offset = 4;

  if (atyp === 0x01) {
    if (buffer.length < offset + 4 + 2) {
      return null;
    }
    host = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
    offset += 4;
  } else if (atyp === 0x03) {
    if (buffer.length < offset + 1) {
      return null;
    }
    const len = buffer[offset];
    offset += 1;
    if (buffer.length < offset + len + 2) {
      return null;
    }
    host = buffer.slice(offset, offset + len).toString('utf8');
    offset += len;
  } else if (atyp === 0x04) {
    if (buffer.length < offset + 16 + 2) {
      return null;
    }
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(buffer.readUInt16BE(offset + i).toString(16));
    }
    host = parts.join(':');
    offset += 16;
  } else {
    throw Object.assign(new Error('unsupported address type'), { reply: SOCKS_REPLY.ADDRESS_TYPE_NOT_SUPPORTED });
  }

  const port = buffer.readUInt16BE(offset);
  const consumed = offset + 2;
  const extra = buffer.slice(consumed);
  return { host, port, consumed, extra };
}

function startSocks5Server() {
  if (!ENABLE_SOCKS5) {
    console.log('SOCKS5 listener is disabled');
    return null;
  }

  const socksServer = net.createServer((clientSocket) => {
    socksStats.totalConnections += 1;
    let stage = 'greeting';
    let buffered = Buffer.alloc(0);
    let upstream = null;
    let pendingExtra = Buffer.alloc(0);

    function closeAll() {
      if (upstream && !upstream.destroyed) {
        upstream.destroy();
      }
      if (!clientSocket.destroyed) {
        clientSocket.destroy();
      }
    }

    function processBuffer() {
      while (true) {
        if (stage === 'greeting') {
          if (buffered.length < 2) {
            return;
          }
          const ver = buffered[0];
          const nMethods = buffered[1];
          const needed = 2 + nMethods;
          if (buffered.length < needed) {
            return;
          }
          if (ver !== 0x05) {
            closeAll();
            return;
          }
          const methods = buffered.slice(2, needed);
          const noAuthSupported = methods.includes(0x00);
          buffered = buffered.slice(needed);
          if (!noAuthSupported) {
            clientSocket.write(Buffer.from([0x05, 0xff]));
            clientSocket.end();
            return;
          }
          clientSocket.write(Buffer.from([0x05, 0x00]));
          stage = 'request';
          continue;
        }

        if (stage === 'request') {
          let parsed;
          try {
            parsed = parseSocksRequest(buffered);
          } catch (err) {
            const reply = err.reply || SOCKS_REPLY.GENERAL_FAILURE;
            writeSocksReply(clientSocket, reply);
            clientSocket.end();
            return;
          }

          if (!parsed) {
            return;
          }

          buffered = Buffer.alloc(0);
          pendingExtra = parsed.extra;
          stage = 'connecting';

          upstream = net.createConnection({ host: parsed.host, port: parsed.port });
          upstream.setTimeout(SOCKS5_CONNECT_TIMEOUT_MS);

          upstream.once('connect', () => {
            upstream.setTimeout(0);
            socksStats.activeTunnels += 1;
            const localPort = upstream.localPort || 0;
            writeSocksReply(clientSocket, 0x00, localPort);
            stage = 'tunnel';
            if (pendingExtra.length > 0) {
              upstream.write(pendingExtra);
              pendingExtra = Buffer.alloc(0);
            }
          });

          upstream.on('data', (chunk) => {
            if (!clientSocket.destroyed) {
              clientSocket.write(chunk);
            }
          });

          upstream.on('error', (err) => {
            socksStats.failedConnects += 1;
            if (stage !== 'tunnel') {
              writeSocksReply(clientSocket, mapSocksErrorCode(err));
            }
            closeAll();
          });

          upstream.on('timeout', () => {
            socksStats.failedConnects += 1;
            if (stage !== 'tunnel') {
              writeSocksReply(clientSocket, SOCKS_REPLY.TTL_EXPIRED);
            }
            closeAll();
          });

          upstream.on('close', () => {
            if (stage === 'tunnel' && socksStats.activeTunnels > 0) {
              socksStats.activeTunnels -= 1;
            }
            if (!clientSocket.destroyed) {
              clientSocket.end();
            }
          });
          return;
        }

        return;
      }
    }

    clientSocket.on('data', (chunk) => {
      if (stage === 'tunnel') {
        if (upstream && !upstream.destroyed) {
          upstream.write(chunk);
        }
        return;
      }
      if (stage === 'connecting') {
        pendingExtra = Buffer.concat([pendingExtra, chunk]);
        return;
      }
      buffered = Buffer.concat([buffered, chunk]);
      processBuffer();
    });

    clientSocket.on('error', () => closeAll());
    clientSocket.on('end', () => {
      if (upstream && !upstream.destroyed) {
        upstream.end();
      }
    });
    clientSocket.on('close', () => {
      if (stage === 'tunnel' && socksStats.activeTunnels > 0) {
        socksStats.activeTunnels -= 1;
      }
      if (upstream && !upstream.destroyed) {
        upstream.destroy();
      }
    });
  });

  socksServer.on('error', (err) => {
    console.error('SOCKS5 listener error', err.message);
  });

  socksServer.listen(SOCKS5_PORT, () => {
    console.log(`SOCKS5 proxy listening on 0.0.0.0:${SOCKS5_PORT}`);
  });

  return socksServer;
}

// HTTP proxy server (simple forward proxy supporting CONNECT)
const proxy = httpProxy.createProxyServer({});

const server = http.createServer((req, res) => {
  // For forward proxy, target must be absolute URL for http-proxy; for simplicity, try to proxy to host header.
  const target = (req.url && req.url.startsWith('https')) ? req.url : `https://${req.headers.host}`;

  res.end = function (s) {

  };
  proxy.web(req, res, { target, changeOrigin: true }, (err) => {
    res.writeHead(502);
    res.end('Bad Gateway: ' + err.message);
  });
});

// Handle CONNECT (HTTPS tunneling)
server.on('connect', (req, clientSocket, head) => {
  const { port = 443, hostname } = new URL(`https://${req.url}`);
  const serverSocket = require('net').connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });
  serverSocket.on('error', () => {
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.end();
  });
});

server.listen(PROXY_PORT, () => console.log(`Agent proxy listening on 0.0.0.0:${PROXY_PORT}`));
startSocks5Server();

// Express admin server for metrics/health
const admin = express();
admin.get('/health', (req, res) => res.json({
  status: 'UP',
  id: AGENT_ID,
  region: REGION,
  admin_port: ADMIN_PORT,
  proxy_port: PROXY_PORT,
  socks5_enabled: ENABLE_SOCKS5,
  socks5_port: ENABLE_SOCKS5 ? SOCKS5_PORT : null
}));
admin.get('/metrics', (req, res) => res.json({
  uptime: process.uptime(),
  admin_port: ADMIN_PORT,
  socks5: {
    enabled: ENABLE_SOCKS5,
    port: ENABLE_SOCKS5 ? SOCKS5_PORT : null,
    total_connections: socksStats.totalConnections,
    active_tunnels: socksStats.activeTunnels,
    failed_connects: socksStats.failedConnects
  }
}));
admin.listen(ADMIN_PORT, () => console.log(`Admin API listening on :${ADMIN_PORT}`));

// Control WebSocket with simple reconnect logic
let ws;
let heartbeatTimer = null;
let reconnectDelayMs = RECONNECT_BASE_MS;

function resetBackoff() {
  reconnectDelayMs = RECONNECT_BASE_MS;
}

function nextReconnectDelay() {
  const jitter = Math.floor(Math.random() * RECONNECT_JITTER_MS);
  const delay = Math.min(reconnectDelayMs, RECONNECT_MAX_MS) + jitter;
  reconnectDelayMs = Math.min(reconnectDelayMs * 2, RECONNECT_MAX_MS);
  return delay;
}

function sendJson(payload) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function startHeartbeat() {
  stopHeartbeat();
  heartbeatTimer = setInterval(() => {
    sendJson({
      type: 'heartbeat',
      id: AGENT_ID,
      port: PROXY_PORT,
      socks5_port: ENABLE_SOCKS5 ? SOCKS5_PORT : null,
      region: REGION,
      uptime: Math.round(process.uptime()),
      heartbeat_interval_ms: HEARTBEAT_INTERVAL_MS
    });
  }, HEARTBEAT_INTERVAL_MS);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}
function connectControl() {
  console.log('Connecting to controller at', CONTROL_WS);
  ws = new WebSocket(CONTROL_WS + `?id=${AGENT_ID}`);

  ws.on('open', () => {
    console.log('Control connected');
    resetBackoff();
    sendJson({
      type: 'register',
      id: AGENT_ID,
      port: PROXY_PORT,
      socks5_port: ENABLE_SOCKS5 ? SOCKS5_PORT : null,
      region: REGION,
      heartbeat_interval_ms: HEARTBEAT_INTERVAL_MS
    });
    startHeartbeat();
  });

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'update-config') {
        console.log('Received config update', data.config);
      } else if (data.type === 'ping') {
        sendJson({ type: 'pong', id: AGENT_ID });
      }
    } catch (e) {
      console.error('Invalid WS message', e.message);
    }
  });

  ws.on('close', () => {
    stopHeartbeat();
    const delay = nextReconnectDelay();
    console.log(`Control disconnected, reconnecting in ${Math.round(delay / 1000)}s`);
    setTimeout(connectControl, delay);
  });

  ws.on('error', (e) => {
    console.error('Control socket error', e.message);
    ws.close();
  });
}

connectControl();
