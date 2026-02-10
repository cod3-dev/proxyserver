const http = require('http');
const httpProxy = require('http-proxy');
const WebSocket = require('ws');
const express = require('express');
const axios = require('axios');

const PROXY_PORT = process.env.PROXY_PORT || 3128;
const CONTROL_WS = process.env.CONTROL_WS || 'ws://127.0.0.1:9100/ws';
const AGENT_ID = process.env.AGENT_ID || `agent-${Math.random().toString(36).slice(2,8)}`;
const REGION = process.env.REGION || 'unknown';

// HTTP proxy server (simple forward proxy supporting CONNECT)
const proxy = httpProxy.createProxyServer({});

const server = http.createServer((req, res) => {
  // For forward proxy, target must be absolute URL for http-proxy; for simplicity, try to proxy to host header.
  const target = (req.url && req.url.startsWith('http')) ? req.url : `http://${req.headers.host}`;

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
  serverSocket.on('error', (err) => {
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.end();
  });
});

server.listen(PROXY_PORT, () => console.log(`Agent proxy listening on 0.0.0.0:${PROXY_PORT}`));

// Express admin server for metrics/health
const admin = express();
admin.get('/health', (req, res) => res.json({ status: 'UP', id: AGENT_ID, region: REGION }));
admin.get('/metrics', (req, res) => res.json({ uptime: process.uptime() }));
admin.listen(3000, () => console.log('Admin API listening on :3000'));

// Control WebSocket with simple reconnect logic
let ws;
function connectControl() {
  console.log('Connecting to controller at', CONTROL_WS);
  ws = new WebSocket(CONTROL_WS + `?id=${AGENT_ID}`);

  ws.on('open', () => {
    console.log('Control connected');
    ws.send(JSON.stringify({ type: 'register', id: AGENT_ID, port: PROXY_PORT, region: REGION }));
  });

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'update-config') {
        console.log('Received config update', data.config);
      } else if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', id: AGENT_ID }));
      }
    } catch (e) {
      console.error('Invalid WS message', e.message);
    }
  });

  ws.on('close', () => {
    console.log('Control disconnected, reconnecting in 3s');
    setTimeout(connectControl, 3000);
  });

  ws.on('error', (e) => {
    console.error('Control socket error', e.message);
    ws.close();
  });
}

connectControl();
