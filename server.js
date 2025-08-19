const Gun = require('gun');
const express = require('express');
const cors = require('cors');
const os = require('os');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8765;
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 100;

// Statistics tracking
const stats = {
  startTime: Date.now(),
  totalConnections: 0,
  activeConnections: 0,
  peakConnections: 0,
  totalMessages: 0,
  totalBytes: 0,
  errors: [],
  connectionHistory: [],
  messageRate: [],
  bandwidthUsage: [],
  peerMap: new Map(),
  rateLimitMap: new Map()
};

// Error tracking
class ErrorTracker {
  constructor(maxErrors = 100) {
    this.maxErrors = maxErrors;
  }

  track(error, context = '') {
    const errorEntry = {
      timestamp: new Date().toISOString(),
      message: error.message || error,
      stack: error.stack,
      context
    };
    
    stats.errors.unshift(errorEntry);
    if (stats.errors.length > this.maxErrors) {
      stats.errors.pop();
    }
    
    console.error(`❌ Error: ${context} - ${error.message || error}`);
  }
}

const errorTracker = new ErrorTracker();

// Rate limiting
function checkRateLimit(ip) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  if (!stats.rateLimitMap.has(ip)) {
    stats.rateLimitMap.set(ip, []);
  }
  
  const requests = stats.rateLimitMap.get(ip);
  const recentRequests = requests.filter(time => time > windowStart);
  
  stats.rateLimitMap.set(ip, recentRequests);
  
  if (recentRequests.length >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }
  
  recentRequests.push(now);
  return true;
}

// Middleware
app.use(cors());
app.use(express.json());

// Serve Gun
app.use(Gun.serve);

// Enhanced dashboard
app.get('/', (req, res) => {
  const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = uptime % 60;
  
  const memUsage = process.memoryUsage();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  
  const recentErrors = stats.errors.slice(0, 5);
  const recentConnections = stats.connectionHistory.slice(-10).reverse();
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gun Relay Server Dashboard</title>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: #fff;
          min-height: 100vh;
          padding: 20px;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
        }
        h1 {
          font-size: 2.5em;
          margin-bottom: 20px;
          text-align: center;
          text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
          margin-bottom: 30px;
        }
        .card {
          background: rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(10px);
          border-radius: 15px;
          padding: 20px;
          border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .card h2 {
          font-size: 1.2em;
          margin-bottom: 15px;
          opacity: 0.9;
        }
        .stat {
          display: flex;
          justify-content: space-between;
          padding: 8px 0;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .stat:last-child {
          border-bottom: none;
        }
        .stat-value {
          font-weight: bold;
          font-size: 1.1em;
        }
        .status-active {
          color: #4ade80;
          text-shadow: 0 0 10px rgba(74, 222, 128, 0.5);
        }
        .status-warning {
          color: #fbbf24;
        }
        .status-error {
          color: #f87171;
        }
        .connection-string {
          background: rgba(0, 0, 0, 0.3);
          padding: 15px;
          border-radius: 10px;
          margin: 20px 0;
          word-break: break-all;
        }
        .connection-string code {
          display: block;
          margin-top: 10px;
          padding: 10px;
          background: rgba(0, 0, 0, 0.3);
          border-radius: 5px;
          font-size: 0.9em;
        }
        .error-list {
          max-height: 200px;
          overflow-y: auto;
        }
        .error-item {
          background: rgba(248, 113, 113, 0.1);
          padding: 10px;
          margin: 5px 0;
          border-radius: 5px;
          font-size: 0.9em;
        }
        .peer-item {
          background: rgba(74, 222, 128, 0.1);
          padding: 8px;
          margin: 5px 0;
          border-radius: 5px;
          font-size: 0.9em;
        }
        .refresh-btn {
          position: fixed;
          bottom: 30px;
          right: 30px;
          background: rgba(255, 255, 255, 0.2);
          border: 2px solid rgba(255, 255, 255, 0.3);
          color: white;
          padding: 15px 30px;
          border-radius: 50px;
          cursor: pointer;
          font-size: 1em;
          transition: all 0.3s;
        }
        .refresh-btn:hover {
          background: rgba(255, 255, 255, 0.3);
          transform: scale(1.05);
        }
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.5; }
          100% { opacity: 1; }
        }
        .live-indicator {
          display: inline-block;
          width: 10px;
          height: 10px;
          background: #4ade80;
          border-radius: 50%;
          margin-left: 10px;
          animation: pulse 2s infinite;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔫 Gun Relay Server Dashboard <span class="live-indicator"></span></h1>
        
        <div class="grid">
          <div class="card">
            <h2>📊 Server Status</h2>
            <div class="stat">
              <span>Status</span>
              <span class="stat-value status-active">✅ ONLINE</span>
            </div>
            <div class="stat">
              <span>Uptime</span>
              <span class="stat-value">${days}d ${hours}h ${minutes}m ${seconds}s</span>
            </div>
            <div class="stat">
              <span>Port</span>
              <span class="stat-value">${PORT}</span>
            </div>
            <div class="stat">
              <span>Node Version</span>
              <span class="stat-value">${process.version}</span>
            </div>
          </div>
          
          <div class="card">
            <h2>👥 Connections</h2>
            <div class="stat">
              <span>Active Peers</span>
              <span class="stat-value ${stats.activeConnections > 0 ? 'status-active' : ''}">${stats.activeConnections}</span>
            </div>
            <div class="stat">
              <span>Total Connections</span>
              <span class="stat-value">${stats.totalConnections}</span>
            </div>
            <div class="stat">
              <span>Peak Connections</span>
              <span class="stat-value">${stats.peakConnections}</span>
            </div>
            <div class="stat">
              <span>Connection Limit</span>
              <span class="stat-value">${MAX_CONNECTIONS}</span>
            </div>
          </div>
          
          <div class="card">
            <h2>📈 Performance</h2>
            <div class="stat">
              <span>Total Messages</span>
              <span class="stat-value">${stats.totalMessages.toLocaleString()}</span>
            </div>
            <div class="stat">
              <span>Data Transferred</span>
              <span class="stat-value">${(stats.totalBytes / 1024 / 1024).toFixed(2)} MB</span>
            </div>
            <div class="stat">
              <span>Avg Message Rate</span>
              <span class="stat-value">${(stats.totalMessages / (uptime || 1)).toFixed(2)}/s</span>
            </div>
            <div class="stat">
              <span>Active Rate Limits</span>
              <span class="stat-value">${stats.rateLimitMap.size}</span>
            </div>
          </div>
          
          <div class="card">
            <h2>💾 System Resources</h2>
            <div class="stat">
              <span>Memory Usage</span>
              <span class="stat-value">${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB</span>
            </div>
            <div class="stat">
              <span>Heap Total</span>
              <span class="stat-value">${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB</span>
            </div>
            <div class="stat">
              <span>System Free RAM</span>
              <span class="stat-value">${(freeMem / 1024 / 1024 / 1024).toFixed(2)} GB</span>
            </div>
            <div class="stat">
              <span>CPU Load</span>
              <span class="stat-value">${os.loadavg()[0].toFixed(2)}</span>
            </div>
          </div>
        </div>
        
        <div class="card">
          <h2>🔗 Connection Info</h2>
          <div class="connection-string">
            <strong>WebSocket Endpoint:</strong>
            <code>wss://${req.get('host')}/gun</code>
          </div>
          <div class="connection-string">
            <strong>Add to Whisperz App:</strong>
            <code>localStorage.setItem('GUN_CUSTOM_PEERS', 'https://${req.get('host')}/gun')</code>
          </div>
        </div>
        
        <div class="grid">
          <div class="card">
            <h2>🔴 Recent Errors (${stats.errors.length})</h2>
            <div class="error-list">
              ${recentErrors.length > 0 ? recentErrors.map(err => `
                <div class="error-item">
                  <strong>${err.timestamp}</strong><br>
                  ${err.context}: ${err.message}
                </div>
              `).join('') : '<p style="opacity: 0.7;">No errors recorded</p>'}
            </div>
          </div>
          
          <div class="card">
            <h2>🌐 Active Peers (${stats.peerMap.size})</h2>
            <div style="max-height: 200px; overflow-y: auto;">
              ${stats.peerMap.size > 0 ? Array.from(stats.peerMap.entries()).slice(0, 10).map(([id, peer]) => `
                <div class="peer-item">
                  <strong>${peer.id.substring(0, 8)}...</strong><br>
                  Connected: ${new Date(peer.connectedAt).toLocaleTimeString()}<br>
                  Messages: ${peer.messageCount}
                </div>
              `).join('') : '<p style="opacity: 0.7;">No active peers</p>'}
            </div>
          </div>
        </div>
        
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
      </div>
      
      <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
      </script>
    </body>
    </html>
  `);
});

// API endpoints for stats
app.get('/api/stats', (req, res) => {
  const uptime = Date.now() - stats.startTime;
  res.json({
    uptime,
    connections: {
      active: stats.activeConnections,
      total: stats.totalConnections,
      peak: stats.peakConnections
    },
    performance: {
      messages: stats.totalMessages,
      bytesTransferred: stats.totalBytes,
      messageRate: stats.totalMessages / (uptime / 1000)
    },
    system: {
      memory: process.memoryUsage(),
      cpu: os.loadavg(),
      platform: os.platform(),
      nodeVersion: process.version
    },
    errors: stats.errors.length
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  const healthy = stats.activeConnections < MAX_CONNECTIONS && 
                  stats.errors.filter(e => Date.now() - new Date(e.timestamp) < 60000).length < 10;
  
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    activeConnections: stats.activeConnections,
    recentErrors: stats.errors.filter(e => Date.now() - new Date(e.timestamp) < 60000).length
  });
});

// Metrics endpoint (Prometheus format)
app.get('/metrics', (req, res) => {
  const uptime = (Date.now() - stats.startTime) / 1000;
  const metrics = `
# HELP gun_relay_uptime_seconds Server uptime in seconds
# TYPE gun_relay_uptime_seconds gauge
gun_relay_uptime_seconds ${uptime}

# HELP gun_relay_connections_active Number of active connections
# TYPE gun_relay_connections_active gauge
gun_relay_connections_active ${stats.activeConnections}

# HELP gun_relay_connections_total Total number of connections
# TYPE gun_relay_connections_total counter
gun_relay_connections_total ${stats.totalConnections}

# HELP gun_relay_messages_total Total number of messages processed
# TYPE gun_relay_messages_total counter
gun_relay_messages_total ${stats.totalMessages}

# HELP gun_relay_bytes_transferred_total Total bytes transferred
# TYPE gun_relay_bytes_transferred_total counter
gun_relay_bytes_transferred_total ${stats.totalBytes}

# HELP gun_relay_errors_total Total number of errors
# TYPE gun_relay_errors_total counter
gun_relay_errors_total ${stats.errors.length}

# HELP gun_relay_memory_usage_bytes Memory usage in bytes
# TYPE gun_relay_memory_usage_bytes gauge
gun_relay_memory_usage_bytes ${process.memoryUsage().heapUsed}
  `.trim();
  
  res.type('text/plain').send(metrics);
});

// Error handling middleware
app.use((err, req, res, next) => {
  errorTracker.track(err, `HTTP ${req.method} ${req.path}`);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║     🚀 Gun Relay Server Started            ║
╠════════════════════════════════════════════╣
║  Port: ${PORT.toString().padEnd(36)}║
║  Dashboard: http://localhost:${PORT.toString().padEnd(25)}║
║  WebSocket: ws://localhost:${PORT}/gun${' '.padEnd(13)}║
║  Health: http://localhost:${PORT}/health${' '.padEnd(15)}║
║  Metrics: http://localhost:${PORT}/metrics${' '.padEnd(14)}║
║  API Stats: http://localhost:${PORT}/api/stats${' '.padEnd(11)}║
╚════════════════════════════════════════════╝
  `);
});

// Initialize Gun with enhanced error handling
const gun = Gun({ 
  web: server,
  radisk: true,
  localStorage: false,
  peers: [],
  axe: false, // Disable unnecessary features for relay
  multicast: false,
  stats: true,
  log: function(msg) {
    if (msg && typeof msg === 'object' && msg.err) {
      errorTracker.track(msg.err, 'Gun internal');
    }
  }
});

// Enhanced connection tracking
gun.on('hi', function(peer) {
  try {
    const peerId = peer.id || peer.url || 'unknown';
    stats.totalConnections++;
    stats.activeConnections++;
    
    if (stats.activeConnections > stats.peakConnections) {
      stats.peakConnections = stats.activeConnections;
    }
    
    // Check connection limit
    if (stats.activeConnections > MAX_CONNECTIONS) {
      console.log(`⚠️ Connection limit reached, rejecting peer: ${peerId}`);
      if (peer.wire) {
        peer.wire.close();
      }
      return;
    }
    
    // Track peer details
    stats.peerMap.set(peerId, {
      id: peerId,
      connectedAt: Date.now(),
      messageCount: 0,
      bytesTransferred: 0,
      lastActivity: Date.now()
    });
    
    stats.connectionHistory.push({
      type: 'connect',
      peer: peerId,
      timestamp: new Date().toISOString()
    });
    
    // Keep only last 100 connection events
    if (stats.connectionHistory.length > 100) {
      stats.connectionHistory.shift();
    }
    
    console.log(`✅ Peer connected: ${peerId} (Active: ${stats.activeConnections})`);
  } catch (err) {
    errorTracker.track(err, 'Connection handler');
  }
});

gun.on('bye', function(peer) {
  try {
    const peerId = peer.id || peer.url || 'unknown';
    stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    
    // Remove from peer map
    if (stats.peerMap.has(peerId)) {
      const peerInfo = stats.peerMap.get(peerId);
      const duration = Date.now() - peerInfo.connectedAt;
      console.log(`👋 Peer disconnected: ${peerId} (Duration: ${(duration/1000).toFixed(2)}s, Messages: ${peerInfo.messageCount})`);
      stats.peerMap.delete(peerId);
    }
    
    stats.connectionHistory.push({
      type: 'disconnect',
      peer: peerId,
      timestamp: new Date().toISOString()
    });
    
    if (stats.connectionHistory.length > 100) {
      stats.connectionHistory.shift();
    }
  } catch (err) {
    errorTracker.track(err, 'Disconnection handler');
  }
});

// Track messages
gun.on('in', function(msg) {
  try {
    stats.totalMessages++;
    
    // Estimate message size
    const size = JSON.stringify(msg).length;
    stats.totalBytes += size;
    
    // Update peer stats
    const peer = msg._ && msg._.via;
    if (peer && stats.peerMap.has(peer)) {
      const peerInfo = stats.peerMap.get(peer);
      peerInfo.messageCount++;
      peerInfo.bytesTransferred += size;
      peerInfo.lastActivity = Date.now();
    }
    
    // Track message rate (keep last 60 seconds)
    const now = Date.now();
    stats.messageRate.push(now);
    stats.messageRate = stats.messageRate.filter(t => now - t < 60000);
  } catch (err) {
    errorTracker.track(err, 'Message tracking');
  }
});

// Cleanup inactive peers periodically
setInterval(() => {
  const now = Date.now();
  const timeout = 5 * 60 * 1000; // 5 minutes
  
  for (const [peerId, peerInfo] of stats.peerMap.entries()) {
    if (now - peerInfo.lastActivity > timeout) {
      console.log(`🧹 Cleaning up inactive peer: ${peerId}`);
      stats.peerMap.delete(peerId);
      stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    }
  }
  
  // Clean old rate limit entries
  for (const [ip, requests] of stats.rateLimitMap.entries()) {
    const recentRequests = requests.filter(t => now - t < RATE_LIMIT_WINDOW);
    if (recentRequests.length === 0) {
      stats.rateLimitMap.delete(ip);
    } else {
      stats.rateLimitMap.set(ip, recentRequests);
    }
  }
}, 60000); // Every minute

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('📛 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\n📛 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  errorTracker.track(err, 'Uncaught exception');
  console.error('💀 Uncaught exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  errorTracker.track(reason, 'Unhandled rejection');
  console.error('💀 Unhandled rejection at:', promise, 'reason:', reason);
});

console.log('✅ Gun.js relay initialized with enhanced monitoring');
console.log('🔒 Private relay mode - no public peers');
console.log('📊 Stats tracking enabled');
console.log('🛡️ Rate limiting active');