const Gun = require('gun');
const express = require('express');
const cors = require('cors');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8765;
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;

// Load saved password or use default
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
try {
  if (fs.existsSync('.admin_password')) {
    ADMIN_PASSWORD = fs.readFileSync('.admin_password', 'utf8').trim();
  }
} catch (err) {
  console.log('Using default admin password');
}

const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 100;

// Admin session management
const adminSessions = new Map();
const SESSION_DURATION = 3600000; // 1 hour

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
  rateLimitMap: new Map(),
  bannedIPs: new Set(),
  logs: [],
  serverPaused: false
};

// Configuration that can be changed at runtime
let config = {
  maxConnections: MAX_CONNECTIONS,
  rateLimitWindow: RATE_LIMIT_WINDOW,
  maxRequestsPerWindow: MAX_REQUESTS_PER_WINDOW,
  enableLogging: true,
  enableRateLimit: true,
  maintenanceMode: false,
  // Privacy settings
  privacyMode: false,
  anonymizeIPs: false,
  disableStats: false,
  ephemeralData: false
};

// Logger
function log(level, message, data = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    data
  };
  
  stats.logs.unshift(entry);
  if (stats.logs.length > 500) {
    stats.logs.pop();
  }
  
  if (config.enableLogging) {
    console.log(`[${level}] ${message}`, data);
  }
}

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
    
    log('ERROR', `${context} - ${error.message || error}`);
  }
}

const errorTracker = new ErrorTracker();

// Admin authentication
function generateSession() {
  return crypto.randomBytes(32).toString('hex');
}

function isAuthenticated(req) {
  const session = req.headers['x-admin-session'] || req.query.session;
  if (!session) return false;
  
  const sessionData = adminSessions.get(session);
  if (!sessionData) return false;
  
  if (Date.now() - sessionData.created > SESSION_DURATION) {
    adminSessions.delete(session);
    return false;
  }
  
  return true;
}

// Rate limiting
function checkRateLimit(ip) {
  if (!config.enableRateLimit) return true;
  if (stats.bannedIPs.has(ip)) return false;
  
  const now = Date.now();
  const windowStart = now - config.rateLimitWindow;
  
  if (!stats.rateLimitMap.has(ip)) {
    stats.rateLimitMap.set(ip, []);
  }
  
  const requests = stats.rateLimitMap.get(ip);
  const recentRequests = requests.filter(time => time > windowStart);
  
  stats.rateLimitMap.set(ip, recentRequests);
  
  if (recentRequests.length >= config.maxRequestsPerWindow) {
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

// Admin login endpoint
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const session = generateSession();
    adminSessions.set(session, {
      created: Date.now(),
      ip: req.ip
    });
    
    log('INFO', `Admin logged in from ${req.ip}`);
    res.json({ success: true, session });
  } else {
    log('WARN', `Failed admin login attempt from ${req.ip}`);
    res.status(401).json({ success: false, error: 'Invalid password' });
  }
});

// Admin logout endpoint
app.post('/admin/logout', (req, res) => {
  const session = req.headers['x-admin-session'] || req.query.session;
  
  if (session && adminSessions.has(session)) {
    adminSessions.delete(session);
    log('INFO', `Admin logged out (session: ${session.substring(0, 8)}...)`);
    res.json({ success: true, message: 'Logged out successfully' });
  } else {
    res.json({ success: true, message: 'Session already expired or invalid' });
  }
});

// Admin control endpoints
app.post('/admin/control/:action', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { action } = req.params;
  
  switch (action) {
    case 'pause':
      stats.serverPaused = true;
      log('INFO', 'Server paused by admin');
      res.json({ success: true, message: 'Server paused' });
      break;
      
    case 'resume':
      stats.serverPaused = false;
      log('INFO', 'Server resumed by admin');
      res.json({ success: true, message: 'Server resumed' });
      break;
      
    case 'clear-stats':
      stats.totalMessages = 0;
      stats.totalBytes = 0;
      stats.errors = [];
      stats.connectionHistory = [];
      stats.logs = [];
      log('INFO', 'Stats cleared by admin');
      res.json({ success: true, message: 'Stats cleared' });
      break;
      
    case 'clear-peers':
      for (const [peerId, peer] of stats.peerMap.entries()) {
        if (peer.wire) {
          peer.wire.close();
        }
      }
      stats.peerMap.clear();
      stats.activeConnections = 0;
      log('INFO', 'All peers disconnected by admin');
      res.json({ success: true, message: 'All peers disconnected' });
      break;
      
    case 'maintenance-on':
      config.maintenanceMode = true;
      log('INFO', 'Maintenance mode enabled');
      res.json({ success: true, message: 'Maintenance mode enabled' });
      break;
      
    case 'maintenance-off':
      config.maintenanceMode = false;
      log('INFO', 'Maintenance mode disabled');
      res.json({ success: true, message: 'Maintenance mode disabled' });
      break;
      
    default:
      res.status(400).json({ error: 'Unknown action' });
  }
});

// Peer management
app.post('/admin/peer/:action/:peerId', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { action, peerId } = req.params;
  
  switch (action) {
    case 'kick':
      const peer = stats.peerMap.get(peerId);
      if (peer && peer.wire) {
        peer.wire.close();
        stats.peerMap.delete(peerId);
        stats.activeConnections--;
        log('INFO', `Peer ${peerId} kicked by admin`);
        res.json({ success: true, message: 'Peer kicked' });
      } else {
        res.status(404).json({ error: 'Peer not found' });
      }
      break;
      
    case 'ban':
      const peerInfo = stats.peerMap.get(peerId);
      if (peerInfo && peerInfo.ip) {
        stats.bannedIPs.add(peerInfo.ip);
        if (peerInfo.wire) {
          peerInfo.wire.close();
        }
        stats.peerMap.delete(peerId);
        stats.activeConnections--;
        log('WARN', `IP ${peerInfo.ip} banned by admin`);
        res.json({ success: true, message: 'IP banned' });
      } else {
        res.status(404).json({ error: 'Peer not found' });
      }
      break;
      
    default:
      res.status(400).json({ error: 'Unknown action' });
  }
});

// IP management
app.post('/admin/ip/:action', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { action } = req.params;
  const { ip } = req.body;
  
  switch (action) {
    case 'ban':
      stats.bannedIPs.add(ip);
      log('WARN', `IP ${ip} banned by admin`);
      res.json({ success: true, message: 'IP banned' });
      break;
      
    case 'unban':
      stats.bannedIPs.delete(ip);
      log('INFO', `IP ${ip} unbanned by admin`);
      res.json({ success: true, message: 'IP unbanned' });
      break;
      
    default:
      res.status(400).json({ error: 'Unknown action' });
  }
});

// Configuration management
app.get('/admin/config', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json(config);
});

app.post('/admin/config', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const updates = req.body;
  Object.assign(config, updates);
  log('INFO', 'Configuration updated', updates);
  res.json({ success: true, config });
});

// Change admin password
app.post('/admin/change-password', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new passwords required' });
  }
  
  if (currentPassword !== ADMIN_PASSWORD) {
    log('WARN', `Failed password change attempt from ${req.ip}`);
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  ADMIN_PASSWORD = newPassword;
  
  // Save password to file for persistence (optional)
  try {
    fs.writeFileSync('.admin_password', newPassword, 'utf8');
  } catch (err) {
    log('WARN', 'Could not save password to file', err);
  }
  
  // Clear all existing sessions for security
  adminSessions.clear();
  
  log('INFO', `Admin password changed successfully from ${req.ip}`);
  res.json({ success: true, message: 'Password changed successfully. Please login again.' });
});

// Get logs
app.get('/admin/logs', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const limit = parseInt(req.query.limit) || 100;
  const level = req.query.level;
  
  let logs = stats.logs;
  if (level) {
    logs = logs.filter(l => l.level === level);
  }
  
  res.json(logs.slice(0, limit));
});

// Enhanced dashboard with admin panel
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
  const recentLogs = stats.logs.slice(0, 10);
  
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
          max-width: 1400px;
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
        .status-active { color: #4ade80; }
        .status-warning { color: #fbbf24; }
        .status-error { color: #f87171; }
        .status-paused { color: #fb923c; }
        
        /* Admin Panel Styles */
        .admin-panel {
          background: rgba(0, 0, 0, 0.3);
          border-radius: 15px;
          padding: 20px;
          margin: 20px 0;
        }
        .admin-login {
          text-align: center;
          padding: 20px;
        }
        .admin-controls {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 10px;
          margin: 20px 0;
        }
        button {
          background: rgba(255, 255, 255, 0.2);
          border: 2px solid rgba(255, 255, 255, 0.3);
          color: white;
          padding: 10px 20px;
          border-radius: 8px;
          cursor: pointer;
          font-size: 1em;
          transition: all 0.3s;
        }
        button:hover {
          background: rgba(255, 255, 255, 0.3);
          transform: scale(1.05);
        }
        button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        button.danger {
          background: rgba(248, 113, 113, 0.3);
          border-color: rgba(248, 113, 113, 0.5);
        }
        button.danger:hover {
          background: rgba(248, 113, 113, 0.5);
        }
        button.success {
          background: rgba(74, 222, 128, 0.3);
          border-color: rgba(74, 222, 128, 0.5);
        }
        button.success:hover {
          background: rgba(74, 222, 128, 0.5);
        }
        button.warning {
          background: rgba(251, 191, 36, 0.3);
          border-color: rgba(251, 191, 36, 0.5);
        }
        button.warning:hover {
          background: rgba(251, 191, 36, 0.5);
        }
        input {
          background: rgba(255, 255, 255, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.3);
          color: white;
          padding: 10px;
          border-radius: 8px;
          font-size: 1em;
          margin: 5px;
        }
        input::placeholder {
          color: rgba(255, 255, 255, 0.5);
        }
        .peer-list {
          max-height: 300px;
          overflow-y: auto;
        }
        .peer-item {
          background: rgba(74, 222, 128, 0.1);
          padding: 10px;
          margin: 5px 0;
          border-radius: 5px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .log-viewer {
          background: rgba(0, 0, 0, 0.3);
          padding: 15px;
          border-radius: 10px;
          max-height: 400px;
          overflow-y: auto;
          font-family: monospace;
          font-size: 0.9em;
        }
        .log-entry {
          padding: 5px;
          margin: 2px 0;
          border-radius: 3px;
        }
        .log-INFO { background: rgba(74, 222, 128, 0.1); }
        .log-WARN { background: rgba(251, 191, 36, 0.1); }
        .log-ERROR { background: rgba(248, 113, 113, 0.1); }
        .tabs {
          display: flex;
          gap: 10px;
          margin-bottom: 20px;
        }
        .tab {
          padding: 10px 20px;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          cursor: pointer;
        }
        .tab.active {
          background: rgba(255, 255, 255, 0.3);
        }
        .tab-content {
          display: none;
        }
        .tab-content.active {
          display: block;
        }
        .config-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 10px;
          background: rgba(255, 255, 255, 0.05);
          margin: 5px 0;
          border-radius: 5px;
        }
        .toggle {
          position: relative;
          width: 50px;
          height: 25px;
          background: rgba(255, 255, 255, 0.2);
          border-radius: 25px;
          cursor: pointer;
        }
        .toggle.active {
          background: rgba(74, 222, 128, 0.5);
        }
        .toggle-slider {
          position: absolute;
          top: 2px;
          left: 2px;
          width: 21px;
          height: 21px;
          background: white;
          border-radius: 50%;
          transition: transform 0.3s;
        }
        .toggle.active .toggle-slider {
          transform: translateX(25px);
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
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.5; }
          100% { opacity: 1; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔫 Gun Relay Server Dashboard <span class="live-indicator"></span></h1>
        
        <!-- Server Status -->
        <div class="grid">
          <div class="card">
            <h2>📊 Server Status</h2>
            <div class="stat">
              <span>Status</span>
              <span class="stat-value ${stats.serverPaused ? 'status-paused' : (config.maintenanceMode ? 'status-warning' : 'status-active')}">
                ${stats.serverPaused ? '⏸️ PAUSED' : (config.maintenanceMode ? '🔧 MAINTENANCE' : '✅ ONLINE')}
              </span>
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
              <span>Banned IPs</span>
              <span class="stat-value">${stats.bannedIPs.size}</span>
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
              <span>Message Rate</span>
              <span class="stat-value">${(stats.totalMessages / (uptime || 1)).toFixed(2)}/s</span>
            </div>
            <div class="stat">
              <span>Errors</span>
              <span class="stat-value ${stats.errors.length > 0 ? 'status-error' : ''}">${stats.errors.length}</span>
            </div>
          </div>
        </div>
        
        <!-- Admin Panel -->
        <div class="admin-panel">
          <h2>🔐 Admin Control Panel</h2>
          
          <div id="adminLogin" class="admin-login">
            <input type="password" id="adminPassword" placeholder="Enter admin password">
            <button onclick="adminLogin()">Login</button>
          </div>
          
          <div id="adminControls" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
              <div class="tabs">
                <div class="tab active" onclick="switchTab('controls')">Controls</div>
                <div class="tab" onclick="switchTab('peers')">Peers</div>
                <div class="tab" onclick="switchTab('config')">Config</div>
                <div class="tab" onclick="switchTab('logs')">Logs</div>
              </div>
              <button onclick="logout()" class="danger" style="margin-left: auto;">🚪 Logout</button>
            </div>
            
            <!-- Controls Tab -->
            <div id="controls-tab" class="tab-content active">
              <h3>Server Controls</h3>
              <div class="admin-controls">
                <button onclick="serverControl('pause')" class="danger">⏸️ Pause Server</button>
                <button onclick="serverControl('resume')" class="success">▶️ Resume Server</button>
                <button onclick="serverControl('clear-stats')">📊 Clear Stats</button>
                <button onclick="serverControl('clear-peers')" class="danger">👥 Disconnect All</button>
                <button onclick="serverControl('maintenance-on')" class="danger">🔧 Maintenance ON</button>
                <button onclick="serverControl('maintenance-off')" class="success">✅ Maintenance OFF</button>
              </div>
              
              <h3>IP Management</h3>
              <div style="margin: 10px 0;">
                <input type="text" id="ipAddress" placeholder="IP Address">
                <button onclick="ipControl('ban')">🚫 Ban IP</button>
                <button onclick="ipControl('unban')">✅ Unban IP</button>
              </div>
            </div>
            
            <!-- Peers Tab -->
            <div id="peers-tab" class="tab-content">
              <h3>Active Peers (${stats.peerMap.size})</h3>
              <div class="peer-list">
                ${Array.from(stats.peerMap.entries()).map(([id, peer]) => `
                  <div class="peer-item">
                    <div>
                      <strong>${id.substring(0, 16)}...</strong><br>
                      <small>Messages: ${peer.messageCount} | Connected: ${new Date(peer.connectedAt).toLocaleTimeString()}</small>
                    </div>
                    <div>
                      <button onclick="peerControl('kick', '${id}')" style="padding: 5px 10px;">Kick</button>
                      <button onclick="peerControl('ban', '${id}')" class="danger" style="padding: 5px 10px;">Ban</button>
                    </div>
                  </div>
                `).join('') || '<p>No active peers</p>'}
              </div>
            </div>
            
            <!-- Config Tab -->
            <div id="config-tab" class="tab-content">
              <h3>Configuration</h3>
              <div class="config-item">
                <span>Max Connections</span>
                <input type="number" id="maxConnections" value="${config.maxConnections}" style="width: 100px;">
              </div>
              <div class="config-item">
                <span>Rate Limit Window (ms)</span>
                <input type="number" id="rateLimitWindow" value="${config.rateLimitWindow}" style="width: 100px;">
              </div>
              <div class="config-item">
                <span>Max Requests per Window</span>
                <input type="number" id="maxRequestsPerWindow" value="${config.maxRequestsPerWindow}" style="width: 100px;">
              </div>
              <div class="config-item">
                <span>Enable Logging</span>
                <div class="toggle ${config.enableLogging ? 'active' : ''}" onclick="toggleConfig('enableLogging', this)">
                  <div class="toggle-slider"></div>
                </div>
              </div>
              <div class="config-item">
                <span>Enable Rate Limit</span>
                <div class="toggle ${config.enableRateLimit ? 'active' : ''}" onclick="toggleConfig('enableRateLimit', this)">
                  <div class="toggle-slider"></div>
                </div>
              </div>
              <button onclick="saveConfig()" class="success" style="margin-top: 10px;">💾 Save Configuration</button>
              
              <h3 style="margin-top: 30px;">🔐 Change Admin Password</h3>
              <div style="background: rgba(0, 0, 0, 0.2); padding: 15px; border-radius: 10px; margin-top: 10px;">
                <input type="password" id="currentPassword" placeholder="Current Password" style="display: block; width: 100%; margin-bottom: 10px;">
                <input type="password" id="newPassword" placeholder="New Password (min 6 chars)" style="display: block; width: 100%; margin-bottom: 10px;">
                <input type="password" id="confirmPassword" placeholder="Confirm New Password" style="display: block; width: 100%; margin-bottom: 10px;">
                <button onclick="changePassword()" class="danger">🔑 Change Password</button>
              </div>
            </div>
            
            <!-- Logs Tab -->
            <div id="logs-tab" class="tab-content">
              <h3>Recent Logs</h3>
              <div style="margin: 10px 0;">
                <button onclick="loadLogs('INFO')">ℹ️ Info</button>
                <button onclick="loadLogs('WARN')">⚠️ Warnings</button>
                <button onclick="loadLogs('ERROR')">❌ Errors</button>
                <button onclick="loadLogs()">📜 All</button>
              </div>
              <div class="log-viewer" id="logViewer">
                ${recentLogs.map(log => `
                  <div class="log-entry log-${log.level}">
                    <strong>${log.timestamp}</strong> [${log.level}] ${log.message}
                  </div>
                `).join('') || '<p>No logs available</p>'}
              </div>
            </div>
          </div>
        </div>
        
        <!-- Connection Info -->
        <div class="card">
          <h2>🔗 Connection Info</h2>
          <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 10px; margin: 10px 0;">
            <strong>WebSocket Endpoint:</strong><br>
            <code style="word-break: break-all;">wss://${req.get('host')}/gun</code>
          </div>
          <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 10px;">
            <strong>Add to Whisperz:</strong><br>
            <code style="word-break: break-all;">localStorage.setItem('GUN_CUSTOM_PEERS', 'https://${req.get('host')}/gun')</code>
          </div>
        </div>
      </div>
      
      <script>
        let adminSession = localStorage.getItem('adminSession');
        
        // Check if already logged in
        if (adminSession) {
          document.getElementById('adminLogin').style.display = 'none';
          document.getElementById('adminControls').style.display = 'block';
        }
        
        async function adminLogin() {
          const password = document.getElementById('adminPassword').value;
          const response = await fetch('/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
          });
          
          const data = await response.json();
          if (data.success) {
            adminSession = data.session;
            localStorage.setItem('adminSession', adminSession);
            document.getElementById('adminLogin').style.display = 'none';
            document.getElementById('adminControls').style.display = 'block';
            alert('Login successful!');
          } else {
            alert('Invalid password!');
          }
        }
        
        async function logout() {
          if (confirm('Are you sure you want to logout?')) {
            // Call server to invalidate session
            if (adminSession) {
              try {
                await fetch('/admin/logout', {
                  method: 'POST',
                  headers: { 'X-Admin-Session': adminSession }
                });
              } catch (err) {
                console.error('Error calling logout endpoint:', err);
              }
            }
            
            // Clear local session
            localStorage.removeItem('adminSession');
            adminSession = null;
            document.getElementById('adminLogin').style.display = 'block';
            document.getElementById('adminControls').style.display = 'none';
            document.getElementById('adminPassword').value = '';
            alert('Logged out successfully!');
          }
        }
        
        async function serverControl(action) {
          const response = await fetch('/admin/control/' + action, {
            method: 'POST',
            headers: { 'X-Admin-Session': adminSession }
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            setTimeout(() => location.reload(), 1000);
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        }
        
        async function peerControl(action, peerId) {
          const response = await fetch('/admin/peer/' + action + '/' + peerId, {
            method: 'POST',
            headers: { 'X-Admin-Session': adminSession }
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            setTimeout(() => location.reload(), 1000);
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        }
        
        async function ipControl(action) {
          const ip = document.getElementById('ipAddress').value;
          if (!ip) {
            alert('Please enter an IP address');
            return;
          }
          
          const response = await fetch('/admin/ip/' + action, {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Admin-Session': adminSession 
            },
            body: JSON.stringify({ ip })
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            document.getElementById('ipAddress').value = '';
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        }
        
        function switchTab(tab) {
          // Hide all tabs
          document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          
          // Show selected tab
          document.getElementById(tab + '-tab').classList.add('active');
          event.target.classList.add('active');
        }
        
        function toggleConfig(key, element) {
          element.classList.toggle('active');
        }
        
        async function saveConfig() {
          const config = {
            maxConnections: parseInt(document.getElementById('maxConnections').value),
            rateLimitWindow: parseInt(document.getElementById('rateLimitWindow').value),
            maxRequestsPerWindow: parseInt(document.getElementById('maxRequestsPerWindow').value),
            enableLogging: document.querySelector('.toggle[onclick*="enableLogging"]').classList.contains('active'),
            enableRateLimit: document.querySelector('.toggle[onclick*="enableRateLimit"]').classList.contains('active')
          };
          
          const response = await fetch('/admin/config', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Admin-Session': adminSession 
            },
            body: JSON.stringify(config)
          });
          
          const data = await response.json();
          if (data.success) {
            alert('Configuration saved!');
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        }
        
        async function loadLogs(level) {
          const url = '/admin/logs?limit=50' + (level ? '&level=' + level : '');
          const response = await fetch(url, {
            headers: { 'X-Admin-Session': adminSession }
          });
          
          if (response.ok) {
            const logs = await response.json();
            const logViewer = document.getElementById('logViewer');
            logViewer.innerHTML = logs.map(log => \`
              <div class="log-entry log-\${log.level}">
                <strong>\${log.timestamp}</strong> [\${log.level}] \${log.message}
              </div>
            \`).join('') || '<p>No logs available</p>';
          }
        }
        
        async function changePassword() {
          const currentPassword = document.getElementById('currentPassword').value;
          const newPassword = document.getElementById('newPassword').value;
          const confirmPassword = document.getElementById('confirmPassword').value;
          
          if (!currentPassword || !newPassword || !confirmPassword) {
            alert('Please fill in all password fields');
            return;
          }
          
          if (newPassword !== confirmPassword) {
            alert('New passwords do not match');
            return;
          }
          
          if (newPassword.length < 6) {
            alert('New password must be at least 6 characters');
            return;
          }
          
          const response = await fetch('/admin/change-password', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Admin-Session': adminSession 
            },
            body: JSON.stringify({ currentPassword, newPassword })
          });
          
          const data = await response.json();
          if (data.success) {
            alert(data.message);
            localStorage.removeItem('adminSession');
            location.reload();
          } else {
            alert('Error: ' + (data.error || 'Failed to change password'));
          }
        }
        
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
      </script>
    </body>
    </html>
  `);
});

// API endpoints remain the same
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
    errors: stats.errors.length,
    config,
    serverStatus: {
      paused: stats.serverPaused,
      maintenance: config.maintenanceMode
    }
  });
});

app.get('/health', (req, res) => {
  const healthy = !stats.serverPaused && 
                  !config.maintenanceMode &&
                  stats.activeConnections < config.maxConnections && 
                  stats.errors.filter(e => Date.now() - new Date(e.timestamp) < 60000).length < 10;
  
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    activeConnections: stats.activeConnections,
    recentErrors: stats.errors.filter(e => Date.now() - new Date(e.timestamp) < 60000).length,
    serverPaused: stats.serverPaused,
    maintenanceMode: config.maintenanceMode
  });
});

// Start server
const server = app.listen(PORT, () => {
  log('INFO', `Gun Relay Server Started on port ${PORT}`);
  console.log(`
╔════════════════════════════════════════════╗
║     🚀 Gun Relay Server with Admin         ║
╠════════════════════════════════════════════╣
║  Port: ${PORT.toString().padEnd(36)}║
║  Dashboard: http://localhost:${PORT.toString().padEnd(25)}║
║  Admin Password: ${ADMIN_PASSWORD.padEnd(26)}║
╚════════════════════════════════════════════╝
  `);
});

// Initialize Gun
const gun = Gun({ 
  web: server,
  radisk: true,
  localStorage: false,
  peers: [],
  axe: false,
  multicast: false,
  stats: true,
  log: function(msg) {
    if (msg && typeof msg === 'object' && msg.err) {
      errorTracker.track(msg.err, 'Gun internal');
    }
  }
});

// Connection handling
gun.on('hi', function(peer) {
  try {
    // Check if server is paused or in maintenance
    if (stats.serverPaused || config.maintenanceMode) {
      if (peer.wire) peer.wire.close();
      return;
    }
    
    const peerId = peer.id || peer.url || 'unknown';
    const peerIp = peer.wire && peer.wire._socket ? peer.wire._socket.remoteAddress : 'unknown';
    
    // Check if IP is banned
    if (stats.bannedIPs.has(peerIp)) {
      log('WARN', `Banned IP attempted connection: ${peerIp}`);
      if (peer.wire) peer.wire.close();
      return;
    }
    
    stats.totalConnections++;
    stats.activeConnections++;
    
    if (stats.activeConnections > stats.peakConnections) {
      stats.peakConnections = stats.activeConnections;
    }
    
    if (stats.activeConnections > config.maxConnections) {
      log('WARN', `Connection limit reached, rejecting peer: ${peerId}`);
      if (peer.wire) peer.wire.close();
      return;
    }
    
    stats.peerMap.set(peerId, {
      id: peerId,
      ip: peerIp,
      wire: peer.wire,
      connectedAt: Date.now(),
      messageCount: 0,
      bytesTransferred: 0,
      lastActivity: Date.now()
    });
    
    log('INFO', `Peer connected: ${peerId} from ${peerIp}`);
  } catch (err) {
    errorTracker.track(err, 'Connection handler');
  }
});

gun.on('bye', function(peer) {
  try {
    const peerId = peer.id || peer.url || 'unknown';
    stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    
    if (stats.peerMap.has(peerId)) {
      const peerInfo = stats.peerMap.get(peerId);
      log('INFO', `Peer disconnected: ${peerId}`);
      stats.peerMap.delete(peerId);
    }
  } catch (err) {
    errorTracker.track(err, 'Disconnection handler');
  }
});

gun.on('in', function(msg) {
  try {
    if (!stats.serverPaused) {
      stats.totalMessages++;
      const size = JSON.stringify(msg).length;
      stats.totalBytes += size;
      
      const peer = msg._ && msg._.via;
      if (peer && stats.peerMap.has(peer)) {
        const peerInfo = stats.peerMap.get(peer);
        peerInfo.messageCount++;
        peerInfo.bytesTransferred += size;
        peerInfo.lastActivity = Date.now();
      }
    }
  } catch (err) {
    errorTracker.track(err, 'Message tracking');
  }
});

// Cleanup interval
setInterval(() => {
  const now = Date.now();
  const timeout = 5 * 60 * 1000;
  
  for (const [peerId, peerInfo] of stats.peerMap.entries()) {
    if (now - peerInfo.lastActivity > timeout) {
      log('INFO', `Cleaning up inactive peer: ${peerId}`);
      stats.peerMap.delete(peerId);
      stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    }
  }
  
  // Clean old sessions
  for (const [session, data] of adminSessions.entries()) {
    if (now - data.created > SESSION_DURATION) {
      adminSessions.delete(session);
    }
  }
}, 60000);

// Graceful shutdown
process.on('SIGTERM', () => {
  log('WARN', 'SIGTERM received, shutting down');
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  log('WARN', 'SIGINT received, shutting down');
  server.close(() => process.exit(0));
});

log('INFO', 'Gun.js relay initialized with admin controls');