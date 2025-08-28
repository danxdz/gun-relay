// server.js - hardened version
const Gun = require('gun');
const express = require('express');
const cors = require('cors');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // SECURITY: hash admin passwords
const rateLimit = require('express-rate-limit'); // SECURITY: protect login
const cookieParser = require('cookie-parser'); // SECURITY: cookie sessions
const DatabaseManager = require('./database-manager');
const SimpleReset = require('./simple-reset');


let helmet;
try {
  helmet = require('helmet');
} catch (e) {
  console.warn('[SECURITY] Helmet not installed! Install helmet for HTTP security headers.');
}

const app = express();
const PORT = process.env.PORT || 8765;

// --- Constants ---
const MAX_LOGS = 500;
const MAX_ERRORS = 100;
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;

// ---------- ADMIN PASSWORD LOADING & MIGRATION ----------
// Priority: env -> .admin_password (bcrypt hash) -> default (only allowed in non-production)
let ADMIN_PASSWORD_HASH = null;
let rawEnvPassword = process.env.ADMIN_PASSWORD || undefined;

const HASH_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const DATA_BASE = path.resolve(process.env.DATA_BASE || path.resolve(process.cwd(), 'radata_base'));

function isWeakPasswordPlain(pw) {
  if (!pw || typeof pw !== 'string') return true;
  if (pw.length < 12) return true;
  const weak = ['admin', 'admin123', 'password', 'changeme', '123456'];
  if (weak.includes(pw.toLowerCase())) return true;
  return false;
}

// Load persisted .admin_password if present
if (fs.existsSync('.admin_password')) {
  try {
    const saved = fs.readFileSync('.admin_password', 'utf8').trim();
    if (saved.startsWith('$2')) {
      ADMIN_PASSWORD_HASH = saved;
      console.log('Loaded admin password hash from .admin_password');
    } else {
      // Plaintext present - migrate to bcrypt hash and overwrite with hash (restricted perms)
      const hashed = bcrypt.hashSync(saved, HASH_ROUNDS);
      fs.writeFileSync('.admin_password', hashed, { mode: 0o600 });
      ADMIN_PASSWORD_HASH = hashed;
      console.log('Migrated plaintext .admin_password to bcrypt hash (file overwritten)');
    }
  } catch (err) {
    console.warn('Failed to read/migrate .admin_password:', err.message);
  }
}

// If env supplied and not a hash, prefer env (but store hashed file for persistence)
if (rawEnvPassword) {
  if (rawEnvPassword.startsWith('$2')) {
    ADMIN_PASSWORD_HASH = rawEnvPassword;
    console.log('Using ADMIN_PASSWORD hash from environment');
  } else {
    // if plain text provided in env, optionally refuse in production if weak
    if (process.env.NODE_ENV === 'production' && isWeakPasswordPlain(rawEnvPassword)) {
      console.error('Refusing to start: ADMIN_PASSWORD env is weak. Provide a strong password (>=12 chars).');
      process.exit(1);
    }
    try {
      const hashed = bcrypt.hashSync(rawEnvPassword, HASH_ROUNDS);
      try {
        fs.writeFileSync('.admin_password', hashed, { mode: 0o600 });
      } catch (e) {
        console.warn('Unable to persist admin hash to .admin_password; using in-memory only');
      }
      ADMIN_PASSWORD_HASH = hashed;
      console.log('Loaded admin password from environment (hashed in-memory/persisted if possible)');
      // clear raw env var reference in memory
      rawEnvPassword = undefined;
    } catch (err) {
      console.error('Failed to hash ADMIN_PASSWORD env:', err.message);
      process.exit(1);
    }
  }
}

// If no password at all, in production refuse to start
if (!ADMIN_PASSWORD_HASH && process.env.NODE_ENV === 'production') {
  console.error('ADMIN_PASSWORD not configured. Set ADMIN_PASSWORD env or provide .admin_password (bcrypt hash).');
  process.exit(1);
}

const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = process.env.MAX_REQUESTS_PER_WINDOW ? parseInt(process.env.MAX_REQUESTS_PER_WINDOW) : 100;

// ---------- IN-MEMORY STRUCTURES ----------
const adminSessions = new Map(); // consider Redis for production persistence
const SESSION_DURATION = parseInt(process.env.SESSION_DURATION_MS || 3600000); // 1 hour default
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
let DATABASE_INSTANCES = {
  prod: { name: 'Production', path: 'prod', namespace: 'prod' },
  test: { name: 'Test', path: 'test', namespace: 'test' },
  dev: { name: 'Development', path: 'dev', namespace: 'dev' },
  staging: { name: 'Staging', path: 'staging', namespace: 'staging' }
};
let RESET_TIMESTAMPS = {};
let DATA_NAMESPACE = 'prod';
const dbManager = new DatabaseManager();
const simpleReset = new SimpleReset();
let config = {
  maxConnections: MAX_CONNECTIONS,
  rateLimitWindow: RATE_LIMIT_WINDOW,
  maxRequestsPerWindow: MAX_REQUESTS_PER_WINDOW,
  enableLogging: true,
  enableRateLimit: true,
  maintenanceMode: false,
  privacyMode: false,
  anonymizeIPs: false,
  currentDatabase: 'prod',
  blockPeerSync: false,
  resetTimestamp: 0
};

// ---------- UTILITIES ----------
function log(level, message, data = {}) {
  if (config.privacyMode) return;
  const entry = { timestamp: new Date().toISOString(), level, message, data };
  stats.logs.unshift(entry);
  if (stats.logs.length > MAX_LOGS) stats.logs.pop();
  if (config.enableLogging) {
    // redact any tokens, sessions, passwords in data for safety when printing
    const safeData = JSON.parse(JSON.stringify(data, (k, v) => {
      if (k && (k.toLowerCase().includes('token') || k.toLowerCase().includes('session') || k.toLowerCase().includes('password'))) return '[REDACTED]';
      return v;
    }));
    console.log(`[${level}] ${message}`, safeData);
  }
}

function getDisplayIP(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  if (!config.anonymizeIPs) return ip;
  if (ip.includes('.')) {
    const parts = ip.split('.');
    return parts.slice(0, 2).join('.') + '.x.x';
  }
  return 'anonymized';
}

class ErrorTracker {
  constructor(maxErrors = MAX_ERRORS) { this.maxErrors = maxErrors; }
  track(error, context = '') {
    const errorEntry = { timestamp: new Date().toISOString(), message: error.message || error, stack: error.stack, context };
    stats.errors.unshift(errorEntry);
    if (stats.errors.length > this.maxErrors) stats.errors.pop();
    log('ERROR', `${context} - ${error.message || error}`);
    // TODO: Optionally send alert/email on repeated/critical errors
  }
}
const errorTracker = new ErrorTracker();

// ---------- SAFE PATHS ----------
function safeResolveDbPath(relName) {
  // only allow small safe names (letters, digits, dash, underscore)
  if (typeof relName !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(relName)) {
    throw new Error('Invalid database name');
  }
  const candidate = path.resolve(DATA_BASE, relName);
  if (!candidate.startsWith(DATA_BASE + path.sep)) throw new Error('Invalid path');
  return candidate;
}

// ---------- SESSIONS ----------
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}
function createAdminSession(req) {
  const session = generateSessionId();
  adminSessions.set(session, { created: Date.now(), ip: req.ip, ua: req.headers['user-agent'] || '' });
  return session;
}
function isAuthenticated(req) {
  const cookieSession = req.cookies?.admin_sid;
  const headerSession = req.headers['x-admin-session'] || req.query.session;
  const session = cookieSession || headerSession;
  if (!session) return false;
  const data = adminSessions.get(session);
  if (!data) return false;
  if (Date.now() - data.created > SESSION_DURATION) { adminSessions.delete(session); return false; }
  // basic UA binding to reduce token theft impact
  if (data.ua && data.ua !== (req.headers['user-agent'] || '')) return false;
  return true;
}

// ---------- BAN MANAGEMENT ----------
const banExpiry = new Map();
function banIP(ip, durationMs) {
  if (!ip) return;
  stats.bannedIPs.add(ip);
  banExpiry.set(ip, Date.now() + durationMs);
  setTimeout(() => {
    stats.bannedIPs.delete(ip);
    banExpiry.delete(ip);
  }, durationMs).unref();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, exp] of banExpiry.entries()) if (exp <= now) { stats.bannedIPs.delete(ip); banExpiry.delete(ip); }
}, 60_000).unref();

// ---------- RATE LIMITERS ----------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ---------- MIDDLEWARE ----------
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  }));
}


// CORS allowlist with fallback for dev
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, cb) {
    if (!origin) return cb(null, true); // allow server-to-server requests
    if (allowedOrigins.length === 0) {
      if (process.env.NODE_ENV !== 'production') return cb(null, true); // allow all in dev
      return cb(new Error('CORS disabled'));
    }
    if (allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS not allowed'));
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));
app.use(cookieParser());

// Serve Gun
app.use(Gun.serve);

// ---------- ADMIN ENDPOINTS ----------

// GET dashboard (SECURITY: require auth to view)
app.get('/', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.send(`
      <!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title></head>
      <body style="font-family:system-ui,Segoe UI,Roboto;">
        <h2>Gun Relay Admin — Login</h2>
        <form method="post" action="/admin/login" style="max-width:400px">
          <input name="password" type="password" placeholder="Admin password" required style="width:100%;padding:8px;margin:8px 0"/>
          <button type="submit" style="padding:8px 12px">Login</button>
        </form>
        <p style="color:#666">Admin UI is protected. Provide credentials to continue.</p>
      </body></html>
    `);
  }

  // If authenticated, return admin dashboard with database management
  const adminHTML = fs.readFileSync(path.join(__dirname, 'admin-database-ui.html'), 'utf8');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Gun Relay Admin Dashboard</title>
      <style>
        body {
          background: #0a0a0a;
          color: #fff;
          font-family: system-ui, -apple-system, sans-serif;
          margin: 0;
          padding: 20px;
        }
        h1 {
          color: #4ade80;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
        }
        button {
          background: #4ade80;
          color: #000;
          border: none;
          padding: 10px 20px;
          border-radius: 5px;
          cursor: pointer;
          font-weight: 600;
        }
        button:hover {
          background: #22c55e;
        }
        button.danger {
          background: #ef4444;
          color: white;
        }
        button.danger:hover {
          background: #dc2626;
        }
        button.warning {
          background: #fbbf24;
          color: #000;
        }
        button.success {
          background: #4ade80;
          color: #000;
        }
        .logout-btn {
          position: fixed;
          top: 20px;
          right: 20px;
          background: #ef4444;
          color: white;
        }
      </style>
    </head>
    <body>
      <button class="logout-btn" onclick="logout()">Logout</button>
      <div class="container">
        <h1>🚀 Gun Relay Admin Dashboard</h1>
        
        <!-- Stats Section -->
        <div style="background: #1a1a1a; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <h2>📊 Server Statistics</h2>
          <div id="stats">Loading stats...</div>
        </div>
        
        ${adminHTML}
        
      </div>
      
      <script>
        const adminSession = '${req.cookies?.admin_sid || req.headers['x-admin-session'] || ''}';
        
        async function logout() {
          if (confirm('Are you sure you want to logout?')) {
            await fetch('/admin/logout', {
              method: 'POST',
              headers: { 'X-Admin-Session': adminSession }
            });
            window.location.href = '/';
          }
        }
        
        async function loadStats() {
          try {
            const response = await fetch('/health');
            const data = await response.json();
            document.getElementById('stats').innerHTML = 'Server Status: ' + data.status;
          } catch (err) {
            document.getElementById('stats').innerHTML = 'Error loading stats';
          }
        }
        
        // Load initial data
        loadStats();
        setInterval(loadStats, 5000);
      </script>
    </body>
    </html>
  `);
});

// Admin login (SECURITY: rate-limited)
app.post('/admin/login', loginLimiter, async (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string' || password.length > 200) {
    return res.status(400).json({ success: false, error: 'Invalid input' });
  }

  // validate using bcrypt hash
  try {
    if (!ADMIN_PASSWORD_HASH) {
      return res.status(500).json({ success: false, error: 'Admin password not configured' });
    }
    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (ok) {
      const session = createAdminSession(req);
      res.cookie('admin_sid', session, { httpOnly: true, secure: (process.env.FORCE_INSECURE !== 'true'), sameSite: 'strict', maxAge: SESSION_DURATION });
      log('INFO', `Admin logged in from ${getDisplayIP(req.ip)}`);
      return res.json({ success: true, session });
    } else {
      log('WARN', `Failed admin login attempt from ${getDisplayIP(req.ip)}`);
      return res.status(401).json({ success: false, error: 'Invalid password' });
    }
  } catch (err) {
    errorTracker.track(err, 'admin/login');
    return res.status(500).json({ success: false, error: 'Internal' });
  }
});

// Admin logout
app.post('/admin/logout', (req, res) => {
  const session = req.cookies?.admin_sid || req.headers['x-admin-session'] || req.query.session;
  if (session && adminSessions.has(session)) {
    adminSessions.delete(session);
    res.clearCookie('admin_sid');
    log('INFO', `Admin logged out`);
    res.json({ success: true, message: 'Logged out successfully' });
  } else {
    res.json({ success: true, message: 'Session already expired or invalid' });
  }
});

// Example: get databases - same as before but with safe path enumeration
app.get("/admin/databases", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });

  const existingDirs = [];
  try {
    if (!fs.existsSync(DATA_BASE)) fs.mkdirSync(DATA_BASE, { recursive: true });
    const files = fs.readdirSync(DATA_BASE);
    files.forEach(file => {
      const full = path.join(DATA_BASE, file);
      try {
        if (fs.statSync(full).isDirectory()) existingDirs.push(file);
      } catch (e) {}
    });
  } catch (err) {
    console.error("Error reading directories:", err);
  }

  res.json({ instances: DATABASE_INSTANCES, current: config.currentDatabase, existingDirectories: existingDirs });
});

// Add database instance (SECURITY: validate keys + safe path)
app.post("/admin/databases/add", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  const { key, name, path: relPath } = req.body;
  if (!key || !name || !relPath) return res.status(400).json({ error: "Missing required fields" });
  if (DATABASE_INSTANCES[key]) return res.status(400).json({ error: "Instance key already exists" });
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(key) || !/^[\w\s\-\_]{1,128}$/.test(name) || !/^[a-zA-Z0-9_-]{1,64}$/.test(relPath)) {
    return res.status(400).json({ error: "Invalid fields" });
  }

  // Create directory under DATA_BASE
  const dir = safeResolveDbPath(relPath);
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    DATABASE_INSTANCES[key] = { name, path: relPath, namespace: key };
    log("INFO", `Added new database instance: ${key} (${name})`);
    res.json({ success: true, message: `Added ${name} instance` });
  } catch (err) {
    log("ERROR", "Failed to create instance dir", { err: err.message });
    res.status(500).json({ error: 'Failed to add instance' });
  }
});

// Remove database instance (SECURITY: safe path, validate not active)
app.post("/admin/databases/remove", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  const { key, deleteDirectory } = req.body;
  if (!key || !DATABASE_INSTANCES[key]) return res.status(400).json({ error: "Instance not found" });
  if (key === config.currentDatabase) return res.status(400).json({ error: "Cannot remove current active database" });

  if (deleteDirectory) {
    try {
      const dirPath = safeResolveDbPath(DATABASE_INSTANCES[key].path);
      if (fs.existsSync(dirPath)) {
        fs.rmSync(dirPath, { recursive: true, force: true });
        log("INFO", `Deleted directory: ${dirPath}`);
      }
    } catch (err) {
      log("ERROR", `Failed to delete directory: ${DATABASE_INSTANCES[key].path}`, { err: err.message });
      return res.status(500).json({ error: 'Failed to delete directory' });
    }
  }

  delete DATABASE_INSTANCES[key];
  log("INFO", `Removed database instance: ${key}`);
  res.json({ success: true, message: `Removed instance` });
});

// Get current Whisperz instance
app.get("/admin/whisperz/instance", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  try {
    const instance = simpleReset.loadInstance();
    res.json({ instance: instance || 'production' });
  } catch (err) {
    log("ERROR", "Failed to load instance", { err: err.message });
    res.status(500).json({ error: "Failed to load instance" });
  }
});

// Complete reset - server and clients
app.post("/admin/database/complete-reset", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const { newInstance, createSnapshot } = req.body;
  
  try {
    // Generate instance name if not provided
    const instanceName = newInstance || `v${Date.now()}`;
    
    // Create snapshot if requested
    if (createSnapshot) {
      const snapshotName = `pre-reset-${Date.now()}`;
      log("INFO", `Creating snapshot before reset: ${snapshotName}`);
      // Implement snapshot logic here if needed
    }
    
    // Perform reset
    const result = await simpleReset.reset(instanceName);
    
    if (result.success) {
      log("INFO", `Database reset successful. New instance: ${instanceName}`);
      res.json({ 
        success: true, 
        newInstance: instanceName,
        message: "Reset successful. Server will restart."
      });
      
      // Restart server after a short delay
      setTimeout(() => {
        log("INFO", "Restarting server after reset...");
        process.exit(0); // Process manager should restart it
      }, 1000);
    } else {
      throw new Error("Reset failed");
    }
  } catch (err) {
    log("ERROR", "Database reset failed", { err: err.message });
    res.status(500).json({ error: err.message || "Reset failed" });
  }
});

// Database snapshots endpoints
app.get("/admin/database/snapshots", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  // For now, return empty array - can be implemented later
  res.json({ snapshots: [] });
});

app.post("/admin/database/snapshot", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const { name, description } = req.body;
  
  // Placeholder for snapshot creation
  log("INFO", `Snapshot requested: ${name}`);
  res.json({ success: true, message: "Snapshot feature coming soon" });
});

app.post("/admin/database/restore", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const { snapshotId } = req.body;
  
  // Placeholder for restore
  log("INFO", `Restore requested from snapshot: ${snapshotId}`);
  res.json({ success: true, message: "Restore feature coming soon" });
});

app.delete("/admin/database/snapshot/:id", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const { id } = req.params;
  
  // Placeholder for deletion
  log("INFO", `Delete snapshot requested: ${id}`);
  res.json({ success: true, message: "Delete feature coming soon" });
});

// Health endpoint (minimal, no internal metrics)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Version endpoint for debugging/deployment
app.get('/version', (req, res) => {
  // You can automate this with git commit hash or package.json version
  let version = null;
  try {
    version = require('./package.json').version;
  } catch (e) {}
  res.json({
    version: version || 'unknown',
    date: new Date().toISOString(),
    commit: process.env.GIT_COMMIT || null
  });
});

// Start server

// TODO: Add graceful shutdown and signal handling for production
app.listen(PORT, () => {
  console.log(`Gun relay server listening on ${PORT}`);
});
