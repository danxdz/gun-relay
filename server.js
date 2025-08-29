// server.js - hardened version
const Gun = require('gun');
const express = require('express');
const cors = require('cors');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
let bcrypt;
try {
  bcrypt = require('bcrypt'); // SECURITY: hash admin passwords
} catch (e) {
  console.warn('[SECURITY WARNING] bcrypt not installed! Using crypto fallback (less secure)');
  // Fallback to crypto if bcrypt is not available
  bcrypt = {
    hashSync: (password, rounds) => {
      const salt = crypto.randomBytes(16).toString('hex');
      return 'crypto$' + salt + '$' + crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    },
    compareSync: (password, hash) => {
      if (hash.startsWith('crypto$')) {
        const parts = hash.split('$');
        const salt = parts[1];
        const storedHash = parts[2];
        const testHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
        return storedHash === testHash;
      }
      return false;
    },
    compare: async (password, hash) => {
      return bcrypt.compareSync(password, hash);
    }
  };
}
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

// Trust proxy headers (needed for Render and other proxied deployments)
// Use specific number for Render (1 proxy)
app.set('trust proxy', 1);

// --- Constants ---
const MAX_LOGS = parseInt(process.env.MAX_LOGS) || 500;
const MAX_ERRORS = parseInt(process.env.MAX_ERRORS) || 100;
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS) || 1000;
const MAX_LOG_SIZE = 1024 * 100; // Max 100KB per log entry

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
    if (saved.startsWith('$2') || saved.startsWith('crypto$')) {
      ADMIN_PASSWORD_HASH = saved;
      // Loaded admin password hash from .admin_password
    } else {
      // Plaintext present - migrate to bcrypt hash and overwrite with hash (restricted perms)
      const hashed = bcrypt.hashSync(saved, HASH_ROUNDS);
      fs.writeFileSync('.admin_password', hashed, { mode: 0o600 });
      ADMIN_PASSWORD_HASH = hashed;
      // Migrated plaintext .admin_password to bcrypt hash
    }
  } catch (err) {
    console.warn('Failed to read/migrate .admin_password:', err.message);
  }
}

// If env supplied and not a hash, prefer env (but store hashed file for persistence)
if (rawEnvPassword) {
  if (rawEnvPassword.startsWith('$2') || rawEnvPassword.startsWith('crypto$')) {
    ADMIN_PASSWORD_HASH = rawEnvPassword;
    // Using ADMIN_PASSWORD hash from environment
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
      console.log('Admin password configured');
      // clear raw env var reference in memory
      rawEnvPassword = undefined;
    } catch (err) {
      console.error('Failed to hash ADMIN_PASSWORD env:', err.message);
      process.exit(1);
    }
  }
}

// If no password at all, in production refuse to start
if (!ADMIN_PASSWORD_HASH) {
  if (process.env.NODE_ENV === 'production') {
    console.error('ADMIN_PASSWORD not configured. Set ADMIN_PASSWORD env or provide .admin_password (bcrypt hash).');
    process.exit(1);
  } else {
    // Development fallback - use a default password
    console.warn('[DEV MODE] No admin password configured. Using default: admin123');
    ADMIN_PASSWORD_HASH = bcrypt.hashSync('admin123', HASH_ROUNDS);
  }
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
  connectionMetadata: new Map(), // Store detailed connection info
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
const auditLogs = [];
const MAX_AUDIT_LOGS = 1000;

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

// Audit logging for admin actions
function audit(action, req, details = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    ip: getDisplayIP(req.ip),
    userAgent: req.headers['user-agent'],
    sessionId: req.cookies?.admin_sid?.substring(0, 8) + '...',
    ...details
  };
  
  auditLogs.unshift(entry);
  if (auditLogs.length > MAX_AUDIT_LOGS) auditLogs.shift();
  
  // Also log to main log
  log('AUDIT', `${action} from ${entry.ip}`, details);
  
  // Persist audit logs in production
  if (process.env.NODE_ENV === 'production' && process.env.AUDIT_LOG_FILE) {
    fs.appendFile(process.env.AUDIT_LOG_FILE || 'audit.log', 
      JSON.stringify(entry) + '\n', 
      (err) => {
        if (err) console.error('Failed to write audit log:', err);
      }
    );
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

// ---------- SIMPLE IP TRACKING ----------
// Get real client IP considering proxies
function getClientIP(req) {
  // Trust proxy is set, so req.ip should work
  if (req.ip) return req.ip;
  
  // Fallback checks
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(ip => ip.trim());
    return ips[0];
  }
  
  return req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress ||
         'unknown';
}

// ---------- SIMPLE CONNECTION TRACKING ----------
// Track connection metadata with 1-second precision
function trackConnection(req, eventType = 'http') {
  const ip = getClientIP(req);
  const timestamp = Math.floor(Date.now() / 1000) * 1000; // Round to nearest second
  const origin = req.headers['origin'] || req.headers['referer'] || 'direct';
  
  // Simple connection record
  const connId = `${ip}_${timestamp}`;
  const metadata = {
    id: connId,
    ip: ip,
    timestamp: timestamp,
    lastSeen: Date.now(),
    origin: origin,
    requests: 1
  };
  
  // Update or create entry
  if (stats.connectionMetadata.has(connId)) {
    const existing = stats.connectionMetadata.get(connId);
    existing.requests++;
    existing.lastSeen = Date.now();
  } else {
    stats.connectionMetadata.set(connId, metadata);
    
    // Auto-cleanup old entries (older than 1 hour)
    if (stats.connectionMetadata.size > 1000) {
      const oneHourAgo = Date.now() - 3600000;
      for (const [key, value] of stats.connectionMetadata) {
        if (value.lastSeen < oneHourAgo) {
          stats.connectionMetadata.delete(key);
        }
      }
    }
  }
  
  return metadata;
}



// ---------- SAFE PATHS ----------
function safeResolveDbPath(relName) {
  // Strict validation to prevent path traversal
  if (typeof relName !== 'string' || !relName) {
    throw new Error('Invalid database name: must be non-empty string');
  }
  
  // Only allow alphanumeric, dash, underscore (no dots, slashes, etc)
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(relName)) {
    throw new Error('Invalid database name: must be alphanumeric, 1-64 chars');
  }
  
  // Additional check for path traversal patterns
  if (relName.includes('..') || relName.includes('/') || relName.includes('\\')) {
    throw new Error('Path traversal attempt blocked');
  }
  
  const candidate = path.resolve(DATA_BASE, relName);
  const normalizedBase = path.normalize(DATA_BASE) + path.sep;
  const normalizedCandidate = path.normalize(candidate);
  
  if (!normalizedCandidate.startsWith(normalizedBase)) {
    throw new Error('Path validation failed');
  }
  
  return candidate;
}

// ---------- SESSIONS ----------
// IP Whitelist for admin access (optional)
const ADMIN_IP_WHITELIST = process.env.ADMIN_IP_WHITELIST 
  ? process.env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim())
  : [];

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}
function createAdminSession(req) {
  const session = generateSessionId();
  adminSessions.set(session, { created: Date.now(), ip: req.ip, ua: req.headers['user-agent'] || '' });
  return session;
}
function isAuthenticated(req) {
  // Check IP whitelist if configured
  if (ADMIN_IP_WHITELIST.length > 0) {
    const clientIP = req.ip || req.connection.remoteAddress;
    const allowed = ADMIN_IP_WHITELIST.some(allowedIP => {
      return clientIP === allowedIP || clientIP.includes(allowedIP);
    });
    if (!allowed) {
      return false;
    }
  }
  
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
// Track all connections automatically
app.use((req, res, next) => {
  // Track the connection with 1-second precision
  trackConnection(req, 'http');
  next();
});
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  }));
}


// CORS configuration with better defaults
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);

// If no origins specified, allow common patterns
if (allowedOrigins.length === 0 && process.env.NODE_ENV === 'production') {
  // Allow Render preview URLs, Whisperz client, and common dev URLs
  allowedOrigins.push(
    'https://gun-relay-nchb.onrender.com',
    'https://localchat-sandy.vercel.app',
    'https://whisperz.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:8080'
  );
}

app.use(cors({
  origin: function(origin, cb) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return cb(null, true);
    
    // In development, still check but be more permissive
    if (process.env.NODE_ENV !== 'production') {
      // Allow localhost and common dev ports
      if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
        return cb(null, true);
      }
    }
    
    // Check against allowed origins
    const allowed = allowedOrigins.some(allowed => {
      if (allowed === '*') return true;
      if (allowed === origin) return true;
      // Check if origin matches pattern (for subdomains)
      if (origin && (
        origin.includes('vercel.app') ||
        origin.includes('onrender.com') ||
        origin.includes('localhost')
      )) {
        return true;
      }
      return false;
    });
    
    if (allowed) {
      return cb(null, true);
    }
    
    // Log and reject
    console.warn(`CORS request blocked from: ${origin}`);
    cb(null, false);
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));
app.use(cookieParser());

// Serve Gun middleware first
app.use(Gun.serve);

// Initialize Gun instance for server use
// Note: Gun will be fully initialized after server starts
let gun;

// Function to publish instance to Gun for clients
function publishInstanceToGun() {
  if (!gun) return; // Gun not initialized yet
  
  const instance = simpleReset.loadInstance();
  if (instance) {
    gun.get('_whisperz_system').get('config').put({
      instance: instance,
      timestamp: Date.now(),
      resetBy: 'server',
      message: 'Instance update'
    });
  }
}

// ---------- CSRF Token Generation ----------
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Store CSRF tokens with sessions
const csrfTokens = new Map();

// ---------- ADMIN ENDPOINTS ----------

// GET dashboard (SECURITY: require auth to view)
app.get('/', (req, res) => {
  if (!isAuthenticated(req)) {
    return res.send(`
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Admin Login</title>
        <style>
          body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #0a0a0a;
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
          }
          .login-container {
            background: #1a1a1a;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            max-width: 400px;
            width: 100%;
          }
          h2 {
            color: #4ade80;
            margin-bottom: 30px;
            text-align: center;
          }
          input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 5px;
            color: white;
            font-size: 16px;
          }
          input:focus {
            outline: none;
            border-color: #4ade80;
          }
          button {
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: #4ade80;
            color: #000;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
          }
          button:hover {
            background: #22c55e;
          }
          .error {
            color: #ef4444;
            margin-top: 10px;
            text-align: center;
            display: none;
          }
          .info {
            color: #888;
            margin-top: 20px;
            text-align: center;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h2>🔐 Gun Relay Admin</h2>
          <form id="loginForm" onsubmit="handleLogin(event)">
            <input 
              id="password" 
              name="password" 
              type="password" 
              placeholder="Enter admin password" 
              required 
              autocomplete="current-password"
            />
            <button type="submit">Login</button>
            <div id="error" class="error"></div>
          </form>
          <p class="info">Admin UI is protected. Provide credentials to continue.</p>
        </div>
        
        <script>
          async function handleLogin(event) {
            event.preventDefault();
            
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            const button = event.target.querySelector('button');
            
            button.disabled = true;
            button.textContent = 'Logging in...';
            errorDiv.style.display = 'none';
            
            try {
              const response = await fetch('/admin/login', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
              });
              
              const data = await response.json();
              
              if (data.success) {
                window.location.href = '/';
              } else {
                errorDiv.textContent = data.error || 'Invalid password';
                errorDiv.style.display = 'block';
                button.disabled = false;
                button.textContent = 'Login';
              }
            } catch (err) {
              errorDiv.textContent = 'Connection error. Please try again.';
              errorDiv.style.display = 'block';
              button.disabled = false;
              button.textContent = 'Login';
            }
          }
        </script>
      </body>
      </html>
    `);
  }

  // If authenticated, return admin dashboard with database management
  let adminHTML = '';
  try {
    adminHTML = fs.readFileSync(path.join(__dirname, 'admin-database-ui.html'), 'utf8');
  } catch (err) {
    log('WARN', 'Could not load admin-database-ui.html, using embedded UI');
    adminHTML = `
      <div id="databasePanel" style="padding: 20px; background: #1a1a1a; border-radius: 10px; margin: 20px 0;">
        <h2 style="color: #4ade80;">📊 Database Management</h2>
        <p style="color: #fbbf24;">Note: Full UI not loaded. Basic functions available.</p>
        <div style="margin-top: 20px;">
          <button onclick="location.reload()" style="padding: 10px 20px; background: #4ade80; color: #000; border: none; border-radius: 5px; cursor: pointer;">
            Refresh Page
          </button>
        </div>
      </div>
    `;
  }
  
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
      <!-- Notification Container (needed by admin-database-ui.html) -->
      <div id="notificationContainer" style="position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;"></div>
      
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
      audit('LOGIN_SUCCESS', req);
      return res.json({ success: true, session });
    } else {
      audit('LOGIN_FAILED', req, { reason: 'Invalid password' });
      return res.status(401).json({ success: false, error: 'Invalid password' });
    }
  } catch (err) {
    errorTracker.track(err, 'admin/login');
    // Don't leak error details in production
    const errorMsg = process.env.NODE_ENV === 'production' 
      ? 'Authentication service unavailable' 
      : `Internal error: ${err.message}`;
    return res.status(500).json({ success: false, error: errorMsg });
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
    
    // Also get what's published in Gun
    gun.get('_whisperz_system').get('config').once((data) => {
      res.json({ 
        instance: instance || 'production',
        gunInstance: data ? data.instance : null,
        gunTimestamp: data ? data.timestamp : null,
        synced: data && data.instance === instance
      });
    });
  } catch (err) {
    log("ERROR", "Failed to load instance", { err: err.message });
    res.status(500).json({ error: "Failed to load instance" });
  }
});

// Rate limiter for dangerous operations
const dangerousOpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Max 3 resets per 15 minutes
  message: 'Too many reset attempts, please try again later'
});

// Complete reset - server and clients
app.post("/admin/database/complete-reset", dangerousOpLimiter, async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  // Strict input validation - only accept expected fields
  const { newInstance, createSnapshot } = req.body || {};
  
  // Validate input types
  if (newInstance !== undefined && (typeof newInstance !== 'string' || newInstance.length > 100)) {
    return res.status(400).json({ error: "Invalid instance name" });
  }
  
  if (createSnapshot !== undefined && typeof createSnapshot !== 'boolean') {
    return res.status(400).json({ error: "Invalid snapshot parameter" });
  }
  
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
      audit('DATABASE_RESET', req, { newInstance: instanceName, createSnapshot });
      
      // Clear the old Gun data and immediately set new instance
      // Using put(null) then immediately setting new data
      gun.get('_whisperz_system').get('config').put({
        instance: instanceName,
        timestamp: Date.now(),
        resetBy: 'admin',
        message: 'Server reset - all clients should clear data',
        reset: true
      });
      
      res.json({ 
        success: true, 
        newInstance: instanceName,
        message: "Reset successful. Server will restart."
      });
      
      // Restart server after a short delay
      setTimeout(() => {
        log("INFO", "Restarting server after reset...");
        process.exit(0); // Process manager should restart it
      }, 1500);
    } else {
      throw new Error("Reset failed");
    }
  } catch (err) {
    log("ERROR", "Database reset failed", { err: err.message });
    res.status(500).json({ error: err.message || "Reset failed" });
  }
});

// Force set instance - for manual override
app.post("/admin/database/force-instance", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const { instance } = req.body;
  
  if (!instance) {
    return res.status(400).json({ error: "Instance name required" });
  }
  
  try {
    // Save to file
    simpleReset.saveInstance(instance);
    
    // Clear old Gun data and set new
    gun.get('_whisperz_system').put(null);
    
    setTimeout(() => {
      gun.get('_whisperz_system').get('config').put({
        instance: instance,
        timestamp: Date.now(),
        resetBy: 'admin',
        message: 'Instance manually set',
        reset: true
      });
    }, 100);
    
    log("INFO", `Instance manually set to: ${instance}`);
    res.json({ success: true, instance: instance });
  } catch (err) {
    log("ERROR", "Failed to set instance", { err: err.message });
    res.status(500).json({ error: err.message });
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

// Audit log endpoint
app.get('/admin/audit', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const limit = parseInt(req.query.limit) || 100;
  const logs = auditLogs.slice(0, limit);
  
  res.json({
    total: auditLogs.length,
    limit,
    logs
  });
});

// Simple connection tracking endpoint
app.get('/admin/connections', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "Unauthorized" });
  
  const connections = Array.from(stats.connectionMetadata.values())
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, 100); // Last 100 connections
  
  // Get unique IPs and origins
  const uniqueIPs = [...new Set(connections.map(c => c.ip))];
  const uniqueOrigins = [...new Set(connections
    .map(c => c.origin)
    .filter(o => o && o !== 'direct'))];
  
  res.json({
    connections: connections,
    summary: {
      total: connections.length,
      uniqueIPs: uniqueIPs.length,
      ips: uniqueIPs.slice(0, 20), // Show first 20 IPs
      origins: uniqueOrigins,
      lastHour: connections.filter(c => c.timestamp > Date.now() - 3600000).length
    }
  });
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

// Start server with WebSocket support for Gun

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing server gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

const server = app.listen(PORT, () => {
  console.log(`Gun relay server listening on ${PORT}`);
  
  // Initialize Gun with the server for WebSocket support
  gun = Gun({ 
    web: server,
    file: path.join(DATA_BASE || 'radata'),
    axe: false,  // Disable to prevent clearing browser data
    peers: [],   // No default peers, this is the main relay
    multicast: false  // Disable UDP multicast (not needed on cloud hosting)
  });
  
  // On server start, determine instance
  setTimeout(() => {
    let instance;
    
    // Priority: Environment variable > Gun > File > New
    if (process.env.WHISPERZ_INSTANCE) {
      // Use environment variable (this persists on Render)
      instance = process.env.WHISPERZ_INSTANCE;
    } else {
      // Check Gun for existing instance
      gun.get('_whisperz_system').get('config').once((data) => {
        if (data && data.instance) {
          instance = data.instance;
        } else {
          // No instance in Gun, check file or create new
          const fileInstance = simpleReset.loadInstance();
          if (fileInstance && fileInstance !== 'production') {
            instance = fileInstance;
          } else {
            // Create new instance
            instance = `v${Date.now()}`;
          }
        }
      });
      
      // Wait for Gun check to complete
      setTimeout(() => {
        if (!instance) {
          instance = `v${Date.now()}`;
        }
        publishInstance();
      }, 100);
      return;
    }
    
    publishInstance();
    
    function publishInstance() {
      // Save locally and publish to Gun
      simpleReset.saveInstance(instance);
      
      gun.get('_whisperz_system').get('config').put({
        instance: instance,
        timestamp: Date.now(),
        resetBy: 'server',
        message: 'Server started',
        reset: false  // Clear any reset flag
      });
      
      // Instance published to Gun
      
      // Republish every 5 minutes (instead of 30 seconds) to reduce spam
      setInterval(() => {
        gun.get('_whisperz_system').get('config').once((data) => {
          if (data && data.instance) {
            // Silently republish instance
            gun.get('_whisperz_system').get('config').put({
              instance: data.instance,
              timestamp: Date.now(),
              resetBy: 'server',
              message: 'Periodic update'
            });
          }
        });
      }, 300000); // 5 minutes instead of 30 seconds
    }
  }, 2000);
});
