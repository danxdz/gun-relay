const Gun = require('gun');
const express = require('express');
const cors = require('cors');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const DatabaseManager = require('./database-manager');
// Note: helmet is optional, server works without it
let helmet;
try {
  helmet = require('helmet');
} catch (e) {
  console.log('Helmet not installed, continuing without security headers');
}

const app = express();
const PORT = process.env.PORT || 8765;
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;

// Load saved password or use default
// Priority: 1. Environment variable, 2. Saved file, 3. Default
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Try to load from file if no env var is set
if (process.env.ADMIN_PASSWORD === undefined) {
  try {
    if (fs.existsSync('.admin_password')) {
      const savedPassword = fs.readFileSync('.admin_password', 'utf8').trim();
      if (savedPassword) {
        ADMIN_PASSWORD = savedPassword;
        console.log('Loaded saved admin password from file');
      }
    }
  } catch (err) {
    console.log('Using default admin password (set ADMIN_PASSWORD env var to persist)');
  }
} else {
  console.log('Using admin password from environment variable');
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

// Database instances configuration
let DATABASE_INSTANCES = {
  prod: { name: 'Production', path: 'radata', namespace: 'prod' },
  test: { name: 'Test', path: 'radata-test', namespace: 'test' },
  dev: { name: 'Development', path: 'radata-dev', namespace: 'dev' },
  staging: { name: 'Staging', path: 'radata-staging', namespace: 'staging' }
};

// Add reset tracking
let RESET_TIMESTAMPS = {};
let DATA_NAMESPACE = 'prod'; // Current namespace for data isolation

// Initialize database manager
const dbManager = new DatabaseManager();

// Configuration that can be changed at runtime
let config = {
  maxConnections: MAX_CONNECTIONS,
  rateLimitWindow: RATE_LIMIT_WINDOW,
  maxRequestsPerWindow: MAX_REQUESTS_PER_WINDOW,
  enableLogging: true,
  enableRateLimit: true,
  maintenanceMode: false,
  // Privacy settings - simplified
  privacyMode: false,
  anonymizeIPs: false,
  currentDatabase: 'prod',
  // New: Block peer sync after reset
  blockPeerSync: false,
  resetTimestamp: 0
};

// Logger
function log(level, message, data = {}) {
  // In privacy mode, don't log anything
  if (config.privacyMode) return;
  
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

// Helper to anonymize IPs if needed
function getDisplayIP(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  if (!config.anonymizeIPs) return ip;
  
  // Anonymize: 192.168.1.1 -> 192.168.x.x
  if (ip.includes('.')) {
    const parts = ip.split('.');
    return parts.slice(0, 2).join('.') + '.x.x';
  }
  return 'anonymized';
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
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: false, // Disabled for Gun.js compatibility
    crossOriginEmbedderPolicy: false
  }));
}
app.use(cors());
app.use(express.json({ limit: '1mb' })); // Limit request size to prevent DoS
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Serve Gun
app.use(Gun.serve);

// Admin login endpoint
// Get database instances
app.get("/admin/databases", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  // Check for existing data directories
  const existingDirs = [];
  const dataPattern = /^radata/;
  try {
    const files = fs.readdirSync(".");
    files.forEach(file => {
      if (dataPattern.test(file) && fs.statSync(file).isDirectory()) {
        existingDirs.push(file);
      }
    });
  } catch (err) {
    console.error("Error reading directories:", err);
  }
  
  res.json({
    instances: DATABASE_INSTANCES,
    current: config.currentDatabase,
    existingDirectories: existingDirs
  });
});

// Add new database instance
app.post("/admin/databases/add", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { key, name, path } = req.body;
  
  if (!key || !name || !path) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  
  if (DATABASE_INSTANCES[key]) {
    return res.status(400).json({ error: "Instance key already exists" });
  }
  
  DATABASE_INSTANCES[key] = { name, path };
  log("INFO", `Added new database instance: ${key} (${name})`);
  
  res.json({ success: true, message: `Added ${name} instance` });
});

// Remove database instance
app.post("/admin/databases/remove", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { key } = req.body;
  
  if (!key || !DATABASE_INSTANCES[key]) {
    return res.status(400).json({ error: "Instance not found" });
  }
  
  if (key === config.currentDatabase) {
    return res.status(400).json({ error: "Cannot remove current active database" });
  }
  
  // Optionally delete the directory
  const { deleteDirectory } = req.body;
  if (deleteDirectory) {
    const dirPath = DATABASE_INSTANCES[key].path;
    try {
      if (fs.existsSync(dirPath)) {
        fs.rmSync(dirPath, { recursive: true, force: true });
        log("INFO", `Deleted directory: ${dirPath}`);
      }
    } catch (err) {
      log("ERROR", `Failed to delete directory: ${dirPath}`, err);
    }
  }
  
  delete DATABASE_INSTANCES[key];
  log("INFO", `Removed database instance: ${key}`);
  
  res.json({ success: true, message: `Removed instance` });
});

// Hard reset database - clears all data and restarts
app.post("/admin/databases/reset", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { key, createNew = true, blockSync = true } = req.body;
  
  if (!key || !DATABASE_INSTANCES[key]) {
    return res.status(400).json({ error: "Instance not found" });
  }
  
  const dbConfig = DATABASE_INSTANCES[key];
  const dirPath = dbConfig.path;
  
  try {
    // If this is the current database, we need to handle it carefully
    if (key === config.currentDatabase) {
      // Set reset timestamp and block peer sync
      const resetTime = Date.now();
      RESET_TIMESTAMPS[key] = resetTime;
      config.resetTimestamp = resetTime;
      config.blockPeerSync = blockSync;
      
      // Update namespace to isolate data
      DATA_NAMESPACE = `${dbConfig.namespace}_${resetTime}`;
      
      // Pause the server
      stats.serverPaused = true;
      
      // Disconnect all peers to force them to reconnect with new namespace
      for (const [peerId, peer] of stats.peerMap.entries()) {
        if (peer.wire) {
          peer.wire.close();
        }
      }
      stats.peerMap.clear();
      stats.activeConnections = 0;
      
      // Clear in-memory stats and data
      stats.totalMessages = 0;
      stats.totalBytes = 0;
      stats.errors = [];
      stats.connectionHistory = [];
      stats.logs = [];
      
      // Ban all current peer IPs temporarily (5 minutes) to prevent immediate resync
      if (blockSync) {
        const tempBanDuration = 5 * 60 * 1000; // 5 minutes
        for (const [peerId, peer] of stats.peerMap.entries()) {
          if (peer.ip && peer.ip !== 'unknown') {
            stats.bannedIPs.add(peer.ip);
            setTimeout(() => {
              stats.bannedIPs.delete(peer.ip);
            }, tempBanDuration);
          }
        }
        log("INFO", `Temporarily banned all peer IPs for 5 minutes to prevent resync`);
      }
    }
    
    // Delete the database directory
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
      log("INFO", `Deleted database directory: ${dirPath}`);
    }
    
    // Recreate empty directory if requested
    if (createNew) {
      fs.mkdirSync(dirPath, { recursive: true });
      log("INFO", `Created fresh database directory: ${dirPath}`);
    }
    
    // Send reset signal to all connected clients (for Whisperz auto-reset)
    if (gun && key === config.currentDatabase) {
      try {
        gun.get('_whisperz_system').get('reset').put({
          timestamp: Date.now(),
          database: key,
          message: 'Database reset by administrator'
        });
        log("INFO", "Sent reset signal to all clients");
      } catch (err) {
        log("WARN", "Could not send reset signal to clients", err);
      }
    }
    
    // If this was the current database, we need to restart the server
    if (key === config.currentDatabase) {
      log("WARNING", "Current database was reset. Server restart required for full reset.");
      res.json({ 
        success: true, 
        message: `Database ${dbConfig.name} has been reset. Server restart required. ${blockSync ? 'Peers temporarily blocked from syncing.' : ''}`,
        requiresRestart: true,
        namespace: DATA_NAMESPACE
      });
      
      // Schedule server restart after response
      setTimeout(() => {
        log("INFO", "Restarting server after database reset...");
        process.exit(0); // Exit cleanly - process manager should restart
      }, 1000);
    } else {
      res.json({ 
        success: true, 
        message: `Database ${dbConfig.name} has been reset successfully.`,
        requiresRestart: false
      });
    }
    
  } catch (err) {
    log("ERROR", `Failed to reset database: ${key}`, err);
    
    // Resume server if it was paused
    if (key === config.currentDatabase) {
      stats.serverPaused = false;
    }
    
    res.status(500).json({ 
      error: "Failed to reset database", 
      details: err.message 
    });
  }
});

// Clear all data from current database without switching
app.post("/admin/databases/clear", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const currentDb = config.currentDatabase;
  const dbConfig = DATABASE_INSTANCES[currentDb];
  
  if (!dbConfig) {
    return res.status(400).json({ error: "Current database configuration not found" });
  }
  
  try {
    // Pause the server
    stats.serverPaused = true;
    
    // Disconnect all peers
    for (const [peerId, peer] of stats.peerMap.entries()) {
      if (peer.wire) {
        peer.wire.close();
      }
    }
    stats.peerMap.clear();
    stats.activeConnections = 0;
    
    // Clear the database directory
    const dirPath = dbConfig.path;
    if (fs.existsSync(dirPath)) {
      // Delete all files in the directory but keep the directory
      const files = fs.readdirSync(dirPath);
      for (const file of files) {
        const filePath = path.join(dirPath, file);
        if (fs.statSync(filePath).isDirectory()) {
          fs.rmSync(filePath, { recursive: true, force: true });
        } else {
          fs.unlinkSync(filePath);
        }
      }
      log("INFO", `Cleared all data from: ${dirPath}`);
    }
    
    // Clear in-memory stats
    stats.totalMessages = 0;
    stats.totalBytes = 0;
    stats.errors = [];
    stats.logs = [];
    
    // Send reset signal to all connected clients (for Whisperz auto-reset)
    try {
      gun.get('_whisperz_system').get('reset').put({
        timestamp: Date.now(),
        database: currentDb,
        message: 'Database cleared by administrator'
      });
      log("INFO", "Sent reset signal to all clients");
    } catch (err) {
      log("WARN", "Could not send reset signal to clients", err);
    }
    
    log("WARNING", "Database cleared. Server restart required for complete reset.");
    
    res.json({ 
      success: true, 
      message: `All data cleared from ${dbConfig.name}. Server restart required.`,
      requiresRestart: true
    });
    
    // Schedule server restart
    setTimeout(() => {
      log("INFO", "Restarting server after database clear...");
      process.exit(0);
    }, 1000);
    
  } catch (err) {
    log("ERROR", `Failed to clear database: ${currentDb}`, err);
    stats.serverPaused = false;
    res.status(500).json({ 
      error: "Failed to clear database", 
      details: err.message 
    });
  }
});

// Set Whisperz instance - forces all clients to reset
app.post("/admin/whisperz/set-instance", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { instance } = req.body;
  
  // If no instance provided, generate one based on timestamp
  const newInstance = instance || `v${Date.now()}`;
  
  try {
    // Set the instance in Gun - this will trigger all Whisperz clients to reset
    gun.get('_whisperz_system').get('config').put({
      instance: newInstance,
      timestamp: Date.now(),
      setBy: 'admin'
    });
    
    log("INFO", `Set Whisperz instance to: ${newInstance} - all clients will reset`);
    
    res.json({ 
      success: true, 
      message: `Whisperz instance set to ${newInstance}. All clients will reset.`,
      instance: newInstance
    });
    
  } catch (err) {
    log("ERROR", `Failed to set Whisperz instance`, err);
    res.status(500).json({ 
      error: "Failed to set instance", 
      details: err.message 
    });
  }
});

// Get current Whisperz instance
app.get("/admin/whisperz/instance", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  gun.get('_whisperz_system').get('config').once((data) => {
    res.json({ 
      instance: data?.instance || 'not_set',
      timestamp: data?.timestamp,
      setBy: data?.setBy
    });
  });
});

// Complete reset - server and clients
app.post("/admin/database/complete-reset", async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { newInstance, createSnapshot } = req.body;
  
  try {
    // Create snapshot before reset if requested
    let snapshotId = null;
    if (createSnapshot) {
      snapshotId = dbManager.createSnapshot(
        `Before Reset - ${new Date().toLocaleString()}`,
        'Automatic snapshot before complete reset'
      );
    }
    
    // Perform complete reset
    const result = await dbManager.completeReset(gun, newInstance || `v${Date.now()}`);
    
    res.json({
      success: true,
      ...result,
      snapshotId: snapshotId,
      message: 'Complete reset successful. Server will restart.'
    });
    
    // Schedule server restart
    setTimeout(() => {
      log("INFO", "Restarting server after complete reset...");
      process.exit(0);
    }, 1000);
    
  } catch (err) {
    log("ERROR", "Complete reset failed", err);
    res.status(500).json({ error: err.message });
  }
});

// Create database snapshot
app.post("/admin/database/snapshot", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { name, description } = req.body;
  
  try {
    const snapshotId = dbManager.createSnapshot(name || 'Manual Snapshot', description);
    
    if (snapshotId) {
      res.json({
        success: true,
        snapshotId: snapshotId,
        message: 'Snapshot created successfully'
      });
    } else {
      res.status(500).json({ error: 'Failed to create snapshot' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List snapshots
app.get("/admin/database/snapshots", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  try {
    const snapshots = dbManager.listSnapshots();
    res.json({
      snapshots: snapshots,
      current: dbManager.currentDatabase
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Restore from snapshot
app.post("/admin/database/restore", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { snapshotId } = req.body;
  
  try {
    dbManager.restoreSnapshot(snapshotId);
    
    res.json({
      success: true,
      message: 'Database restored. Server will restart.'
    });
    
    // Schedule server restart
    setTimeout(() => {
      log("INFO", "Restarting server after restore...");
      process.exit(0);
    }, 1000);
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete snapshot
app.delete("/admin/database/snapshot/:id", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { id } = req.params;
  
  try {
    const success = dbManager.deleteSnapshot(id);
    
    if (success) {
      res.json({ success: true, message: 'Snapshot deleted' });
    } else {
      res.status(404).json({ error: 'Snapshot not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  
  // Validate input
  if (!password || typeof password !== 'string' || password.length > 100) {
    return res.status(400).json({ success: false, error: 'Invalid input' });
  }
  
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
      
    case 'switch-database':
      const { database } = req.body;
      if (!DATABASE_INSTANCES[database]) {
        return res.status(400).json({ error: 'Invalid database instance' });
      }
      
      // Pause the server during switch
      stats.serverPaused = true;
      
      // Disconnect all peers
      for (const [peerId, peer] of stats.peerMap.entries()) {
        if (peer.wire) {
          peer.wire.close();
        }
      }
      stats.peerMap.clear();
      stats.activeConnections = 0;
      
      // Switch database
      initializeGun(database);
      
      // Resume server
      stats.serverPaused = false;
      
      log('INFO', `Switched to database: ${DATABASE_INSTANCES[database].name}`);
      res.json({ 
        success: true, 
        message: `Switched to ${DATABASE_INSTANCES[database].name} database`,
        currentDatabase: database
      });
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
              
              <!-- Enhanced Database Management -->
              <div style="padding: 20px; background: #2a2a2a; border-radius: 10px; margin: 20px 0;">
                <h3 style="color: #4ade80;">📊 Database Management</h3>
                
                <!-- Current Status -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin: 15px 0;">
                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div>
                      <label style="color: #888; display: block; margin-bottom: 5px;">Instance Name:</label>
                      <strong id="currentInstance" style="color: #4ade80; font-size: 1.2em;">Loading...</strong>
                    </div>
                    <div>
                      <label style="color: #888; display: block; margin-bottom: 5px;">Status:</label>
                      <strong style="color: #4ade80;">Active</strong>
                    </div>
                  </div>
                </div>

                <!-- Quick Actions -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin: 15px 0;">
                  <h4 style="margin-bottom: 15px;">Quick Actions</h4>
                  <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button onclick="createSnapshot()" class="success" style="padding: 10px 20px;">
                      📸 Create Snapshot
                    </button>
                    <button onclick="showCompleteReset()" class="danger" style="padding: 10px 20px;">
                      🔄 Complete Reset (Server + Clients)
                    </button>
                    <button onclick="showSnapshots()" style="padding: 10px 20px;">
                      📁 Manage Snapshots
                    </button>
                  </div>
                </div>

                <!-- Complete Reset Dialog -->
                <div id="resetDialog" style="display: none; background: #1a1a1a; padding: 20px; border-radius: 8px; margin: 15px 0; border: 2px solid #ef4444;">
                  <h4 style="color: #ef4444;">⚠️ Complete System Reset</h4>
                  <p style="margin: 15px 0; color: #fbbf24;">
                    This will completely reset both the server database and all connected Whisperz clients.
                  </p>
                  
                  <div style="margin: 20px 0;">
                    <label style="display: block; margin-bottom: 10px;">New Instance Name:</label>
                    <input type="text" id="newInstanceName" placeholder="e.g., production-v2" style="width: 300px; padding: 10px;">
                    <small style="display: block; color: #888; margin-top: 5px;">Leave empty to auto-generate</small>
                  </div>
                  
                  <div style="margin: 20px 0;">
                    <label>
                      <input type="checkbox" id="createBackup" checked style="margin-right: 10px;">
                      Create backup snapshot before reset
                    </label>
                  </div>
                  
                  <div style="background: #2a2a2a; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>What will happen:</strong>
                    <ul style="margin: 10px 0 0 20px; color: #fbbf24;">
                      <li>Server database will be completely cleared</li>
                      <li>All Whisperz clients will detect the change</li>
                      <li>Clients will clear their local data automatically</li>
                      <li>Server will restart (takes ~5 seconds)</li>
                      <li>All users will need to log in again</li>
                    </ul>
                  </div>
                  
                  <div style="display: flex; gap: 10px;">
                    <button onclick="executeCompleteReset()" class="danger" style="padding: 10px 20px;">
                      ⚠️ Confirm Reset
                    </button>
                    <button onclick="hideResetDialog()" style="padding: 10px 20px;">
                      Cancel
                    </button>
                  </div>
                </div>

                <!-- Snapshots Manager -->
                <div id="snapshotsDialog" style="display: none; background: #1a1a1a; padding: 20px; border-radius: 8px; margin: 15px 0;">
                  <h4>📁 Database Snapshots</h4>
                  <div id="snapshotsList" style="margin: 20px 0; max-height: 300px; overflow-y: auto;">
                    <!-- Snapshots will be loaded here -->
                  </div>
                  <button onclick="hideSnapshots()" style="padding: 10px 20px;">
                    Close
                  </button>
                </div>
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
              
              <h3 style="margin-top: 20px;">🔒 Privacy Settings</h3>
              <div class="config-item">
                <span>Privacy Mode (No Logging)</span>
                <div class="toggle ${config.privacyMode ? 'active' : ''}" onclick="toggleConfig('privacyMode', this)">
                  <div class="toggle-slider"></div>
                </div>
              </div>
              <div class="config-item">
                <span>Anonymize IP Addresses</span>
                <div class="toggle ${config.anonymizeIPs ? 'active' : ''}" onclick="toggleConfig('anonymizeIPs', this)">
                  <div class="toggle-slider"></div>
                </div>
              </div>
              <button onclick="saveConfig()" class="success" style="margin-top: 10px;">💾 Save Configuration</button>
              <button onclick="enableMaxPrivacy()" class="warning" style="margin-left: 10px;">🔐 Quick Privacy Mode</button>
              
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
          loadDatabaseStatus();
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
            updateDatabaseDisplay();
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
            enableRateLimit: document.querySelector('.toggle[onclick*="enableRateLimit"]').classList.contains('active'),
            privacyMode: document.querySelector('.toggle[onclick*="privacyMode"]')?.classList.contains('active') || false,
            anonymizeIPs: document.querySelector('.toggle[onclick*="anonymizeIPs"]')?.classList.contains('active') || false
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
            if (config.privacyMode) {
              alert('Privacy Mode enabled - No logging or tracking');
            }
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        }
        
        async function switchDatabase() {
          const selector = document.getElementById('databaseSelector');
          const database = selector.value;
          
          if (!confirm(\`Switch to \${selector.options[selector.selectedIndex].text} database? This will disconnect all peers.\`)) {
            return;
          }
          
          try {
            const response = await fetch('/admin/control/switch-database', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ database })
            });
            
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              updateDatabaseDisplay();
            } else {
              alert('Failed to switch database: ' + (data.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error switching database: ' + err.message);
          }
        }
        
        async function updateDatabaseDisplay() {
          try {
            const response = await fetch('/admin/databases', {
              headers: {
                'X-Admin-Session': adminSession
              }
            });
            
            if (response.ok) {
              const data = await response.json();
              const selector = document.getElementById('databaseSelector');
              const display = document.getElementById('currentDatabase');
              
              if (selector && display) {
                // Clear and populate selector
                selector.innerHTML = '';
                for (const [key, instance] of Object.entries(data.instances)) {
                  const option = document.createElement('option');
                  option.value = key;
                  option.textContent = instance.name;
                  if (key === data.current) {
                    option.selected = true;
                  }
                  selector.appendChild(option);
                }
                
                const currentName = data.instances[data.current]?.name || 'Unknown';
                display.textContent = \`Current: \${currentName}\`;
                
                // Store data globally for manager
                window.databaseData = data;
              }
            }
          } catch (err) {
            console.error('Error updating database display:', err);
          }
        }
        
        function toggleDatabaseManager() {
          const manager = document.getElementById('databaseManager');
          if (manager.style.display === 'none') {
            updateDatabaseManager();
            manager.style.display = 'block';
          } else {
            manager.style.display = 'none';
          }
        }
        
        function updateDatabaseManager() {
          if (!window.databaseData) return;
          
          // Update instances list
          const instancesList = document.getElementById('instancesList');
          instancesList.innerHTML = '';
          
          for (const [key, instance] of Object.entries(window.databaseData.instances)) {
            const div = document.createElement('div');
            div.style.cssText = 'padding: 8px; margin: 5px 0; background: rgba(0,0,0,0.3); border-radius: 3px; display: flex; justify-content: space-between; align-items: center;';
            
            const info = document.createElement('span');
            info.innerHTML = \`<strong>\${instance.name}</strong> (key: <code>\${key}</code>) - Path: <code>\${instance.path}</code>\`;
            div.appendChild(info);
            
            if (key !== window.databaseData.current) {
              const deleteBtn = document.createElement('button');
              deleteBtn.className = 'danger';
              deleteBtn.style.cssText = 'padding: 5px 10px; font-size: 12px;';
              deleteBtn.textContent = '🗑️ Delete';
              deleteBtn.onclick = () => removeDatabaseInstance(key);
              div.appendChild(deleteBtn);
            } else {
              const activeLabel = document.createElement('span');
              activeLabel.style.cssText = 'color: #4CAF50; font-weight: bold;';
              activeLabel.textContent = '✓ Active';
              div.appendChild(activeLabel);
            }
            
            instancesList.appendChild(div);
          }
          
          // Update existing directories
          const existingDirs = document.getElementById('existingDirs');
          existingDirs.innerHTML = '';
          
          if (window.databaseData.existingDirectories && window.databaseData.existingDirectories.length > 0) {
            window.databaseData.existingDirectories.forEach(dir => {
              const span = document.createElement('span');
              span.style.cssText = 'display: inline-block; margin: 3px 5px; padding: 3px 8px; background: rgba(0,0,0,0.3); border-radius: 3px;';
              span.textContent = dir;
              existingDirs.appendChild(span);
            });
          } else {
            existingDirs.innerHTML = '<em style="color: #999;">No data directories found</em>';
          }
        }
        
        async function addDatabaseInstance() {
          const key = document.getElementById('newInstanceKey').value.trim();
          const name = document.getElementById('newInstanceName').value.trim();
          const path = document.getElementById('newInstancePath').value.trim();
          
          if (!key || !name || !path) {
            alert('Please fill all fields');
            return;
          }
          
          if (!/^[a-z0-9_-]+$/i.test(key)) {
            alert('Key must contain only letters, numbers, hyphens and underscores');
            return;
          }
          
          try {
            const response = await fetch('/admin/databases/add', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ key, name, path })
            });
            
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              document.getElementById('newInstanceKey').value = '';
              document.getElementById('newInstanceName').value = '';
              document.getElementById('newInstancePath').value = '';
              await updateDatabaseDisplay();
              updateDatabaseManager();
            } else {
              alert('Error: ' + data.error);
            }
          } catch (err) {
            alert('Error adding instance: ' + err.message);
          }
        }
        
        async function removeDatabaseInstance(key) {
          const instance = window.databaseData.instances[key];
          if (!confirm(\`Delete database instance "\${instance.name}"?\\n\\nAlso delete the data directory "\${instance.path}"?\\n(Click OK to delete directory too, Cancel to only remove from list)\`)) {
            return;
          }
          
          const deleteDir = confirm(\`Delete the data directory "\${instance.path}" from disk?\`);
          
          try {
            const response = await fetch('/admin/databases/remove', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ key, deleteDirectory: deleteDir })
            });
            
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              await updateDatabaseDisplay();
              updateDatabaseManager();
            } else {
              alert('Error: ' + data.error);
            }
          } catch (err) {
            alert('Error removing instance: ' + err.message);
          }
        }
        
        async function clearCurrentDatabase() {
          if (!window.databaseData) {
            alert('Database information not loaded.');
            return;
          }
          
          const currentDb = window.databaseData.current;
          const dbConfig = window.databaseData.instances[currentDb];
          if (!dbConfig) {
            alert('Current database configuration not found.');
            return;
          }

          if (!confirm(\`⚠️ WARNING: Clear all data from the "\${dbConfig.name}" database?\\n\\nThis will:\\n• Delete all stored data\\n• Disconnect all peers\\n• Require server restart\\n\\nThis action cannot be undone!\`)) {
            return;
          }

          try {
            const response = await fetch('/admin/databases/clear', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              }
            });
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              if (data.requiresRestart) {
                alert('The server will restart in a moment. Please refresh the page in a few seconds.');
              }
              await updateDatabaseDisplay();
              updateDatabaseManager();
            } else {
              alert('Error clearing database: ' + (data.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error clearing database: ' + err.message);
          }
        }

        async function hardResetDatabase() {
          if (!window.databaseData) {
            alert('Database information not loaded.');
            return;
          }
          
          const selector = document.getElementById('databaseSelector');
          const selectedDb = selector ? selector.value : window.databaseData.current;
          const dbConfig = window.databaseData.instances[selectedDb];
          if (!dbConfig) {
            alert('Database configuration not found.');
            return;
          }

          if (!confirm(\`⚠️ WARNING: Hard reset the "\${dbConfig.name}" database?\\n\\nThis will:\\n• Delete the entire database directory\\n• Remove all stored data permanently\\n• Create a fresh empty database\\n• Require server restart if it's the current database\\n\\nThis action cannot be undone!\`)) {
            return;
          }

          try {
            const response = await fetch('/admin/databases/reset', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ key: selectedDb, createNew: true })
            });
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              if (data.requiresRestart) {
                alert('The server will restart in a moment. Please refresh the page in a few seconds.');
              }
              await updateDatabaseDisplay();
              updateDatabaseManager();
            } else {
              alert('Error hard resetting database: ' + (data.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error hard resetting database: ' + err.message);
          }
        }
        
        async function resetWhisperzClients() {
          // First, get current instance
          try {
            const response = await fetch('/admin/whisperz/instance', {
              headers: {
                'X-Admin-Session': adminSession
              }
            });
            const data = await response.json();
            
            const currentInstance = data.instance || 'not_set';
            
            if (!confirm(\`Reset all Whisperz clients?\\n\\nCurrent instance: \${currentInstance}\\n\\nThis will:\\n• Change the instance name\\n• Force ALL Whisperz clients to clear their data\\n• Clients will reload automatically\\n\\nThis does NOT affect server data.\`)) {
              return;
            }
            
            // Generate new instance name
            const newInstance = prompt('Enter new instance name (or leave empty for auto-generate):', \`v\${Date.now()}\`);
            
            // Set new instance
            const setResponse = await fetch('/admin/whisperz/set-instance', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ 
                instance: newInstance || \`v\${Date.now()}\` 
              })
            });
            
            const result = await setResponse.json();
            if (result.success) {
              alert(\`Success! Instance changed to: \${result.instance}\\n\\nAll Whisperz clients will now reset.\`);
            } else {
              alert('Error: ' + (result.error || 'Failed to set instance'));
            }
          } catch (err) {
            alert('Error resetting Whisperz clients: ' + err.message);
          }
        }
        
        // Enhanced Database Management Functions
        let dbSnapshots = [];
        
        async function loadDatabaseStatus() {
          try {
            // Get current instance
            const instanceRes = await fetch('/admin/whisperz/instance', {
              headers: { 'X-Admin-Session': adminSession }
            });
            const instanceData = await instanceRes.json();
            const instanceEl = document.getElementById('currentInstance');
            if (instanceEl) {
              instanceEl.textContent = instanceData.instance || 'not_set';
            }
            
            // Get snapshots
            const snapshotsRes = await fetch('/admin/database/snapshots', {
              headers: { 'X-Admin-Session': adminSession }
            });
            const snapshotsData = await snapshotsRes.json();
            dbSnapshots = snapshotsData.snapshots || [];
          } catch (err) {
            console.error('Error loading database status:', err);
          }
        }
        
        function showCompleteReset() {
          document.getElementById('resetDialog').style.display = 'block';
          document.getElementById('snapshotsDialog').style.display = 'none';
        }
        
        function hideResetDialog() {
          document.getElementById('resetDialog').style.display = 'none';
        }
        
        async function executeCompleteReset() {
          const newInstance = document.getElementById('newInstanceName').value.trim();
          const createBackup = document.getElementById('createBackup').checked;
          
          if (!confirm('Are you absolutely sure? This cannot be undone!')) {
            return;
          }
          
          try {
            const response = await fetch('/admin/database/complete-reset', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({
                newInstance: newInstance || null,
                createSnapshot: createBackup
              })
            });
            
            const result = await response.json();
            if (result.success) {
              alert(\`Reset successful!\\n\\nNew instance: \${result.newInstance}\\nServer will restart in a moment.\`);
              hideResetDialog();
            } else {
              alert('Reset failed: ' + (result.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error during reset: ' + err.message);
          }
        }
        
        async function createSnapshot() {
          const name = prompt('Snapshot name:', \`Snapshot \${new Date().toLocaleString()}\`);
          if (!name) return;
          
          const description = prompt('Description (optional):');
          
          try {
            const response = await fetch('/admin/database/snapshot', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ name, description })
            });
            
            const result = await response.json();
            if (result.success) {
              alert('Snapshot created successfully!');
              loadDatabaseStatus();
            } else {
              alert('Failed to create snapshot: ' + (result.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error creating snapshot: ' + err.message);
          }
        }
        
        function showSnapshots() {
          document.getElementById('snapshotsDialog').style.display = 'block';
          document.getElementById('resetDialog').style.display = 'none';
          renderSnapshots();
        }
        
        function hideSnapshots() {
          document.getElementById('snapshotsDialog').style.display = 'none';
        }
        
        function renderSnapshots() {
          const container = document.getElementById('snapshotsList');
          if (!container) return;
          
          if (dbSnapshots.length === 0) {
            container.innerHTML = '<p style="color: #888;">No snapshots available</p>';
            return;
          }
          
          container.innerHTML = dbSnapshots.map(snapshot => \`
            <div style="background: #2a2a2a; padding: 15px; margin: 10px 0; border-radius: 8px;">
              <div style="display: flex; justify-content: space-between; align-items: start;">
                <div>
                  <strong>\${snapshot.name}</strong>
                  <div style="color: #888; font-size: 0.9em; margin-top: 5px;">
                    \${new Date(snapshot.created).toLocaleString()}
                  </div>
                  \${snapshot.description ? \`<div style="color: #aaa; margin-top: 5px;">\${snapshot.description}</div>\` : ''}
                </div>
                <div style="display: flex; gap: 10px;">
                  <button onclick="restoreSnapshot('\${snapshot.id}')" class="warning" style="padding: 5px 10px;">
                    Restore
                  </button>
                  <button onclick="deleteSnapshot('\${snapshot.id}')" class="danger" style="padding: 5px 10px;">
                    Delete
                  </button>
                </div>
              </div>
            </div>
          \`).join('');
        }
        
        async function restoreSnapshot(snapshotId) {
          const snapshot = dbSnapshots.find(s => s.id === snapshotId);
          if (!snapshot) return;
          
          if (!confirm(\`Restore from snapshot "\${snapshot.name}"?\\n\\nThis will replace the current database and restart the server.\`)) {
            return;
          }
          
          try {
            const response = await fetch('/admin/database/restore', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ snapshotId })
            });
            
            const result = await response.json();
            if (result.success) {
              alert('Database restored! Server will restart.');
            } else {
              alert('Restore failed: ' + (result.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error restoring snapshot: ' + err.message);
          }
        }
        
        async function deleteSnapshot(snapshotId) {
          const snapshot = dbSnapshots.find(s => s.id === snapshotId);
          if (!snapshot) return;
          
          if (!confirm(\`Delete snapshot "\${snapshot.name}"?\`)) {
            return;
          }
          
          try {
            const response = await fetch(\`/admin/database/snapshot/\${snapshotId}\`, {
              method: 'DELETE',
              headers: {
                'X-Admin-Session': adminSession
              }
            });
            
            const result = await response.json();
            if (result.success) {
              alert('Snapshot deleted!');
              loadDatabaseStatus();
              renderSnapshots();
            } else {
              alert('Delete failed: ' + (result.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error deleting snapshot: ' + err.message);
          }
        }
        
        function enableMaxPrivacy() {
          if (confirm('Enable privacy mode? This will disable all logging and anonymize IPs.')) {
            // Set toggles
            document.querySelector('.toggle[onclick*="privacyMode"]')?.classList.add('active');
            document.querySelector('.toggle[onclick*="anonymizeIPs"]')?.classList.add('active');
            document.querySelector('.toggle[onclick*="enableLogging"]')?.classList.remove('active');
            // Save
            saveConfig();
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
            // Safely escape HTML to prevent XSS
            function escapeHtml(text) {
              const div = document.createElement('div');
              div.textContent = text;
              return div.innerHTML;
            }
            logViewer.innerHTML = logs.map(log => \`
              <div class="log-entry log-\${escapeHtml(log.level)}">
                <strong>\${escapeHtml(log.timestamp)}</strong> [\${escapeHtml(log.level)}] \${escapeHtml(log.message)}
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

// Initialize Gun with dynamic database path
let gun;

function initializeGun(databaseKey = 'prod') {
  // WARNING: Gun.js cannot be reinitialized on the same server without crashing
  // This function should only be called ONCE at startup
  if (gun) {
    console.warn('WARNING: Gun already initialized. Cannot reinitialize without server crash!');
    return gun;
  }
  
  const dbConfig = DATABASE_INSTANCES[databaseKey] || DATABASE_INSTANCES.prod;
  
  // Close existing Gun instance if exists (this will likely crash)
  if (gun && gun._.opt && gun._.opt.web) {
    try {
      // Disconnect all peers
      if (stats.peerMap) {
        stats.peerMap.forEach((peer, id) => {
          if (peer.wire) peer.wire.close();
        });
        stats.peerMap.clear();
      }
    } catch (err) {
      console.error('Error closing previous Gun instance:', err);
    }
  }
  
  log('info', `Initializing Gun with database: ${dbConfig.name} (${dbConfig.path})`);
  
  gun = Gun({ 
    web: server,
    radisk: true,
    localStorage: false,
    peers: [],
    axe: false,
    multicast: false,
    stats: true,
    file: dbConfig.path,  // Set the database path
    log: function(msg) {
      if (msg && typeof msg === 'object' && msg.err) {
        errorTracker.track(msg.err, 'Gun internal');
      }
    }
  });
  
  // Re-setup Gun handlers
  setupGunHandlers();
  
  config.currentDatabase = databaseKey;
  
  return gun;
}

// Initialize with default database
initializeGun(config.currentDatabase);

// Setup Gun event handlers
function setupGunHandlers() {
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
      ip: getDisplayIP(peerIp),
      rawIp: peerIp,  // Keep raw IP for security checks
      wire: peer.wire,
      connectedAt: Date.now(),
      messageCount: 0,
      bytesTransferred: 0,
      lastActivity: Date.now()
    });
    
    log('INFO', `Peer connected: ${peerId} from ${getDisplayIP(peerIp)}`);
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
}

// Cleanup interval - store reference for cleanup
const cleanupInterval = setInterval(() => {
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
function gracefulShutdown(signal) {
  log('WARN', `${signal} received, shutting down gracefully`);
  
  // Clear intervals
  clearInterval(cleanupInterval);
  
  // Close all peer connections
  for (const [peerId, peerInfo] of stats.peerMap.entries()) {
    if (peerInfo.wire) {
      peerInfo.wire.close();
    }
  }
  
  // Close server
  server.close(() => {
    log('INFO', 'Server closed successfully');
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

log('INFO', 'Gun.js relay initialized with admin controls');