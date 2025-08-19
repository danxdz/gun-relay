#!/usr/bin/env node

const http = require('http');
const https = require('https');

const RELAY_URL = process.argv[2] || 'http://localhost:8765';
const INTERVAL = parseInt(process.argv[3]) || 5000; // Default 5 seconds

console.log(`
╔════════════════════════════════════════════╗
║     📊 Gun Relay Monitor                   ║
╚════════════════════════════════════════════╝
`);

console.log(`📡 Monitoring: ${RELAY_URL}`);
console.log(`⏱️  Interval: ${INTERVAL}ms`);
console.log('Press Ctrl+C to stop\n');

let lastStats = null;
let checkCount = 0;

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function checkHealth() {
  const url = `${RELAY_URL}/api/stats`;
  const client = url.startsWith('https') ? https : http;
  
  client.get(url, (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      try {
        const stats = JSON.parse(data);
        checkCount++;
        
        // Clear console and show header
        console.clear();
        console.log(`
╔════════════════════════════════════════════╗
║     📊 Gun Relay Monitor                   ║
╚════════════════════════════════════════════╝
`);
        console.log(`📡 Monitoring: ${RELAY_URL}`);
        console.log(`🔄 Check #${checkCount} - ${new Date().toLocaleTimeString()}\n`);
        
        // Status
        console.log('═══ SERVER STATUS ═══');
        console.log(`✅ Status: ONLINE`);
        console.log(`⏱️  Uptime: ${formatUptime(stats.uptime)}`);
        console.log(`📦 Node: ${stats.system.nodeVersion}`);
        console.log(`🖥️  Platform: ${stats.system.platform}`);
        
        // Connections
        console.log('\n═══ CONNECTIONS ═══');
        console.log(`👥 Active: ${stats.connections.active}`);
        console.log(`📊 Total: ${stats.connections.total}`);
        console.log(`📈 Peak: ${stats.connections.peak}`);
        
        // Performance
        console.log('\n═══ PERFORMANCE ═══');
        console.log(`💬 Messages: ${stats.performance.messages.toLocaleString()}`);
        console.log(`📡 Data Transfer: ${formatBytes(stats.performance.bytesTransferred)}`);
        console.log(`⚡ Message Rate: ${stats.performance.messageRate.toFixed(2)}/s`);
        
        // Calculate deltas if we have previous stats
        if (lastStats) {
          const timeDelta = (Date.now() - lastStats.timestamp) / 1000;
          const messageDelta = stats.performance.messages - lastStats.performance.messages;
          const bytesDelta = stats.performance.bytesTransferred - lastStats.performance.bytesTransferred;
          
          console.log('\n═══ CURRENT ACTIVITY ═══');
          console.log(`📈 Messages/sec: ${(messageDelta / timeDelta).toFixed(2)}`);
          console.log(`📊 Bandwidth: ${formatBytes(bytesDelta / timeDelta)}/s`);
          console.log(`🔄 Connection Changes: ${stats.connections.active - lastStats.connections.active}`);
        }
        
        // System Resources
        console.log('\n═══ SYSTEM RESOURCES ═══');
        console.log(`💾 Heap Used: ${formatBytes(stats.system.memory.heapUsed)}`);
        console.log(`📊 Heap Total: ${formatBytes(stats.system.memory.heapTotal)}`);
        console.log(`🔧 External: ${formatBytes(stats.system.memory.external)}`);
        console.log(`⚙️  CPU Load: ${stats.system.cpu[0].toFixed(2)}`);
        
        // Errors
        if (stats.errors > 0) {
          console.log('\n⚠️  WARNINGS ⚠️');
          console.log(`❌ Total Errors: ${stats.errors}`);
        }
        
        // Store current stats for delta calculation
        lastStats = {
          ...stats,
          timestamp: Date.now()
        };
        
        // Show health check endpoint
        console.log('\n═══ ENDPOINTS ═══');
        console.log(`🌐 Dashboard: ${RELAY_URL}/`);
        console.log(`💚 Health: ${RELAY_URL}/health`);
        console.log(`📊 Metrics: ${RELAY_URL}/metrics`);
        console.log(`🔌 WebSocket: ${RELAY_URL.replace('http', 'ws')}/gun`);
        
        console.log('\n────────────────────────────────────────');
        console.log('Press Ctrl+C to stop monitoring');
        
      } catch (err) {
        console.error('❌ Failed to parse stats:', err.message);
      }
    });
  }).on('error', (err) => {
    checkCount++;
    console.clear();
    console.log(`
╔════════════════════════════════════════════╗
║     📊 Gun Relay Monitor                   ║
╚════════════════════════════════════════════╝
`);
    console.log(`📡 Monitoring: ${RELAY_URL}`);
    console.log(`🔄 Check #${checkCount} - ${new Date().toLocaleTimeString()}\n`);
    console.log('❌ Status: OFFLINE or UNREACHABLE');
    console.log(`Error: ${err.message}`);
    console.log('\nRetrying in', INTERVAL / 1000, 'seconds...');
  });
}

// Initial check
checkHealth();

// Set up interval
const interval = setInterval(checkHealth, INTERVAL);

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n👋 Stopping monitor...');
  clearInterval(interval);
  process.exit(0);
});

// Handle errors
process.on('uncaughtException', (err) => {
  console.error('💀 Uncaught exception:', err);
  clearInterval(interval);
  process.exit(1);
});