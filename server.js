const Gun = require('gun');
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8765;

// Enable CORS for all origins
app.use(cors());

// Serve Gun
app.use(Gun.serve);

// Health check endpoint
app.get('/', (req, res) => {
  res.send(`
    <h1>🔫 Gun Relay Server Active</h1>
    <p>Status: ✅ Running</p>
    <p>Port: ${PORT}</p>
    <p>WebSocket endpoint: wss://${req.get('host')}/gun</p>
    <hr>
    <p>Add this to your Whisperz app:</p>
    <code>localStorage.setItem('GUN_CUSTOM_PEERS', 'https://${req.get('host')}/gun')</code>
  `);
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Gun relay server running on port ${PORT}`);
  console.log(`📡 WebSocket endpoint: ws://localhost:${PORT}/gun`);
});

// Initialize Gun with the server
const gun = Gun({ 
  web: server,
  radisk: true, // Enable storage
  localStorage: false, // Disable in Node.js
  peers: [] // No default peers - pure relay
});

// Optional: Log connections
gun.on('hi', peer => {
  console.log('👋 Peer connected:', peer.url || 'direct');
});

gun.on('bye', peer => {
  console.log('👻 Peer disconnected:', peer.url || 'direct');
});

console.log('✅ Gun.js relay initialized');
console.log('🔒 No public peers - private relay mode');