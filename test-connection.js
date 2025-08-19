#!/usr/bin/env node

const Gun = require('gun');
require('gun/lib/webrtc');

const RELAY_URL = process.argv[2] || 'http://localhost:8765/gun';

console.log(`
╔════════════════════════════════════════════╗
║     🧪 Gun Relay Connection Test           ║
╚════════════════════════════════════════════╝
`);

console.log(`📡 Testing connection to: ${RELAY_URL}`);
console.log('⏳ Connecting...\n');

// Create Gun instance
const gun = Gun({
  peers: [RELAY_URL],
  localStorage: false,
  radisk: false
});

// Test data
const testId = `test-${Date.now()}`;
const testData = {
  message: 'Hello from test client!',
  timestamp: new Date().toISOString(),
  random: Math.random()
};

// Connection test
let connected = false;
let messageReceived = false;

// Set timeout for the test
const timeout = setTimeout(() => {
  if (!connected) {
    console.error('❌ Connection timeout - Could not connect to relay');
    process.exit(1);
  }
  if (!messageReceived) {
    console.error('❌ Message timeout - Connected but no data sync');
    process.exit(1);
  }
}, 10000);

// Test write
console.log('📝 Writing test data...');
gun.get('relay-test').get(testId).put(testData, (ack) => {
  if (ack.err) {
    console.error('❌ Write failed:', ack.err);
    clearTimeout(timeout);
    process.exit(1);
  } else {
    connected = true;
    console.log('✅ Successfully wrote data to relay');
  }
});

// Test read
console.log('👂 Listening for data...\n');
gun.get('relay-test').get(testId).on((data, key) => {
  if (data && data.message) {
    messageReceived = true;
    console.log('✅ Successfully received data:');
    console.log('   Key:', key);
    console.log('   Message:', data.message);
    console.log('   Timestamp:', data.timestamp);
    console.log('   Random:', data.random);
    
    // Test peer-to-peer messaging
    console.log('\n🔄 Testing P2P messaging...');
    
    // Create a second gun instance
    const gun2 = Gun({
      peers: [RELAY_URL],
      localStorage: false,
      radisk: false
    });
    
    // Send message from gun2
    const p2pTest = `p2p-${Date.now()}`;
    gun2.get('p2p-test').get(p2pTest).put({
      from: 'gun2',
      message: 'P2P test message',
      time: Date.now()
    });
    
    // Receive on gun1
    gun.get('p2p-test').get(p2pTest).once((data) => {
      if (data && data.from === 'gun2') {
        console.log('✅ P2P messaging works!');
        console.log('   Message:', data.message);
        console.log(`
╔════════════════════════════════════════════╗
║     ✅ ALL TESTS PASSED!                   ║
╠════════════════════════════════════════════╣
║  The relay server is working correctly     ║
║  - Connection: OK                          ║
║  - Data Write: OK                          ║
║  - Data Read: OK                           ║
║  - P2P Messaging: OK                       ║
╚════════════════════════════════════════════╝
        `);
        clearTimeout(timeout);
        
        // Cleanup test data
        gun.get('relay-test').get(testId).put(null);
        gun.get('p2p-test').get(p2pTest).put(null);
        
        setTimeout(() => process.exit(0), 1000);
      }
    });
  }
});

// Error handling
gun.on('error', (err) => {
  console.error('❌ Gun error:', err);
  clearTimeout(timeout);
  process.exit(1);
});

process.on('SIGINT', () => {
  console.log('\n⛔ Test interrupted');
  clearTimeout(timeout);
  process.exit(0);
});