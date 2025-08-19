# 🔫 Gun Relay Server for Whisperz

Enhanced Gun.js relay server with admin controls, comprehensive monitoring, statistics, and security features for Whisperz P2P chat.

## ✨ Features

### 🎮 Admin Control Panel (NEW!)
- **Web-based Admin Interface** - Control everything from your browser/mobile
- **Server Controls** - Pause/resume server, maintenance mode
- **Peer Management** - Kick or ban specific peers
- **IP Management** - Ban/unban IP addresses
- **Configuration Management** - Change settings without restart
- **Real-time Log Viewer** - View logs filtered by level
- **Password Protected** - Secure admin access

## ✨ Core Features

### Core Functionality
- **Gun.js WebSocket Relay** - Enables P2P connections for mobile/NAT users
- **Zero Knowledge** - Relay cannot decrypt E2E encrypted messages
- **Auto-scaling** - Handles multiple concurrent connections efficiently
- **Private Mode** - No public peers, complete privacy

### Monitoring & Analytics
- **📊 Real-time Dashboard** - Beautiful web interface with live stats
- **📈 Performance Metrics** - Message rates, bandwidth usage, connection stats
- **🔍 Error Tracking** - Comprehensive error logging and display
- **💚 Health Checks** - `/health` endpoint for monitoring
- **📉 Prometheus Metrics** - `/metrics` endpoint for external monitoring

### Security & Reliability
- **🛡️ Rate Limiting** - Prevent abuse and DoS attacks
- **🔒 Connection Limits** - Configurable max connections
- **♻️ Auto-cleanup** - Removes inactive peers automatically
- **⚡ Graceful Shutdown** - Proper connection handling on restart

## 🚀 Quick Start

### Local Development
```bash
# Install dependencies
npm install

# Start server
npm start

# Development mode with auto-reload
npm run dev

# Test connection
npm test

# Monitor server
npm run monitor
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# With SSL/Nginx proxy
docker-compose --profile with-ssl up -d

# View logs
docker-compose logs -f gun-relay
```

## 🌐 Deploy to Cloud

### Deploy to Render.com (FREE)
1. Push code to GitHub
2. Go to [render.com](https://render.com)
3. New > Web Service > Connect repo
4. Auto-deploys with `render.yaml` config

### Deploy to Railway ($5/month)
```bash
# Install Railway CLI
npm install -g @railway/cli

# Deploy
railway login
railway init
railway up
```

### Deploy to Fly.io
```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Deploy
fly launch
fly deploy
```

## 📡 Connect from Whisperz

Add your relay URL to the Whisperz app:

```javascript
// In browser console or app settings
localStorage.setItem('GUN_CUSTOM_PEERS', 'https://your-relay.onrender.com/gun')

// Multiple relays for redundancy
localStorage.setItem('GUN_CUSTOM_PEERS', 
  'https://relay1.com/gun,https://relay2.com/gun'
)
```

## 📊 Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Web dashboard with real-time stats |
| `/gun` | WebSocket endpoint for Gun.js |
| `/health` | Health check (returns 200 if healthy) |
| `/api/stats` | JSON API for statistics |
| `/metrics` | Prometheus-compatible metrics |

## 🔧 Configuration

Environment variables:
```bash
PORT=8765                 # Server port
MAX_CONNECTIONS=1000      # Maximum concurrent connections
NODE_ENV=production       # Environment (development/production)
ADMIN_PASSWORD=admin123   # Admin panel password (CHANGE THIS!)
```

### 🔐 Admin Panel Access

1. Navigate to your server dashboard (e.g., `http://localhost:8765/`)
2. Click on "Admin Control Panel"
3. Enter the admin password (default: `admin123`)
4. Access full control features:
   - **Server Controls**: Pause/resume, maintenance mode, clear stats
   - **Peer Management**: View, kick, or ban connected peers
   - **IP Management**: Ban/unban specific IP addresses
   - **Configuration**: Change settings without server restart
   - **Logs**: View real-time logs filtered by level

**⚠️ IMPORTANT**: Change the default admin password in production!

## 📈 Monitoring

### Built-in Monitor
```bash
# Monitor local server
npm run monitor

# Monitor remote server
node monitor.js https://your-relay.com 5000
```

### Dashboard Features
- **Real-time Stats** - Auto-refreshes every 30 seconds
- **Connection Tracking** - Active peers with details
- **Performance Metrics** - Messages/sec, bandwidth usage
- **System Resources** - Memory, CPU usage
- **Error Log** - Recent errors with timestamps
- **Visual Indicators** - Status lights, progress bars

## 🧪 Testing

### Test Connection
```bash
# Test local server
npm test

# Test remote server
node test-connection.js https://your-relay.com/gun
```

### Load Testing
```bash
# Install artillery
npm install -g artillery

# Run load test
artillery quick --count 10 --num 100 ws://localhost:8765/gun
```

## 🛡️ Security

### Rate Limiting
- 100 requests per minute per IP
- Configurable connection limits
- Automatic cleanup of inactive peers

### SSL/TLS Setup
1. Place certificates in `./ssl/` directory
2. Use nginx proxy configuration
3. Deploy with `docker-compose --profile with-ssl up`

### Best Practices
- Always use HTTPS in production
- Set appropriate connection limits
- Monitor error logs regularly
- Keep Gun.js updated

## 📝 API Response Examples

### Health Check
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "activeConnections": 42,
  "recentErrors": 0
}
```

### Stats API
```json
{
  "uptime": 3600000,
  "connections": {
    "active": 42,
    "total": 1337,
    "peak": 100
  },
  "performance": {
    "messages": 50000,
    "bytesTransferred": 10485760,
    "messageRate": 13.89
  },
  "system": {
    "memory": {...},
    "cpu": [0.5, 0.3, 0.2],
    "nodeVersion": "v18.0.0"
  }
}
```

## 🐛 Troubleshooting

### Relay Not Connecting
- Check firewall rules for port 8765
- Ensure WebSocket support
- Verify CORS settings
- Check server logs

### High Memory Usage
- Reduce `MAX_CONNECTIONS`
- Enable cleanup interval
- Monitor with `npm run monitor`

### WebSocket Errors
- Ensure using `wss://` for HTTPS
- Check proxy configuration
- Verify SSL certificates

## 📚 Architecture

```
┌─────────────┐     WebSocket      ┌─────────────┐
│   Client A  │◄──────────────────►│             │
└─────────────┘                    │             │
                                   │  Gun Relay  │
┌─────────────┐     WebSocket      │   Server    │
│   Client B  │◄──────────────────►│             │
└─────────────┘                    │             │
                                   └─────────────┘
                                          │
                                    ┌─────▼─────┐
                                    │ Dashboard │
                                    └───────────┘
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open pull request

## 📄 License

MIT License - See LICENSE file for details

## 🔗 Links

- [Whisperz App](https://github.com/danxdz/Whisperz)
- [Gun.js Documentation](https://gun.eco/docs)
- [Deployment Guide](https://github.com/danxdz/Whisperz/blob/main/GUN_RELAY_SETUP.md)

## 💡 Support

For issues or questions:
- Open an issue on GitHub
- Check the error logs in dashboard
- Use `npm run monitor` for debugging

---

**Version:** 3.0.0 | **Last Updated:** January 2024