# 🔫 Gun.js Relay Server

A production-ready Gun.js relay server with admin dashboard, monitoring, and privacy controls.

## ✨ Features

### 🎯 Core
- **Gun.js WebSocket Relay** - P2P relay for Gun.js applications
- **Admin Dashboard** - Full control panel at `/`
- **Real-time Stats** - Monitor connections, messages, bandwidth
- **Privacy Mode** - Hide IPs and disable logging
- **Database Management** - Add/remove database instances

### 🔒 Security
- **Password Protected** - Admin panel with secure sessions
- **Rate Limiting** - Prevent abuse (100 req/min default)
- **Connection Limits** - Max concurrent connections (1000 default)
- **IP Banning** - Block malicious IPs
- **Auto-cleanup** - Remove inactive peers

### 📊 Monitoring
- **Health Check** - `/health` endpoint
- **Statistics API** - `/api/stats` endpoint
- **Metrics** - `/metrics` for Prometheus
- **Live Logs** - Filter by INFO/WARN/ERROR
- **Error Tracking** - Comprehensive error logging

## 🚀 Quick Deploy

### Deploy to Render (Recommended)
1. Fork this repo
2. Connect to [Render.com](https://render.com)
3. Create new Web Service
4. Set environment variable:
   ```
   ADMIN_PASSWORD=your_secure_password
   ```
5. Deploy! Access at `https://your-app.onrender.com`

### Local Development
```bash
# Install
npm install

# Run with custom password
ADMIN_PASSWORD=mypassword npm start

# Access
http://localhost:8765
```

## 🎮 Admin Panel

Access the admin dashboard at `/` (root URL).

### Features:
- **Server Controls** - Pause/resume, maintenance mode
- **Peer Management** - View, kick, or ban peers
- **Configuration** - Change settings live
- **Privacy Controls** - Enable privacy mode
- **Database Instances** - Manage multiple databases
- **Password Change** - Update admin password
- **Log Viewer** - Real-time filtered logs

### Default Login:
- Password: `admin123` (change immediately!)

## 🔧 Configuration

### Environment Variables
```bash
PORT=8765                    # Server port
ADMIN_PASSWORD=secure123     # Admin password (persists on Render)
MAX_CONNECTIONS=1000         # Max concurrent connections
```

### Database Instances
The server supports multiple database instances (prod/test/dev/staging) but requires restart to switch. Each instance uses separate storage.

⚠️ **Note**: Database switching may cause issues. Use "Reset Database" instead for clearing data.

## 📱 Mobile Access

The admin panel is fully mobile-optimized. Deploy to Render for access from anywhere.

### Connect from Whisperz:
```javascript
// Add to Whisperz custom peers
localStorage.setItem('GUN_CUSTOM_PEERS', 'https://your-app.onrender.com/gun')
```

## 🛡️ Privacy Features

### Privacy Mode
- Disables all logging
- Anonymizes IP addresses  
- No data persistence
- Zero-knowledge relay

### Enable Privacy:
1. Login to admin panel
2. Go to Config tab
3. Toggle "Privacy Mode"
4. Or click "Quick Privacy Mode" button

## 📈 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Admin dashboard |
| `/gun` | Gun.js WebSocket relay |
| `/health` | Health check |
| `/api/stats` | JSON statistics |
| `/metrics` | Prometheus metrics |

## ⚠️ Important Notes

1. **Set ADMIN_PASSWORD env variable** on Render for persistence
2. **Database switching** requires server restart
3. **Free Render tier** has ephemeral storage (use env vars)
4. **Privacy mode** disables logging but not connections

## 🔨 Development

### Project Structure
```
├── server.js          # Main server file
├── package.json       # Dependencies
├── README.md         # Documentation
└── .gitignore        # Git ignore rules
```

### Testing Connection
```bash
npm run test  # Test relay connection
```

## 📝 License

MIT

## 🤝 Support

For issues or questions about the Gun relay, please open an issue on GitHub.

---

Built for [Whisperz](https://github.com/danxdz/whisperz) P2P chat