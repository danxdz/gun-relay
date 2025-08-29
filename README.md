# Gun.js Relay Server

## Version 3.5.0 - Production-Hardened with Security Fixes

A high-performance, secure relay server for Gun.js with enterprise-grade security, comprehensive audit logging, and Whisperz chat integration. All critical security vulnerabilities have been addressed.

### ✨ Key Features
- **🔄 Complete Reset System**: Clear server database and notify all connected Whisperz clients
- **🔐 Advanced Security**: IP whitelisting, audit logging, XSS protection, CSRF tokens
- **📡 Instance Synchronization**: Automatic client detection of server resets
- **🎯 Auto-Disappearing Notifications**: Beautiful toast notifications instead of alerts
- **🌐 CORS Support**: Automatic support for Vercel and Render deployments
- **📊 Rate Limiting**: Protection against abuse with configurable limits
- **📝 Audit Logging**: Track all admin actions with detailed logs
- **🛡️ IP Whitelisting**: Restrict admin access to specific IPs
- **🔒 Security Hardened**: bcrypt passwords, session management, input validation
- **Multiple Reset Methods**: Web UI, API endpoints, and CLI utility

## Features

- 🚀 **High Performance**: Handles thousands of concurrent connections
- 📊 **Real-time Dashboard**: Monitor connections, messages, and system stats
- 🔐 **Admin Panel**: Protected admin interface with authentication
- 🗄️ **Database Management**: Switch between multiple database instances
- 🔄 **Database Reset**: Clear or hard reset databases with automatic server restart
- 🛡️ **Security**: Rate limiting, IP banning, and privacy controls
- 📝 **Comprehensive Logging**: Track errors, connections, and system events
- 🏥 **Health Monitoring**: Built-in health check endpoint
- 🐳 **Docker Ready**: Includes Dockerfile for containerized deployment

## Quick Start

### Local Development

```bash
# Install dependencies
npm install

# Start the server
npm start

# Or use development mode with auto-reload
npm run dev
```

### Database Management Options

#### Complete Reset (Server + Clients)
The most powerful feature - resets everything with one click:

1. **Via Admin Panel**:
   - Navigate to `/` (root URL) and login
   - Find the **Database Management** section
   - Click **"🔄 Complete Reset (Server + Clients)"**
   - Enter new instance name (or auto-generate)
   - Option to create backup snapshot
   - Confirm and wait for server restart

2. **What Happens**:
   - Server database is completely cleared
   - Instance name changes (e.g., "production" → "v2")
   - All Whisperz clients detect the change
   - Clients automatically clear their local data
   - Everyone starts fresh!

#### Database Snapshots
Create and restore database backups:
- **📸 Create Snapshot**: Save current state before changes
- **📁 Manage Snapshots**: View, restore, or delete snapshots
- Automatic backup option before reset

#### Manual Reset Options
```bash
# Interactive mode
npm run reset

# Direct reset
node reset-database.js --db prod --force

# List all databases
node reset-database.js --list
```

See [DATABASE_RESET_GUIDE.md](DATABASE_RESET_GUIDE.md) for detailed instructions.

### Docker Deployment

```bash
# Build the image
docker build -t gun-relay .

# Run the container
docker run -p 8765:8765 -e ADMIN_PASSWORD=your-secure-password gun-relay
```

### Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

## Configuration

### Environment Variables

```bash
# Core Settings (REQUIRED for production)
NODE_ENV=production                    # Set to 'production' for security
ADMIN_PASSWORD=your-secure-password    # Min 12 chars, no default in production
PORT=8765                              # Server port

# Security Settings
ADMIN_IP_WHITELIST=1.2.3.4,5.6.7.8    # Restrict admin access to specific IPs
AUDIT_LOG_FILE=/var/log/gun-audit.log # Persist audit logs to file
SESSION_DURATION_MS=3600000            # Session timeout (1 hour default)
ALLOWED_ORIGINS=https://example.com    # CORS whitelist (comma-separated)
FORCE_INSECURE=false                  # Only set true for local dev

# Performance & Limits
MAX_CONNECTIONS=1000                   # Maximum concurrent connections
MAX_LOGS=500                          # Maximum log entries in memory
MAX_ERRORS=100                        # Maximum error entries in memory
RATE_LIMIT_WINDOW=60000               # Rate limit window (ms)
MAX_REQUESTS_PER_WINDOW=100           # Requests per window

# Instance Management
WHISPERZ_INSTANCE=v123456             # Force specific instance name
DATA_BASE=/path/to/data                # Database directory (default: ./radata_base)
```

## Security Features

### 🔒 Security Hardening (v3.5.0)

All critical vulnerabilities have been addressed:

- **Path Traversal Protection**: Strict validation prevents file system access
- **XSS Prevention**: Safe DOM manipulation, no innerHTML with user data  
- **CORS Security**: Restrictive CORS policy, even in development
- **Input Validation**: All inputs validated, no mass assignment
- **Error Handling**: No sensitive information leaked in errors
- **Memory Protection**: Bounded logs prevent memory exhaustion
- **Session Security**: HttpOnly cookies, secure flags, session binding
- **Rate Limiting**: Protection on all sensitive endpoints
- **Audit Logging**: Complete audit trail of all admin actions
- **IP Whitelisting**: Optional IP-based access control

## Admin Panel

Access the admin panel at `https://your-server:port/`

⚠️ **Production Requirements**:
- Set `NODE_ENV=production`
- Set strong `ADMIN_PASSWORD` (min 12 chars)
- Use HTTPS (reverse proxy with SSL)
- Consider setting `ADMIN_IP_WHITELIST`

### Admin Features

- **Real-time Statistics**: Active connections, message throughput, bandwidth usage
- **Connection Management**: View and manage active peers
- **Database Control**: Switch between database instances, reset databases
- **IP Management**: Ban/unban IP addresses
- **Privacy Controls**: Enable privacy mode, anonymize IPs
- **System Monitoring**: CPU, memory, and performance metrics
- **Error Tracking**: View recent errors and logs

## API Endpoints

### Public Endpoints
- `GET /` - Admin dashboard
- `GET /health` - Health check endpoint
- `GET /gun` - Gun.js WebSocket endpoint

### Admin Endpoints (Requires Authentication)
- `POST /admin/login` - Admin authentication
- `POST /admin/action` - Execute admin actions
- `GET /admin/stats` - Get server statistics
- `GET /admin/databases` - List database instances
- `POST /admin/databases/add` - Add new database instance
- `POST /admin/databases/remove` - Remove database instance
- `POST /admin/databases/reset` - Hard reset database
- `POST /admin/databases/clear` - Clear current database

## Database Management

The server supports multiple database instances:
- **Production** (`radata`)
- **Test** (`radata-test`)
- **Development** (`radata-dev`)
- **Staging** (`radata-staging`)

You can add custom instances through the admin panel or API.

## Security

- Rate limiting per IP address
- IP banning capabilities
- Session-based admin authentication
- Optional privacy mode
- Helmet.js security headers (when available)

## Monitoring

Use the included monitoring script:

```bash
npm run monitor
```

This will continuously check the server health and display statistics.

## Testing

```bash
# Run connection test
npm test
```

## Troubleshooting

### Database Issues
- Use the reset utility for database problems
- Check [DATABASE_RESET_GUIDE.md](DATABASE_RESET_GUIDE.md) for detailed help

### Connection Issues
- Check firewall settings
- Verify Gun.js client configuration
- Monitor rate limiting in admin panel

### Performance Issues
- Monitor active connections in dashboard
- Check system resources (CPU/Memory)
- Consider increasing `MAX_CONNECTIONS`
- Use database reset if performance degrades

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.

---

**Note**: Always change the default admin password in production environments!