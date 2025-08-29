# Gun.js Relay Server

## Version 3.3.0 - Production-Ready with Whisperz Integration

A high-performance, secure relay server for Gun.js with admin controls, database management, and Whisperz chat integration.

### ✨ Key Features
- **🔄 Complete Reset System**: Clear server database and notify all connected Whisperz clients
- **🔐 Secure Admin Panel**: Password-protected dashboard with modern UI
- **📡 Instance Synchronization**: Automatic client detection of server resets
- **🎯 Auto-Disappearing Notifications**: Beautiful toast notifications instead of alerts
- **🌐 CORS Support**: Automatic support for Vercel and Render deployments
- **📊 Rate Limiting**: Protection against abuse with configurable limits
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

- `PORT` - Server port (default: 8765)
- `ADMIN_PASSWORD` - Admin panel password (default: admin123)
- `MAX_CONNECTIONS` - Maximum concurrent connections (default: 10000)
- `RATE_LIMIT_WINDOW` - Rate limit time window in ms (default: 60000)
- `MAX_REQUESTS_PER_WINDOW` - Max requests per window (default: 100)

## Admin Panel

Access the admin panel at `http://your-server:port/`

Default password: `admin123` (change this in production!)

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