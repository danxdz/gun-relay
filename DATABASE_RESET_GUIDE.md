# GunJS Database Reset Guide

## Overview
This guide explains how to reset and manage GunJS databases in your application. GunJS stores data in local directories (RAD/radisk storage), and sometimes you need to completely clear this data for a fresh start.

## Why Reset the Database?

- **Development/Testing**: Clear test data between development cycles
- **Corrupted Data**: Fix issues caused by corrupted database files
- **Storage Management**: Free up disk space from old/unused data
- **Instance Switching**: Clean transition between different database instances
- **Performance Issues**: Resolve performance degradation from accumulated data

## Important Notes About GunJS

⚠️ **GunJS Limitation**: GunJS cannot be fully reinitialized on the same server instance without restarting the process. This is a known limitation of the Gun library. When you reset the database, the server will automatically restart to ensure a clean state.

## Reset Methods

### Method 1: Admin Panel (Web UI)

1. **Access the Admin Panel**
   - Navigate to `http://your-server:port/admin`
   - Login with your admin password

2. **Go to Database Management**
   - Click on the "⚙️ Manage" button next to the database selector
   - The Database Management panel will open

3. **Choose Reset Option**
   
   **Option A: Clear Current Database**
   - Click "🧹 Clear Current Database"
   - Confirms the current active database
   - Deletes all data files but keeps the directory
   - Server will restart automatically

   **Option B: Hard Reset Selected Database**
   - Select a database from the dropdown
   - Click "⚠️ Hard Reset Selected Database"
   - Completely removes and recreates the database directory
   - Server will restart if it's the current database

4. **Wait for Server Restart**
   - The server will restart automatically (takes ~1-3 seconds)
   - Refresh the page after a few seconds
   - Re-login to the admin panel

### Method 2: API Endpoints

You can programmatically reset databases using the admin API:

#### Clear Current Database
```bash
curl -X POST http://localhost:3000/admin/databases/clear \
  -H "Content-Type: application/json" \
  -H "X-Admin-Session: YOUR_SESSION_TOKEN"
```

#### Reset Specific Database
```bash
curl -X POST http://localhost:3000/admin/databases/reset \
  -H "Content-Type: application/json" \
  -H "X-Admin-Session: YOUR_SESSION_TOKEN" \
  -d '{"key": "prod", "createNew": true}'
```

### Method 3: Command Line Utility

Use the `reset-database.js` utility script for manual control:

#### Interactive Mode
```bash
node reset-database.js
```
This opens an interactive menu where you can:
- Reset specific databases
- Clean all databases
- List existing databases

#### Direct Commands
```bash
# List all databases and their status
node reset-database.js --list

# Reset specific database (with confirmation)
node reset-database.js --db prod

# Reset without confirmation (use with caution!)
node reset-database.js --db prod --force

# Clean all databases
node reset-database.js --clean-all

# Show help
node reset-database.js --help
```

### Method 4: Manual Directory Deletion

For emergency situations or when other methods fail:

1. **Stop the server**
   ```bash
   # Stop your Node.js process
   pkill -f "node server.js"
   # or use your process manager
   pm2 stop server
   ```

2. **Delete database directories**
   ```bash
   # Remove specific database
   rm -rf radata
   
   # Remove all databases
   rm -rf radata*
   ```

3. **Restart the server**
   ```bash
   node server.js
   # or
   pm2 start server.js
   ```

## Database Instances

The system supports multiple database instances:

| Key | Name | Directory | Purpose |
|-----|------|-----------|---------|
| prod | Production | radata | Main production database |
| test | Test | radata-test | Testing environment |
| dev | Development | radata-dev | Development work |
| staging | Staging | radata-staging | Pre-production testing |

## Adding Custom Database Instances

You can add custom database instances through the admin panel:

1. Open Database Management panel
2. In "Add New Instance" section:
   - **Key**: Unique identifier (e.g., "backup")
   - **Name**: Display name (e.g., "Backup DB")
   - **Path**: Directory path (e.g., "radata-backup")
3. Click "Add Instance"

## Troubleshooting

### Server Won't Restart Automatically
If the server doesn't restart after a reset:
1. Manually restart the Node.js process
2. Check if you're using a process manager (pm2, forever, systemd)
3. Ensure the process manager is configured to auto-restart on exit

### Permission Errors
If you get permission errors when resetting:
```bash
# Run with appropriate permissions
sudo node reset-database.js --db prod

# Or fix directory permissions
sudo chown -R $(whoami) radata*
```

### Database Still Contains Old Data
This usually happens when:
1. The server wasn't properly restarted
2. Multiple server instances are running
3. Data is cached in memory

Solution:
1. Kill all Node.js processes: `pkill -f node`
2. Clear the database directory manually
3. Start a fresh server instance

### Cannot Switch Databases
GunJS cannot switch databases without a restart. Always use the reset functions which handle the restart automatically.

## Best Practices

1. **Always Backup Important Data**
   - Before resetting production databases, create backups
   - Use the database instance feature to maintain backups

2. **Use Different Instances for Different Environments**
   - Keep production, staging, and development data separate
   - Switch between instances as needed

3. **Regular Maintenance**
   - Periodically clean test/dev databases to save disk space
   - Monitor database directory sizes

4. **Automate Resets for Testing**
   ```bash
   # Example: Reset test database before running tests
   node reset-database.js --db test --force && npm test
   ```

5. **Process Management**
   - Use pm2 or similar for automatic restarts
   - Configure proper restart policies

## Security Considerations

- **Admin Authentication Required**: All reset operations require admin authentication
- **Confirmation Prompts**: Destructive operations require explicit confirmation
- **No Client-Side Reset**: Databases can only be reset from the server/admin side
- **Audit Logging**: All reset operations are logged in the server logs

## Example Workflows

### Development Workflow
```bash
# Start fresh development session
node reset-database.js --db dev --force
node server.js
```

### Testing Workflow
```bash
# Clean test environment before tests
node reset-database.js --db test --force
npm test
```

### Production Maintenance
1. Schedule maintenance window
2. Backup current data if needed
3. Use admin panel to reset database
4. Verify system functionality
5. Monitor logs for any issues

## Additional Commands

### Check Database Size
```bash
# Check size of database directories
du -sh radata*
```

### Monitor Database Files
```bash
# Watch database directory for changes
watch -n 1 'ls -la radata/'
```

### Backup Before Reset
```bash
# Create backup before reset
cp -r radata radata-backup-$(date +%Y%m%d)
```

## Support

If you encounter issues with database reset:
1. Check server logs for error messages
2. Ensure proper file permissions
3. Verify no other processes are using the database files
4. Try manual directory deletion as last resort

Remember: Database resets are destructive operations. Always ensure you have backups of important data before proceeding.