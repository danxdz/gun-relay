/**
 * Enhanced Database Manager for Gun Relay
 * Handles both server database and client instance management
 */

const fs = require('fs');
const path = require('path');

class DatabaseManager {
  constructor() {
    this.snapshotsFile = 'database-snapshots.json';
    this.currentDatabase = 'production';
    this.snapshots = this.loadSnapshots();
  }

  // Load saved snapshots from disk
  loadSnapshots() {
    try {
      if (fs.existsSync(this.snapshotsFile)) {
        return JSON.parse(fs.readFileSync(this.snapshotsFile, 'utf8'));
      }
    } catch (err) {
      console.error('Error loading snapshots:', err);
    }
    return {};
  }

  // Save snapshots to disk
  saveSnapshots() {
    try {
      fs.writeFileSync(this.snapshotsFile, JSON.stringify(this.snapshots, null, 2));
      return true;
    } catch (err) {
      console.error('Error saving snapshots:', err);
      return false;
    }
  }

  // Create a snapshot of current database
  createSnapshot(name, description = '') {
    const timestamp = Date.now();
    const snapshotId = `snapshot_${timestamp}`;
    const currentPath = 'radata';
    const snapshotPath = `snapshots/${snapshotId}`;

    try {
      // Create snapshots directory if it doesn't exist
      if (!fs.existsSync('snapshots')) {
        fs.mkdirSync('snapshots');
      }

      // Copy current database to snapshot
      if (fs.existsSync(currentPath)) {
        this.copyDirectory(currentPath, snapshotPath);
      }

      // Save snapshot metadata
      this.snapshots[snapshotId] = {
        id: snapshotId,
        name: name,
        description: description,
        path: snapshotPath,
        created: timestamp,
        size: this.getDirectorySize(snapshotPath)
      };

      this.saveSnapshots();
      return snapshotId;
    } catch (err) {
      console.error('Error creating snapshot:', err);
      return null;
    }
  }

  // Restore from a snapshot
  restoreSnapshot(snapshotId) {
    const snapshot = this.snapshots[snapshotId];
    if (!snapshot) {
      throw new Error('Snapshot not found');
    }

    const currentPath = 'radata';
    const backupPath = `radata_backup_${Date.now()}`;

    try {
      // Backup current database
      if (fs.existsSync(currentPath)) {
        fs.renameSync(currentPath, backupPath);
      }

      // Restore from snapshot
      this.copyDirectory(snapshot.path, currentPath);

      // Clean up old backup after successful restore
      setTimeout(() => {
        if (fs.existsSync(backupPath)) {
          fs.rmSync(backupPath, { recursive: true, force: true });
        }
      }, 5000);

      return true;
    } catch (err) {
      // Rollback on error
      if (fs.existsSync(backupPath)) {
        if (fs.existsSync(currentPath)) {
          fs.rmSync(currentPath, { recursive: true, force: true });
        }
        fs.renameSync(backupPath, currentPath);
      }
      throw err;
    }
  }

  // Delete a snapshot
  deleteSnapshot(snapshotId) {
    const snapshot = this.snapshots[snapshotId];
    if (!snapshot) {
      return false;
    }

    try {
      // Delete snapshot directory
      if (fs.existsSync(snapshot.path)) {
        fs.rmSync(snapshot.path, { recursive: true, force: true });
      }

      // Remove from metadata
      delete this.snapshots[snapshotId];
      this.saveSnapshots();
      return true;
    } catch (err) {
      console.error('Error deleting snapshot:', err);
      return false;
    }
  }

  // List all snapshots
  listSnapshots() {
    return Object.values(this.snapshots).sort((a, b) => b.created - a.created);
  }

  // Complete reset - clears server DB and triggers client reset
  async completeReset(gun, newInstance) {
    const resetData = {
      timestamp: Date.now(),
      previousInstance: this.currentDatabase,
      newInstance: newInstance,
      serverCleared: false,
      clientsNotified: false
    };

    try {
      // Step 1: Clear server database
      const currentPath = 'radata';
      if (fs.existsSync(currentPath)) {
        fs.rmSync(currentPath, { recursive: true, force: true });
        fs.mkdirSync(currentPath);
      }
      resetData.serverCleared = true;

      // Step 2: Set new instance for Whisperz clients
      if (gun) {
        gun.get('_whisperz_system').get('config').put({
          instance: newInstance,
          timestamp: Date.now(),
          resetBy: 'admin'
        });
        resetData.clientsNotified = true;
      }

      // Step 3: Update current instance
      this.currentDatabase = newInstance;

      return resetData;
    } catch (err) {
      console.error('Error during complete reset:', err);
      throw err;
    }
  }

  // Helper: Copy directory recursively
  copyDirectory(src, dest) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }

    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);

      if (entry.isDirectory()) {
        this.copyDirectory(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }

  // Helper: Get directory size
  getDirectorySize(dirPath) {
    let totalSize = 0;
    
    if (!fs.existsSync(dirPath)) {
      return 0;
    }

    const files = fs.readdirSync(dirPath);
    for (const file of files) {
      const filePath = path.join(dirPath, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        totalSize += this.getDirectorySize(filePath);
      } else {
        totalSize += stats.size;
      }
    }
    
    return totalSize;
  }

  // Format bytes to human readable
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

module.exports = DatabaseManager;