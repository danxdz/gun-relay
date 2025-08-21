/**
 * Simple Reset Approach for GunJS
 * 
 * The problem: Gun cannot properly write data while being reset
 * The solution: Use a two-phase approach
 */

const fs = require('fs');
const path = require('path');

class SimpleReset {
  constructor() {
    this.instanceFile = 'current-instance.json';
  }

  // Save instance to a separate file (not in Gun DB)
  saveInstance(instanceName) {
    try {
      const data = {
        instance: instanceName,
        timestamp: Date.now(),
        resetBy: 'admin'
      };
      fs.writeFileSync(this.instanceFile, JSON.stringify(data, null, 2));
      return true;
    } catch (err) {
      console.error('Error saving instance:', err);
      return false;
    }
  }

  // Load instance from file
  loadInstance() {
    try {
      if (fs.existsSync(this.instanceFile)) {
        const data = JSON.parse(fs.readFileSync(this.instanceFile, 'utf8'));
        return data.instance;
      }
    } catch (err) {
      console.error('Error loading instance:', err);
    }
    return 'production'; // Default
  }

  // Clear the Gun database
  clearDatabase() {
    const dbPath = 'radata';
    try {
      if (fs.existsSync(dbPath)) {
        // Remove all files in the directory
        const files = fs.readdirSync(dbPath);
        for (const file of files) {
          const filePath = path.join(dbPath, file);
          if (fs.statSync(filePath).isDirectory()) {
            fs.rmSync(filePath, { recursive: true, force: true });
          } else {
            fs.unlinkSync(filePath);
          }
        }
        console.log('Database cleared successfully');
        return true;
      }
    } catch (err) {
      console.error('Error clearing database:', err);
      return false;
    }
    return true;
  }

  // Perform reset
  async reset(newInstance) {
    // Step 1: Save new instance to file
    this.saveInstance(newInstance);
    
    // Step 2: Clear Gun database
    this.clearDatabase();
    
    // Step 3: Server will restart and read the new instance
    return {
      success: true,
      instance: newInstance,
      message: 'Reset complete. Server restarting...'
    };
  }
}

module.exports = SimpleReset;