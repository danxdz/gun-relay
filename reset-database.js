#!/usr/bin/env node

/**
 * Database Reset Utility for GunJS
 * 
 * This script allows you to manually reset GunJS databases
 * without going through the admin interface.
 * 
 * Usage:
 *   node reset-database.js                    # Interactive mode
 *   node reset-database.js --db prod          # Reset specific database
 *   node reset-database.js --db prod --force  # Skip confirmation
 *   node reset-database.js --list             # List all databases
 *   node reset-database.js --clean-all        # Remove all database directories
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Database configurations (should match server.js)
const DATABASE_INSTANCES = {
  prod: { name: 'Production', path: 'radata' },
  test: { name: 'Test', path: 'radata-test' },
  dev: { name: 'Development', path: 'radata-dev' },
  staging: { name: 'Staging', path: 'radata-staging' }
};

// Parse command line arguments
const args = process.argv.slice(2);
const flags = {};
let currentArg = null;

for (const arg of args) {
  if (arg.startsWith('--')) {
    currentArg = arg.substring(2);
    flags[currentArg] = true;
  } else if (currentArg) {
    flags[currentArg] = arg;
    currentArg = null;
  }
}

// Utility functions
function listDatabases() {
  console.log('\n📊 Available Database Instances:\n');
  for (const [key, config] of Object.entries(DATABASE_INSTANCES)) {
    const exists = fs.existsSync(config.path);
    const status = exists ? '✅ Exists' : '❌ Not Created';
    let size = '';
    
    if (exists) {
      try {
        const stats = getDirectorySize(config.path);
        size = ` (${formatBytes(stats.size)}, ${stats.files} files)`;
      } catch (err) {
        size = ' (Unable to read size)';
      }
    }
    
    console.log(`  ${key.padEnd(10)} - ${config.name.padEnd(15)} [${config.path}] ${status}${size}`);
  }
  console.log('');
}

function getDirectorySize(dirPath) {
  let totalSize = 0;
  let fileCount = 0;
  
  function walkDir(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        walkDir(filePath);
      } else {
        totalSize += stats.size;
        fileCount++;
      }
    }
  }
  
  walkDir(dirPath);
  return { size: totalSize, files: fileCount };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function resetDatabase(key, skipConfirmation = false) {
  const dbConfig = DATABASE_INSTANCES[key];
  
  if (!dbConfig) {
    console.error(`❌ Database instance "${key}" not found.`);
    console.log('Available instances:', Object.keys(DATABASE_INSTANCES).join(', '));
    return false;
  }
  
  console.log(`\n🎯 Target Database: ${dbConfig.name} (${key})`);
  console.log(`📁 Directory Path: ${dbConfig.path}`);
  
  if (!fs.existsSync(dbConfig.path)) {
    console.log('ℹ️  Directory does not exist. Nothing to reset.');
    return true;
  }
  
  try {
    const stats = getDirectorySize(dbConfig.path);
    console.log(`📊 Current Size: ${formatBytes(stats.size)} (${stats.files} files)`);
  } catch (err) {
    console.log('📊 Unable to read directory size');
  }
  
  if (!skipConfirmation) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    return new Promise((resolve) => {
      rl.question('\n⚠️  WARNING: This will permanently delete all data! Continue? (yes/no): ', (answer) => {
        rl.close();
        
        if (answer.toLowerCase() !== 'yes' && answer.toLowerCase() !== 'y') {
          console.log('❌ Reset cancelled.');
          resolve(false);
          return;
        }
        
        performReset(dbConfig.path);
        resolve(true);
      });
    });
  } else {
    performReset(dbConfig.path);
    return true;
  }
}

function performReset(dirPath) {
  try {
    console.log(`\n🗑️  Deleting directory: ${dirPath}`);
    fs.rmSync(dirPath, { recursive: true, force: true });
    
    console.log(`📁 Creating fresh directory: ${dirPath}`);
    fs.mkdirSync(dirPath, { recursive: true });
    
    console.log('✅ Database reset successfully!');
    return true;
  } catch (err) {
    console.error(`❌ Error resetting database: ${err.message}`);
    return false;
  }
}

function cleanAllDatabases(skipConfirmation = false) {
  console.log('\n🧹 Clean All Databases\n');
  
  const existingDbs = Object.entries(DATABASE_INSTANCES)
    .filter(([key, config]) => fs.existsSync(config.path));
  
  if (existingDbs.length === 0) {
    console.log('ℹ️  No database directories found. Nothing to clean.');
    return;
  }
  
  console.log('The following databases will be deleted:');
  for (const [key, config] of existingDbs) {
    try {
      const stats = getDirectorySize(config.path);
      console.log(`  • ${config.name} (${key}): ${formatBytes(stats.size)}`);
    } catch (err) {
      console.log(`  • ${config.name} (${key}): Unable to read size`);
    }
  }
  
  if (!skipConfirmation) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    return new Promise((resolve) => {
      rl.question('\n⚠️  WARNING: This will permanently delete ALL databases! Continue? (yes/no): ', (answer) => {
        rl.close();
        
        if (answer.toLowerCase() !== 'yes' && answer.toLowerCase() !== 'y') {
          console.log('❌ Clean all cancelled.');
          resolve(false);
          return;
        }
        
        for (const [key, config] of existingDbs) {
          console.log(`\n🗑️  Cleaning ${config.name}...`);
          performReset(config.path);
        }
        
        console.log('\n✅ All databases cleaned successfully!');
        resolve(true);
      });
    });
  } else {
    for (const [key, config] of existingDbs) {
      console.log(`\n🗑️  Cleaning ${config.name}...`);
      performReset(config.path);
    }
    console.log('\n✅ All databases cleaned successfully!');
  }
}

async function interactiveMode() {
  console.log('\n🔧 GunJS Database Reset Utility\n');
  
  listDatabases();
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  const question = (prompt) => new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
  
  while (true) {
    console.log('\nOptions:');
    console.log('  1. Reset a specific database');
    console.log('  2. Clean all databases');
    console.log('  3. List databases');
    console.log('  4. Exit');
    
    const choice = await question('\nSelect an option (1-4): ');
    
    switch (choice.trim()) {
      case '1':
        const dbKey = await question('Enter database key (prod/test/dev/staging): ');
        await resetDatabase(dbKey.trim());
        break;
        
      case '2':
        await cleanAllDatabases();
        break;
        
      case '3':
        listDatabases();
        break;
        
      case '4':
        console.log('👋 Goodbye!');
        rl.close();
        return;
        
      default:
        console.log('❌ Invalid option. Please try again.');
    }
  }
}

// Main execution
async function main() {
  console.log('═══════════════════════════════════════');
  console.log('     GunJS Database Reset Utility      ');
  console.log('═══════════════════════════════════════');
  
  if (flags.list) {
    listDatabases();
  } else if (flags.db) {
    await resetDatabase(flags.db, flags.force === true);
  } else if (flags['clean-all']) {
    await cleanAllDatabases(flags.force === true);
  } else if (flags.help || flags.h) {
    console.log('\nUsage:');
    console.log('  node reset-database.js                    # Interactive mode');
    console.log('  node reset-database.js --db prod          # Reset specific database');
    console.log('  node reset-database.js --db prod --force  # Skip confirmation');
    console.log('  node reset-database.js --list             # List all databases');
    console.log('  node reset-database.js --clean-all        # Remove all database directories');
    console.log('  node reset-database.js --help             # Show this help');
  } else {
    await interactiveMode();
  }
  
  process.exit(0);
}

// Handle errors
process.on('uncaughtException', (err) => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('\n❌ Unhandled promise rejection:', err.message);
  process.exit(1);
});

// Run the script
main().catch((err) => {
  console.error('\n❌ Error:', err.message);
  process.exit(1);
});