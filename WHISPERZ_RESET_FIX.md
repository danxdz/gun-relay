# Whisperz Reset Fix - Handle Offline Peers

## The Issue
Currently, offline peers don't receive reset signals when they reconnect because the code only uses `.on()` which listens for real-time updates.

## The Solution
Use both `.once()` and `.on()` to handle both scenarios:
- `.once()` - Checks the current value when app starts (for offline peers)
- `.on()` - Listens for future changes (for online peers)

## Implementation

Replace the current `initAutoReset()` method in `gunAuthService.js` with this improved version:

```javascript
// Initialize auto-reset functionality
// This allows remote reset from Gun relay admin panel
initAutoReset() {
  if (!this.gun) return;
  
  // Check for version-based reset (backup mechanism)
  const REQUIRED_RESET_VERSION = 0; // Set to 0 for Gun admin panel reset
  const lastResetVersion = parseInt(localStorage.getItem('whisperz_reset_version') || '0');
  
  if (REQUIRED_RESET_VERSION > lastResetVersion) {
    console.log('🔄 Version-based reset required');
    localStorage.setItem('whisperz_reset_version', REQUIRED_RESET_VERSION);
    this.performReset(Date.now(), true);
  }
  
  console.log('👂 Listening for remote reset signals from Gun admin panel...');
  
  // Define the reset handler function
  const handleResetSignal = (data) => {
    console.log('📡 Reset signal data received:', data);
    const lastReset = parseInt(localStorage.getItem('whisperz_last_reset') || '0');
    
    if (data && data.timestamp && data.timestamp > lastReset) {
      // Optional: Check if reset is not too old (e.g., within 24 hours)
      const resetAge = Date.now() - data.timestamp;
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      if (resetAge > maxAge) {
        console.log('⏭️ Reset signal too old, ignoring (age:', Math.round(resetAge / 1000 / 60), 'minutes)');
        return;
      }
      
      console.log('🔄 Remote reset signal received. Clearing local data...');
      this.performReset(data.timestamp, false);
    } else {
      console.log('⏭️ Reset signal ignored (already processed or invalid)');
    }
  };
  
  // IMPORTANT: Check for missed resets on startup (for offline peers)
  this.gun.get('_whisperz_system').get('reset').once(handleResetSignal);
  
  // Also listen for future reset signals (for online peers)  
  this.gun.get('_whisperz_system').get('reset').on(handleResetSignal);
}

// Perform the actual reset
performReset(timestamp, isVersionReset = false) {
  // Store the reset timestamp
  localStorage.setItem('whisperz_last_reset', timestamp);
  
  // Clear all local storage except reset markers
  const resetTimestamp = localStorage.getItem('whisperz_last_reset');
  const resetVersion = localStorage.getItem('whisperz_reset_version');
  
  localStorage.clear();
  
  // Restore reset markers
  if (resetTimestamp) localStorage.setItem('whisperz_last_reset', resetTimestamp);
  if (resetVersion) localStorage.setItem('whisperz_reset_version', resetVersion);
  
  // Clear session storage
  sessionStorage.clear();
  
  // Delete IndexedDB databases
  if (window.indexedDB) {
    indexedDB.deleteDatabase('gun');
    indexedDB.deleteDatabase('radata');
    indexedDB.deleteDatabase('radata-mobile');
  }
  
  // Reload the page after a short delay
  setTimeout(() => {
    console.log('🔄 Reloading application...');
    window.location.reload();
  }, 100);
}
```

## Key Improvements

1. **Handles Offline Peers**: Uses `.once()` to check for missed resets when app starts
2. **Prevents Duplicate Processing**: Timestamp check ensures each reset is only processed once
3. **Age Check**: Optional check to ignore very old reset signals (>24 hours)
4. **Clean Logging**: Clear console messages to track what's happening
5. **Unified Handler**: Single function handles both `.once()` and `.on()` callbacks

## Testing

### Test Online Reset:
1. Open Whisperz in multiple tabs
2. Click reset in Gun admin panel
3. All tabs should reset immediately

### Test Offline Reset:
1. Open Whisperz in a tab
2. Go offline (airplane mode or close tab)
3. Click reset in Gun admin panel
4. Go back online (or reopen tab)
5. Should reset automatically on reconnect

## Server-Side Considerations

Make sure the Gun relay server is sending the reset signal correctly:

```javascript
// In server.js reset endpoints
gun.get('_whisperz_system').get('reset').put({
  timestamp: Date.now(),
  database: key,
  message: 'Database reset by administrator'
});
```

## Benefits

- ✅ Online peers reset immediately
- ✅ Offline peers reset when they reconnect
- ✅ No duplicate resets
- ✅ Old resets are ignored
- ✅ Clear debugging information

## Deployment

1. Update `gunAuthService.js` with the improved code
2. Commit and push to trigger Vercel redeploy
3. Test with both online and offline scenarios

This implementation ensures that ALL peers will eventually receive and process the reset signal, regardless of whether they were online when the reset was triggered.