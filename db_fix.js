// This is a patch file with the fixes needed for database switching

// 1. Fix the /admin/databases endpoint to show existing directories
// Replace the current endpoint (around line 200) with:

// Get database instances and existing directories
app.get("/admin/databases", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  // Check for existing data directories
  const existingDirs = [];
  const dataPattern = /^radata/;
  try {
    const files = fs.readdirSync('.');
    files.forEach(file => {
      if (dataPattern.test(file) && fs.statSync(file).isDirectory()) {
        existingDirs.push(file);
      }
    });
  } catch (err) {
    console.error('Error reading directories:', err);
  }
  
  res.json({
    instances: DATABASE_INSTANCES,
    current: config.currentDatabase,
    existingDirectories: existingDirs
  });
});

// 2. Add new endpoints after the /admin/databases endpoint:

// Add new database instance
app.post("/admin/databases/add", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { key, name, path } = req.body;
  
  if (!key || !name || !path) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  
  if (DATABASE_INSTANCES[key]) {
    return res.status(400).json({ error: "Instance key already exists" });
  }
  
  DATABASE_INSTANCES[key] = { name, path };
  log('INFO', `Added new database instance: ${key} (${name})`);
  
  res.json({ success: true, message: `Added ${name} instance` });
});

// Remove database instance
app.post("/admin/databases/remove", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const { key } = req.body;
  
  if (!key || !DATABASE_INSTANCES[key]) {
    return res.status(400).json({ error: "Instance not found" });
  }
  
  if (key === config.currentDatabase) {
    return res.status(400).json({ error: "Cannot remove current active database" });
  }
  
  delete DATABASE_INSTANCES[key];
  log('INFO', `Removed database instance: ${key}`);
  
  res.json({ success: true, message: `Removed instance` });
});

// 3. Update the UI section (replace the current Database Instance section around line 830):

              <h3>Database Instance</h3>
              <div style="margin: 10px 0;">
                <select id="databaseSelector" style="padding: 8px; margin-right: 10px;">
                  <!-- Will be populated dynamically -->
                </select>
                <span id="currentDatabase" style="margin-right: 10px;">Current: Loading...</span>
                <button onclick="switchDatabase()" class="success">🔄 Switch</button>
                <button onclick="showDatabaseManager()" style="margin-left: 10px;">⚙️ Manage</button>
              </div>
              
              <!-- Database Manager Modal -->
              <div id="databaseManager" style="display: none; margin-top: 10px; padding: 10px; border: 1px solid #444; border-radius: 5px;">
                <h4>Manage Database Instances</h4>
                
                <div style="margin: 10px 0;">
                  <h5>Existing Instances:</h5>
                  <div id="instancesList"></div>
                </div>
                
                <div style="margin: 10px 0;">
                  <h5>Add New Instance:</h5>
                  <input type="text" id="newInstanceKey" placeholder="Key (e.g., custom)" style="margin: 5px;">
                  <input type="text" id="newInstanceName" placeholder="Name (e.g., Custom DB)" style="margin: 5px;">
                  <input type="text" id="newInstancePath" placeholder="Path (e.g., radata-custom)" style="margin: 5px;">
                  <button onclick="addDatabaseInstance()" class="success">➕ Add</button>
                </div>
                
                <div style="margin: 10px 0;">
                  <h5>Existing Directories:</h5>
                  <div id="existingDirs"></div>
                </div>
                
                <button onclick="hideDatabaseManager()">✖️ Close</button>
              </div>

// 4. Update JavaScript functions (replace/add these functions):

        async function updateDatabaseDisplay() {
          try {
            const response = await fetch('/admin/databases', {
              headers: {
                'X-Admin-Session': adminSession
              }
            });
            
            if (response.ok) {
              const data = await response.json();
              const selector = document.getElementById('databaseSelector');
              const display = document.getElementById('currentDatabase');
              
              if (selector && display) {
                // Clear and populate selector
                selector.innerHTML = '';
                for (const [key, instance] of Object.entries(data.instances)) {
                  const option = document.createElement('option');
                  option.value = key;
                  option.textContent = instance.name;
                  if (key === data.current) {
                    option.selected = true;
                  }
                  selector.appendChild(option);
                }
                
                const currentName = data.instances[data.current]?.name || 'Unknown';
                display.textContent = `Current: ${currentName}`;
                
                // Store data for manager
                window.databaseData = data;
              }
            }
          } catch (err) {
            console.error('Error updating database display:', err);
          }
        }
        
        function showDatabaseManager() {
          const manager = document.getElementById('databaseManager');
          manager.style.display = 'block';
          
          // Update instances list
          const instancesList = document.getElementById('instancesList');
          instancesList.innerHTML = '';
          
          for (const [key, instance] of Object.entries(window.databaseData.instances)) {
            const div = document.createElement('div');
            div.style.margin = '5px 0';
            div.innerHTML = `
              <strong>${instance.name}</strong> (${key}) - Path: ${instance.path}
              ${key !== window.databaseData.current ? 
                `<button onclick="removeDatabaseInstance('${key}')" style="margin-left: 10px;" class="danger">🗑️ Remove</button>` : 
                ' (Active)'}
            `;
            instancesList.appendChild(div);
          }
          
          // Update existing directories
          const existingDirs = document.getElementById('existingDirs');
          existingDirs.innerHTML = '';
          
          if (window.databaseData.existingDirectories) {
            window.databaseData.existingDirectories.forEach(dir => {
              const div = document.createElement('div');
              div.textContent = `📁 ${dir}`;
              existingDirs.appendChild(div);
            });
          }
        }
        
        function hideDatabaseManager() {
          document.getElementById('databaseManager').style.display = 'none';
        }
        
        async function addDatabaseInstance() {
          const key = document.getElementById('newInstanceKey').value.trim();
          const name = document.getElementById('newInstanceName').value.trim();
          const path = document.getElementById('newInstancePath').value.trim();
          
          if (!key || !name || !path) {
            alert('Please fill all fields');
            return;
          }
          
          try {
            const response = await fetch('/admin/databases/add', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ key, name, path })
            });
            
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              document.getElementById('newInstanceKey').value = '';
              document.getElementById('newInstanceName').value = '';
              document.getElementById('newInstancePath').value = '';
              await updateDatabaseDisplay();
              showDatabaseManager();
            } else {
              alert('Error: ' + data.error);
            }
          } catch (err) {
            alert('Error adding instance: ' + err.message);
          }
        }
        
        async function removeDatabaseInstance(key) {
          if (!confirm(`Remove database instance ${key}?`)) {
            return;
          }
          
          try {
            const response = await fetch('/admin/databases/remove', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Admin-Session': adminSession
              },
              body: JSON.stringify({ key })
            });
            
            const data = await response.json();
            if (data.success) {
              alert(data.message);
              await updateDatabaseDisplay();
              showDatabaseManager();
            } else {
              alert('Error: ' + data.error);
            }
          } catch (err) {
            alert('Error removing instance: ' + err.message);
          }
        }