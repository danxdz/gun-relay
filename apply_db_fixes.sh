#!/bin/bash

echo "Applying database management fixes..."

# 1. First backup
cp server.js server.js.backup_db

# 2. Replace the /admin/databases endpoint
sed -i '/^app\.get("\/admin\/databases"/,/^});$/c\
// Get database instances and existing directories\
app.get("/admin/databases", (req, res) => {\
  if (!isAuthenticated(req)) {\
    return res.status(401).json({ error: "Unauthorized" });\
  }\
  \
  // Check for existing data directories\
  const existingDirs = [];\
  const dataPattern = /^radata/;\
  try {\
    const files = fs.readdirSync(".");\
    files.forEach(file => {\
      if (dataPattern.test(file) && fs.statSync(file).isDirectory()) {\
        existingDirs.push(file);\
      }\
    });\
  } catch (err) {\
    console.error("Error reading directories:", err);\
  }\
  \
  res.json({\
    instances: DATABASE_INSTANCES,\
    current: config.currentDatabase,\
    existingDirectories: existingDirs\
  });\
});' server.js

# 3. Add new endpoints after /admin/databases
sed -i '/^app\.get("\/admin\/databases"/,/^});$/a\
\
// Add new database instance\
app.post("/admin/databases/add", (req, res) => {\
  if (!isAuthenticated(req)) {\
    return res.status(401).json({ error: "Unauthorized" });\
  }\
  \
  const { key, name, path } = req.body;\
  \
  if (!key || !name || !path) {\
    return res.status(400).json({ error: "Missing required fields" });\
  }\
  \
  if (DATABASE_INSTANCES[key]) {\
    return res.status(400).json({ error: "Instance key already exists" });\
  }\
  \
  DATABASE_INSTANCES[key] = { name, path };\
  log("INFO", `Added new database instance: ${key} (${name})`);\
  \
  res.json({ success: true, message: `Added ${name} instance` });\
});\
\
// Remove database instance\
app.post("/admin/databases/remove", (req, res) => {\
  if (!isAuthenticated(req)) {\
    return res.status(401).json({ error: "Unauthorized" });\
  }\
  \
  const { key } = req.body;\
  \
  if (!key || !DATABASE_INSTANCES[key]) {\
    return res.status(400).json({ error: "Instance not found" });\
  }\
  \
  if (key === config.currentDatabase) {\
    return res.status(400).json({ error: "Cannot remove current active database" });\
  }\
  \
  // Optionally delete the directory\
  const { deleteDirectory } = req.body;\
  if (deleteDirectory) {\
    const dirPath = DATABASE_INSTANCES[key].path;\
    try {\
      if (fs.existsSync(dirPath)) {\
        fs.rmSync(dirPath, { recursive: true, force: true });\
        log("INFO", `Deleted directory: ${dirPath}`);\
      }\
    } catch (err) {\
      log("ERROR", `Failed to delete directory: ${dirPath}`, err);\
    }\
  }\
  \
  delete DATABASE_INSTANCES[key];\
  log("INFO", `Removed database instance: ${key}`);\
  \
  res.json({ success: true, message: `Removed instance` });\
});' server.js

echo "Database management fixes applied!"
echo "Run: git diff server.js to see changes"