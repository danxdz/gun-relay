#!/bin/bash
# Add the /admin/databases endpoint before /admin/login
sed -i '/app.post.*admin\/login/i\
// Get database instances\
app.get("/admin/databases", (req, res) => {\
  if (!isAuthenticated(req)) {\
    return res.status(401).json({ error: "Unauthorized" });\
  }\
  \
  res.json({\
    instances: DATABASE_INSTANCES,\
    current: config.currentDatabase\
  });\
});\
' server.js
