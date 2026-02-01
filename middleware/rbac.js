const fs = require('fs');
const path = require('path');

const permsFile = path.join(__dirname, '..', 'role_permissions.json');

function getPermissions() {
  try {
    return JSON.parse(fs.readFileSync(permsFile, 'utf8'));
  } catch (err) {
    return {};
  }
}

// check role
function requireRole(roles) {
  if (typeof roles === 'string') roles = [roles];

  return function (req, res, next) {
    const role = req.session.role;
    if (role === 'SuperAdmin') return next();

    if (!roles.includes(role)) {
      return res.status(403).send(`
        <div style="text-align:center; padding:50px; font-family:sans-serif;">
          <h1>Access Denied</h1>
          <p>Your role (${role}) cannot access this page.</p>
          <a href="/dashboard">Return to Dashboard</a>
        </div>
      `);
    }
    next();
  };
}

// check specific permission
function requirePermission(key) {
  return function (req, res, next) {
    const role = req.session.role;
    if (role === 'SuperAdmin') return next();

    const perms = getPermissions();
    const rolePerms = perms[role] || {};

    if (!rolePerms[key]) {
      return res.status(403).send(`
        <div style="text-align:center; padding:50px; font-family:sans-serif;">
          <h1>Access Denied</h1>
          <p>You need "${key}" permission for this action.</p>
          <a href="/dashboard">Return to Dashboard</a>
        </div>
      `);
    }
    next();
  };
}

module.exports = { requireRole, requirePermission };
