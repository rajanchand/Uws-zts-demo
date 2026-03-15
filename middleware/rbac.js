/**
 * ZTS ARCHITECTURE: POLICY ENFORCEMENT POINT (PEP)
 * This middleware aligns with NIST SP 800-207 standards.
 * Every request is intercepted here to verify Identity and Authorization 
 * before granting access to resources.
 */

const fs = require('fs');
const path = require('path');

const permsFile = path.join(__dirname, '..', 'role_permissions.json');

/**
 * Common Permission Helper: Checks if a role has a specific power
 */
function hasPermission(role, permKey) {
  if (role === 'SuperAdmin' || role === 'Owner') return true;
  try {
    const data = JSON.parse(fs.readFileSync(permsFile, 'utf8'));
    return !!(data[role] && data[role][permKey]);
  } catch (err) {
    return false;
  }
}

/**
 * Common Helper: Returns an array of strings representing all permissions for a role
 */
function getRolePermissions(role) {
  if (role === 'SuperAdmin' || role === 'Owner') {
    return ['manage_users', 'delete_users', 'reset_passwords', 'approve_devices', 'manage_depts', 'view_monitoring', 'analyze_risk', 'manage_network', 'view_posture'];
  }
  try {
    const data = JSON.parse(fs.readFileSync(permsFile, 'utf8'));
    const rolePerms = data[role] || {};
    return Object.keys(rolePerms).filter(k => rolePerms[k]);
  } catch (err) {
    return [];
  }
}


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
    if (role === 'SuperAdmin' || role === 'Owner') return next();

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
    if (role === 'SuperAdmin' || role === 'Owner') return next();

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

module.exports = { 
  requireRole, 
  requirePermission, 
  hasPermission, 
  getRolePermissions 
};
