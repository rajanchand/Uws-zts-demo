const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { requireRole } = require('../middleware/rbac');
const { requireReAuth } = require('../middleware/stepUpAuth');

const permsFile = path.join(__dirname, '..', 'role_permissions.json');

const names = {
  manage_users: 'User Management',
  delete_users: 'Delete Users',
  reset_passwords: 'Force Password Reset',
  approve_devices: 'Endpoint Approval',
  manage_depts: 'Department Control',
  view_monitoring: 'Real-time Monitoring',
  analyze_risk: 'Behavioral Risk Analysis',
  manage_network: 'Network Segmentation',
  view_posture: 'Security Posture View'
};

router.get('/api/rbac/matrix', async (req, res) => {
  try {
    const perms = JSON.parse(fs.readFileSync(permsFile, 'utf8'));
    const matrix = {};
    
    for (const role in perms) {
      matrix[role] = Object.entries(perms[role]).map(([key, val]) => ({
        role: role,
        permission_key: key,
        permission_name: names[key] || key,
        is_granted: val
      }));
    }
    res.json({ success: true, matrix });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post('/api/rbac/toggle', requireRole(['SuperAdmin', 'Owner']), requireReAuth, async (req, res) => {
  const { role, permission_key, is_granted } = req.body;
  if (!role || !permission_key) return res.sendStatus(400);

  try {
    const perms = JSON.parse(fs.readFileSync(permsFile, 'utf8'));
    if (!perms[role]) perms[role] = {};
    perms[role][permission_key] = !!is_granted;
    
    fs.writeFileSync(permsFile, JSON.stringify(perms, null, 2));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
