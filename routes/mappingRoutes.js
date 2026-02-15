const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { supabase } = require('../db');
const { logEvent } = require('../services/auditService');
const { getPendingDevices, approveDevice, rejectDevice, getAllDevices } = require('../services/deviceService');
const { validatePassword } = require('../middleware/passwordPolicy');
const { requireReAuth } = require('../middleware/stepUpAuth');
const { logSecurityEvent } = require('../services/monitorService');

const { requireRole, requirePermission, hasPermission } = require('../middleware/rbac');


// Centralized hasPermission logic is now imported from RBAC middleware.


const router = express.Router();

// --- Middleware ---

/**
 * Ensures the user is accessing from an approved device for sensitive admin actions.
 */
const requireApprovedDevice = async (req, res, next) => {
    if (req.session.role === 'SuperAdmin') return next();
    try {
        const { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ 
                success: false, 
                message: 'Access denied: Active Admin actions require an approved company device.' 
            });
        }
        next();
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Server error verifying device posture.' });
    }
};

// --- Pages ---

router.get('/mapping', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'mapping.html'));
});

router.get('/register-device', requirePermission('approve_devices'), (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'register-device.html'));
});

// --- User Management API ---

// Get all users
router.get('/api/mapping/users', async (req, res) => {
    // Allow if they can manage users OR if they are just monitoring
    if (!hasPermission(req.session.role, 'manage_users') && !hasPermission(req.session.role, 'view_monitoring')) {
        return res.status(403).json({ error: 'Access denied.' });
    }
    try {
        const { data: users } = await supabase
            .from('users')
            .select('id, username, role, email, department, status, failed_attempts, created_at')
            .order('id', { ascending: true });

        res.json(users || []);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Create new user
router.post('/api/mapping/users/create', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { username, password, role, email, department } = req.body;

        if (!username || !password || !role) {
            return res.json({ success: false, message: 'Username, password, and role are required.' });
        }

        // Password Policy enforcement
        const policy = validatePassword(password);
        if (!policy.valid) {
            return res.json({ success: false, message: policy.errors.join(' ') });
        }

        // Check availability
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .single();

        if (existing) {
            return res.json({ success: false, message: 'Username already exists.' });
        }

        const hash = bcrypt.hashSync(password, 10);

        const { error } = await supabase.from('users').insert({
            username,
            password_hash: hash,
            role,
            email: email || '',
            department: department || 'General',
            status: 'active'
        });

        if (error) {
            return res.json({ success: false, message: `Failed to create user: ${error.message}` });
        }

        await logEvent(req.session.userId, 'USER_CREATED', `Created user: ${username} (${role})`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_CREATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { new_user: username, role, department: department || 'General' }
        });

        res.json({ success: true, message: 'User created successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Approve device
router.post('/api/mapping/devices/approve', requirePermission('approve_devices'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { deviceId, trustLevel } = req.body;
        if (!deviceId) return res.json({ success: false });

        const adminId = req.session.userId;
        const approvedLevel = trustLevel || 'Managed';
        await approveDevice(deviceId, adminId, approvedLevel);

        const { data: target } = await supabase.from('devices').select('user_id').eq('id', deviceId).single();
        const tId = target ? target.user_id : 'unknown';

        await logEvent(adminId, 'DEVICE_APPROVED', `Approved device ${deviceId} (${approvedLevel}) for user ${tId}`, req.ip);
        await logSecurityEvent({
            event_type: 'DEVICE_APPROVED',
            user_id: adminId,
            username: req.session.username,
            ip: req.ip,
            details: { action: 'device_approved', target_device: deviceId, target_user: tId, trust_level: approvedLevel }
        });

        res.json({ success: true, message: `Device approved as ${approvedLevel}` });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Approve High Risk Login
router.post('/api/mapping/users/approve-risk', requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!hasPermission(req.session.role, 'manage_users')) {
            return res.status(403).json({ success: false, message: 'Access denied.' });
        }

        const { data: user } = await supabase.from('users').select('username, status').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        if (user.status !== 'active_pending_approval') {
            return res.json({ success: false, message: 'User is not currently pending a risk approval.' });
        }

        const { error } = await supabase
            .from('users')
            .update({ status: 'active' })
            .eq('id', userId);

        if (error) throw error;

        await logEvent(req.session.userId, 'USER_RISK_APPROVED', `Approved high-risk login for: ${user.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_RISK_APPROVED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, target_user_id: userId }
        });

        res.json({ success: true, message: `Login approved for ${user.username}.` });
    } catch (err) {
        console.error('Approve risk error:', err);
        res.status(500).json({ success: false, message: 'Server error during approval.' });
    }
});

// Delete user
router.post('/api/mapping/users/delete', requirePermission('delete_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const userId = req.body.userId;
        // Check delete_users permission from RBAC matrix
        if (!hasPermission(req.session.role, 'delete_users')) {
            return res.status(403).json({ success: false, message: 'Access denied: You do not have permission to delete users.' });
        }

        if (userId === req.session.userId) {
            return res.json({ success: false, message: 'You cannot delete your own account.' });
        }

        const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        // Cleanup dependencies
        await supabase.from('devices').update({ approved_by: null }).eq('approved_by', userId);
        await supabase.from('ip_rules').update({ created_by: null }).eq('created_by', userId);
        await supabase.from('devices').delete().eq('user_id', userId);
        await supabase.from('otp_store').delete().eq('user_id', userId);
        await supabase.from('risk_logs').delete().eq('user_id', userId);
        await supabase.from('sessions_log').delete().eq('user_id', userId);
        await supabase.from('audit_log').update({ user_id: null }).eq('user_id', userId);

        const { error } = await supabase.from('users').delete().eq('id', userId);
        if (error) return res.json({ success: false, message: `Delete failed: ${error.message}` });

        await logEvent(req.session.userId, 'USER_DELETED', `Deleted user: ${user.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_DELETED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { deleted_user: user.username, deleted_user_id: userId }
        });

        res.json({ success: true, message: `User "${user.username}" deleted.` });
    } catch (err) {
        res.status(500).json({ success: false, message: `Server error: ${err.message}` });
    }
});

// Change user role
router.post('/api/mapping/users/change-role', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId, newRole } = req.body;

        const { data: user } = await supabase.from('users').select('username, role').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ role: newRole }).eq('id', userId);

        await logEvent(req.session.userId, 'ROLE_CHANGED', `${user.username}: ${user.role} -> ${newRole}`, req.ip);
        await logSecurityEvent({
            event_type: 'ROLE_CHANGED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, target_user_id: userId, old_role: user.role, new_role: newRole }
        });

        res.json({ success: true, message: 'Role updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Edit user details
router.post('/api/mapping/users/edit', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId, username, role, email, department } = req.body;

        const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        if (username && username !== user.username) {
            const { data: existing } = await supabase.from('users').select('id').eq('username', username).single();
            if (existing && existing.id !== userId) {
                return res.json({ success: false, message: `Username "${username}" is already taken.` });
            }
        }

        const updates = {};
        if (username) updates.username = username;
        if (role) updates.role = role;
        if (email !== undefined) updates.email = email;
        if (department) updates.department = department;

        const { error } = await supabase.from('users').update(updates).eq('id', userId);
        if (error) return res.json({ success: false, message: `Update failed: ${error.message}` });

        const changes = [];
        if (username && username !== user.username) changes.push(`username: ${user.username} -> ${username}`);
        if (role) changes.push(`role: ${role}`);
        if (email !== undefined) changes.push(`email: ${email}`);
        if (department) changes.push(`dept: ${department}`);

        await logEvent(req.session.userId, 'USER_EDITED', `Edited user ID ${userId}: ${changes.join(', ')}`, req.ip);
        res.json({ success: true, message: 'User updated successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Suspend user
router.post('/api/mapping/users/suspend', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId } = req.body;

        const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'suspended' }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_SUSPENDED', `Suspended user: ${user.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, action: 'suspended' }
        });

        res.json({ success: true, message: 'User suspended.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Block user
router.post('/api/mapping/users/block', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId } = req.body;

        const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'blocked' }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_BLOCKED', `Blocked user: ${user.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, action: 'blocked' }
        });

        res.json({ success: true, message: 'User blocked.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Activate user
router.post('/api/mapping/users/activate', requirePermission('manage_users'), requireReAuth, requireApprovedDevice, async (req, res) => {
    try {
        const { userId } = req.body;

        const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'active', failed_attempts: 0 }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_ACTIVATED', `Activated user: ${user.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_UNBLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username }
        });

        res.json({ success: true, message: 'User activated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// --- Department Management ---

router.get('/api/mapping/departments', async (req, res) => {
    try {
        const { data: depts } = await supabase.from('departments').select('*').order('name');
        if (!depts) return res.json([]);

        const { data: allUsers } = await supabase.from('users').select('id, username, department');

        const userMap = {};
        const deptUserCounts = {};
        (allUsers || []).forEach(u => {
            userMap[u.id] = u.username;
            const dName = (u.department || '').toLowerCase();
            deptUserCounts[dName] = (deptUserCounts[dName] || 0) + 1;
        });

        const enriched = depts.map(d => ({
            id: d.id,
            name: d.name,
            created_at: d.created_at,
            created_by: d.created_by,
            created_by_name: d.created_by ? (userMap[d.created_by] || 'Unknown') : '-',
            head_user_id: d.head_user_id,
            head_name: d.head_user_id ? (userMap[d.head_user_id] || 'Unknown') : '-',
            total_users: deptUserCounts[d.name.toLowerCase()] || 0
        }));

        res.json(enriched);
    } catch (err) {
        console.error('Departments fetch error:', err);
        res.json([]);
    }
});

router.post('/api/mapping/departments/create', requirePermission('manage_depts'), requireApprovedDevice, async (req, res) => {
    try {
        // Permission already checked by requirePermission('manage_depts') middleware

        const name = (req.body.name || '').trim();
        if (!name) return res.json({ success: false, message: 'Department name is required.' });

        const insertData = { name, created_by: req.session.userId };
        if (req.body.head_user_id) {
            insertData.head_user_id = parseInt(req.body.head_user_id);
        }

        const { error } = await supabase.from('departments').insert(insertData);
        if (error) return res.json({ success: false, message: `Department already exists or error: ${error.message}` });

        await logEvent(req.session.userId, 'DEPT_CREATED', `Created department: ${name}`, req.ip);
        res.json({ success: true, message: 'Department created.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

router.post('/api/mapping/departments/delete', requirePermission('manage_depts'), requireApprovedDevice, async (req, res) => {
    try {
        // Permission checked by requirePermission('manage_depts') middleware

        const deptId = req.body.departmentId;

        const { data: dept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!dept) return res.json({ success: false, message: 'Department not found.' });

        await supabase.from('departments').delete().eq('id', deptId);

        await logEvent(req.session.userId, 'DEPT_DELETED', `Deleted department: ${dept.name}`, req.ip);
        res.json({ success: true, message: 'Department deleted.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Update Department Head
router.post('/api/mapping/departments/update-head', requirePermission('manage_depts'), requireApprovedDevice, async (req, res) => {
    try {
        const deptId = req.body.departmentId;
        const headUserId = req.body.head_user_id ? parseInt(req.body.head_user_id) : null;

        const { data: dept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!dept) return res.json({ success: false, message: 'Department not found.' });

        const { error } = await supabase.from('departments').update({ head_user_id: headUserId }).eq('id', deptId);
        if (error) return res.json({ success: false, message: `Update failed: ${error.message}` });

        await logEvent(req.session.userId, 'DEPT_HEAD_CHANGED', `Changed head for ${dept.name} to user ID ${headUserId}`, req.ip);
        res.json({ success: true, message: 'Department head updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// --- Device Registration / Approval ---

router.get('/api/mapping/devices/pending', requirePermission('approve_devices'), async (req, res) => {
    try {
        const devices = await getPendingDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});

router.get('/api/mapping/devices/all', requirePermission('approve_devices'), async (req, res) => {
    try {
        const devices = await getAllDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});

router.post('/api/mapping/devices/reject', requireApprovedDevice, async (req, res) => {
    try {
        const deviceId = req.body.deviceId;
        await rejectDevice(deviceId);

        await logEvent(req.session.userId, 'DEVICE_REJECTED', `Rejected device ID: ${deviceId}`, req.ip);
        res.json({ success: true, message: 'Device rejected.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
