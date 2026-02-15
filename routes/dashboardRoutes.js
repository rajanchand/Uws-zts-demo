const express = require('express');
const fs = require('fs');
const path = require('path');
const { supabase } = require('../db');
const { getRiskHistory, getAllRiskHistory } = require('../services/riskEngine');
const { getUserAuditLog } = require('../services/auditService');
const { getDeviceHealth } = require('../services/deviceService');

const router = express.Router();

// Helper: check if current user's role has a specific permission
function hasPermission(role, permKey) {
    if (role === 'SuperAdmin') return true;
    try {
        const perms = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'role_permissions.json'), 'utf8'));
        return !!(perms[role] && perms[role][permKey]);
    } catch (e) {
        return false;
    }
}

// Helper to get permissions array for a role
function getRolePermissionsArray(role) {
    if (role === 'SuperAdmin') return ['manage_users', 'delete_users', 'reset_passwords', 'approve_devices', 'manage_depts', 'view_monitoring', 'analyze_risk', 'manage_network', 'view_posture'];
    try {
        const permsJSON = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'role_permissions.json'), 'utf8'));
        const rolePerms = permsJSON[role] || {};
        return Object.keys(rolePerms).filter(k => rolePerms[k]);
    } catch (e) {
        return [];
    }
}

const dashboardContent = {
    SuperAdmin: {
        title: 'Super Admin Control Centre',
        description: 'Full system access. Manage users, view all logs, monitor the platform.',
        cards: [
            { icon: 'U', title: 'User Management', description: 'View and manage user accounts', link: '/mapping' },
            { icon: 'R', title: 'System Risk', description: 'Monitor risk scores across users', link: '/risk' },
            { icon: 'A', title: 'Audit Trail', description: 'Complete security event log', link: '/mapping' },
            { icon: 'D', title: 'Device Registry', description: 'Manage registered devices', link: '/register-device' },
            { icon: 'P', title: 'Security Posture', description: 'View ZTS security configuration status', link: '#security-posture' }
        ]
    },
    HR: {
        title: 'HR Department Dashboard',
        description: 'Human Resources portal. Employee management tools.',
        cards: [
            { icon: 'E', title: 'Employee Records', description: 'View and manage employee data', link: '#' },
            { icon: 'L', title: 'Leave Management', description: 'Track leave requests', link: '#' },
            { icon: 'R', title: 'HR Reports', description: 'Generate department reports', link: '#' }
        ]
    },
    Finance: {
        title: 'Finance Department Dashboard',
        description: 'Financial operations and reporting tools.',
        cards: [
            { icon: 'B', title: 'Budget Tracker', description: 'Monitor departmental budgets', link: '#' },
            { icon: 'I', title: 'Invoices', description: 'Manage invoicing workflow', link: '#' },
            { icon: 'A', title: 'Security Audit', description: 'View user logs and activity', link: '/mapping' }
        ]
    },
    IT: {
        title: 'IT Department Dashboard',
        description: 'Infrastructure, security, and support tools.',
        cards: [
            { icon: 'S', title: 'System Health', description: 'Monitor server status', link: '#' },
            { icon: 'M', title: 'User Management', description: 'Audit roles and telemetry', link: '/mapping' },
            { icon: 'N', title: 'Network', description: 'Network management tools', link: '/network' }
        ]
    },
    CustomerSupport: {
        title: 'Customer Support Dashboard',
        description: 'Customer service management tools.',
        cards: [
            { icon: 'T', title: 'Open Tickets', description: 'View customer tickets', link: '#' },
            { icon: 'K', title: 'Knowledge Base', description: 'Internal support articles', link: '#' },
            { icon: 'F', title: 'Feedback', description: 'Customer feedback log', link: '#' }
        ]
    }
};

router.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'dashboard.html'));
});

router.get('/api/dashboard-data', async (req, res) => {
    try {
        const role = req.session.role;
        const content = dashboardContent[role] || dashboardContent.HR;

        const securityCard = { icon: 'S', title: 'My Security', description: 'View your risk score', link: '/risk' };
        const cards = content.cards.slice();
        cards.push(securityCard);

        const { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.session.userId);

        const { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint')
            .eq('user_id', req.session.userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        let isNewDevice = false;
        if (lastSession) {
            const { count: deviceCount } = await supabase
                .from('devices')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', req.session.userId)
                .eq('fingerprint', lastSession.device_fingerprint);
            isNewDevice = deviceCount === 0;
        }

        res.json({
            user: {
                username: req.session.username,
                role: req.session.role,
                department: req.session.department,
                permissions: getRolePermissionsArray(req.session.role)
            },
            dashboard: {
                title: content.title,
                description: content.description,
                cards: cards
            },
            security: {
                riskScore: req.session.riskScore || 0,
                riskLevel: req.session.riskLevel || 'Low',
                sessionCount: sessionCount || 0,
                loginContext: {
                    country: lastSession ? lastSession.country : req.session.loginCountry || 'Unknown',
                    isNewDevice: isNewDevice
                }
            }
        });
    } catch (err) {
        console.error('Dashboard data error:', err);
        res.status(500).json({ error: 'Failed to load dashboard data' });
    }
});

router.get('/api/activity', async (req, res) => {
    try {
        const logs = await getUserAuditLog(req.session.userId, 20);
        res.json(logs);
    } catch (err) {
        res.json([]);
    }
});

router.get('/risk', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'risk.html'));
});

router.get('/admin/user-details', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'user-details.html'));
});

router.get('/api/risk-data', async (req, res) => {
    try {
        const history = await getRiskHistory(req.session.userId, 20);
        const currentScore = req.session.riskScore || 0;
        const currentLevel = req.session.riskLevel || 'Low';
        const factors = req.session.riskFactors || [];

        res.json({
            currentScore: currentScore,
            currentLevel: currentLevel,
            factors: factors,
            history: history
        });
    } catch (err) {
        res.json({ currentScore: 0, currentLevel: 'Low', factors: [], history: [] });
    }
});

router.get('/api/admin-stats', async (req, res) => {
    // Check if user has any admin-level permission from the RBAC matrix
    const role = req.session.role;
    const hasAdminAccess = hasPermission(role, 'manage_users') || 
                           hasPermission(role, 'view_monitoring') ||
                           hasPermission(role, 'analyze_risk');

    if (!hasAdminAccess) {
        return res.status(403).json({ error: 'Access denied' });
    }

    // DEVICE POSTURE ENFORCEMENT
    // Check if the current device is approved (SuperAdmin bypasses this)
    if (role !== 'SuperAdmin') {
        const { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.status(403).json({ 
                error: 'Access denied: Your device is not managed or approved by IT. Admin functions restricted.' 
            });
        }
    }

    try {
        const { count: totalUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true });

        const { count: activeUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'active');

        const { count: blockedUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'blocked');

        const { count: pendingDevices } = await supabase
            .from('devices').select('*', { count: 'exact', head: true })
            .eq('approved', false);

        const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const { count: events24h } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .gte('created_at', since24h);

        const { count: loginFails } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .eq('action', 'LOGIN_FAILED')
            .gte('created_at', since24h);

        const { count: totalSessions } = await supabase
            .from('sessions_log').select('*', { count: 'exact', head: true });

        const { data: recentEvents } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(10);

        const { data: usersData } = await supabase
            .from('users')
            .select('role, status');

        const roleCount = {};
        (usersData || []).forEach(u => {
            roleCount[u.role] = (roleCount[u.role] || 0) + 1;
        });

        res.json({
            users: {
                total:   totalUsers   || 0,
                active:  activeUsers  || 0,
                blocked: blockedUsers || 0
            },
            devices: {
                pendingApproval: pendingDevices || 0
            },
            activity: {
                events24h:    events24h    || 0,
                loginFails24h: loginFails  || 0,
                totalSessions: totalSessions || 0
            },
            roleBreakdown: roleCount,
            recentEvents: recentEvents || []
        });

    } catch (err) {
        console.error('Admin stats error:', err);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// ============================================================
// SUPERADMIN: View other users' audit log, risk, login history, device health
// ============================================================

// SuperAdmin: View any user's audit log
router.get('/api/admin/user/:userId/audit-log', async (req, res) => {
    if (!hasPermission(req.session.role, 'view_monitoring')) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const targetId = parseInt(req.params.userId);
        if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user ID' });

        // Verify target user exists
        const { data: targetUser } = await supabase
            .from('users')
            .select('id, username, role, department')
            .eq('id', targetId)
            .single();

        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        const logs = await getUserAuditLog(targetId, parseInt(req.query.limit) || 50);

        res.json({
            user: {
                id: targetUser.id,
                username: targetUser.username,
                role: targetUser.role,
                department: targetUser.department
            },
            logs: logs
        });
    } catch (err) {
        console.error('Admin audit log error:', err);
        res.status(500).json({ error: 'Failed to load audit log' });
    }
});

// SuperAdmin: View any user's risk data
router.get('/api/admin/user/:userId/risk-data', async (req, res) => {
    if (!hasPermission(req.session.role, 'analyze_risk')) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const targetId = parseInt(req.params.userId);
        if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user ID' });

        const { data: targetUser } = await supabase
            .from('users')
            .select('id, username, role, department, status')
            .eq('id', targetId)
            .single();

        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        // Get full risk history for this user
        const history = await getRiskHistory(targetId, parseInt(req.query.limit) || 30);

        // Get latest risk entry for current score/factors
        let currentScore = 0;
        let currentLevel = 'Low';
        let currentFactors = [];

        if (history && history.length > 0) {
            const latest = history[0];
            currentScore = latest.score || 0;
            currentLevel = latest.level || 'Low';
            try {
                currentFactors = typeof latest.factors_json === 'string'
                    ? JSON.parse(latest.factors_json)
                    : (latest.factors_json || []);
            } catch (e) {
                currentFactors = [];
            }
        }

        res.json({
            user: {
                id: targetUser.id,
                username: targetUser.username,
                role: targetUser.role,
                department: targetUser.department,
                status: targetUser.status
            },
            currentScore: currentScore,
            currentLevel: currentLevel,
            factors: currentFactors,
            history: history
        });
    } catch (err) {
        console.error('Admin risk data error:', err);
        res.status(500).json({ error: 'Failed to load risk data' });
    }
});

// SuperAdmin: View any user's login history & sessions
router.get('/api/admin/user/:userId/login-history', async (req, res) => {
    if (!hasPermission(req.session.role, 'view_monitoring')) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const targetId = parseInt(req.params.userId);
        if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user ID' });

        const { data: targetUser } = await supabase
            .from('users')
            .select('id, username, role, department')
            .eq('id', targetId)
            .single();

        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        const limit = parseInt(req.query.limit) || 50;

        const { data: sessions } = await supabase
            .from('sessions_log')
            .select('*')
            .eq('user_id', targetId)
            .order('login_at', { ascending: false })
            .limit(limit);

        // Compute summary stats
        const allSessions = sessions || [];
        const countries = [...new Set(allSessions.map(s => s.country).filter(Boolean))];
        const browsers = [...new Set(allSessions.map(s => s.browser).filter(Boolean))];
        const avgRisk = allSessions.length > 0
            ? Math.round(allSessions.reduce((sum, s) => sum + (s.risk_score || 0), 0) / allSessions.length)
            : 0;

        res.json({
            user: {
                id: targetUser.id,
                username: targetUser.username,
                role: targetUser.role,
                department: targetUser.department
            },
            summary: {
                totalSessions: allSessions.length,
                uniqueCountries: countries,
                uniqueBrowsers: browsers,
                averageRiskScore: avgRisk
            },
            sessions: allSessions
        });
    } catch (err) {
        console.error('Admin login history error:', err);
        res.status(500).json({ error: 'Failed to load login history' });
    }
});

// SuperAdmin: View any user's device health
router.get('/api/admin/user/:userId/device-health', async (req, res) => {
    if (!hasPermission(req.session.role, 'view_posture')) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const targetId = parseInt(req.params.userId);
        if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user ID' });

        const { data: targetUser } = await supabase
            .from('users')
            .select('id, username, role, department')
            .eq('id', targetId)
            .single();

        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        const health = await getDeviceHealth(targetId);

        res.json({
            user: {
                id: targetUser.id,
                username: targetUser.username,
                role: targetUser.role,
                department: targetUser.department
            },
            deviceHealth: health
        });
    } catch (err) {
        console.error('Admin device health error:', err);
        res.status(500).json({ error: 'Failed to load device health' });
    }
});

module.exports = router;
