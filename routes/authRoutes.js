const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const { supabase } = require('../db');
const { generateOTP, verifyOTP } = require('../services/otpService');
const { sendLoginAlertEmail, sendAnomalyAlertEmail } = require('../services/emailService');
const { calculateRisk } = require('../services/riskEngine');
const { registerDevice, findDevice, approveDevice } = require('../services/deviceService');
const { getGeoFromIP, isVPNConnection, checkImpossibleTravel, isHostingISP } = require('../services/geoService');
const { logEvent } = require('../services/auditService');
const { logSecurityEvent } = require('../services/monitorService');
const { generateCSRFToken } = require('../middleware/csrf');
const { loginLimiter, otpLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// --- Helper Functions to keep Route handlers lean ---

/**
 * Checks if the current time is within allowed working hours
 */
function isWithinWorkingHours() {
    const currentHour = new Date().getUTCHours();
    const ALLOW_START = 0;   // 12:00 AM UTC
    const ALLOW_END = 24;    // Allow all hours (adjust as needed)
    return currentHour >= ALLOW_START && currentHour < ALLOW_END;
}

/**
 * Checks if IP is explicitly blocked
 */
async function checkIPBlockList(ip, username) {
    try {
        const { data: ipRule } = await supabase
            .from('ip_rules')
            .select('action, reason')
            .eq('ip_address', ip)
            .eq('action', 'block')
            .single();

        if (ipRule) {
            await logSecurityEvent({
                event_type: 'IP_BLOCKED',
                username: username,
                ip: ip,
                details: { reason: ipRule.reason || 'IP is in block list', action: 'login_rejected' }
            });
            return { blocked: true, message: 'Access denied from your IP address.' };
        }
    } catch (e) {
        // No blocking rule found, continue
    }
    return { blocked: false };
}

/**
 * Validates device approval status for non-SuperAdmin users
 */
async function validateDevice(user, deviceResult, ip, country, browserInfo) {
    const autoApproveRoles = ['SuperAdmin'];
    const needsApproval = !autoApproveRoles.includes(user.role);

    if (deviceResult.isNew && needsApproval) {
        await logEvent(user.id, 'DEVICE_NEW', 'New device registered, pending approval', ip);
        await logSecurityEvent({
            event_type: 'DEVICE_NEW',
            user_id: user.id,
            username: user.username,
            ip: ip,
            location: country,
            device_id: deviceResult.device ? deviceResult.device.id : null,
            details: { browser: browserInfo, needs_approval: true, role: user.role }
        });
        sendAnomalyAlertEmail(user.username, ip, country, 'New device detected (needs approval)').catch(() => {});
        return { success: false, message: 'New device detected. Your device must be approved by an administrator before you can login.', devicePending: true };
    }

    if (deviceResult.isNew && !needsApproval) {
        await approveDevice(deviceResult.device.id, user.id);
        await logEvent(user.id, 'DEVICE_AUTO_APPROVED', `Device auto-approved for ${user.role}`, ip);
        await logSecurityEvent({
            event_type: 'DEVICE_NEW',
            user_id: user.id,
            username: user.username,
            ip: ip,
            location: country,
            device_id: deviceResult.device ? deviceResult.device.id : null,
            details: { browser: browserInfo, auto_approved: true, role: user.role }
        });
        sendAnomalyAlertEmail(user.username, ip, country, 'New device registered (auto-approved)').catch(() => {});
    }

    if (!deviceResult.device.approved && needsApproval) {
        await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked - device not approved', ip);
        return { success: false, message: 'Your device is pending approval. Please contact your administrator.', devicePending: true };
    }

    return { success: true };
}

/**
 * Checks for Geo-Fence violation based on department restrictions
 */
async function checkGeoFenceRestriction(user, country, ip) {
    if (!user.department) return { success: true };

    try {
        const { data: deptInfo } = await supabase
            .from('departments')
            .select('allowed_countries')
            .eq('name', user.department)
            .single();

        if (deptInfo && deptInfo.allowed_countries) {
            const allowedList = deptInfo.allowed_countries.split(',').map(c => c.trim().toLowerCase());

            if (allowedList.length > 0 && !allowedList.includes(country.toLowerCase())) {
                await logEvent(user.id, 'GEO_FENCE_VIOLATION', `Login blocked from ${country} (Department geo-fence)`, ip);
                await logSecurityEvent({
                    event_type: 'GEO_FENCE_VIOLATION',
                    user_id: user.id,
                    username: user.username,
                    ip: ip,
                    location: country,
                    risk_score: 100,
                    details: { reason: 'Country not in department allowed list', allowed: deptInfo.allowed_countries, role: user.role }
                });

                return { success: false, message: `Access denied. Logins from ${country} are not permitted for your department.` };
            }
        }
    } catch (e) {
        // Ignore if departments table doesn't have the column yet
    }
    return { success: true };
}

// --- Route Handlers ---

router.get('/login', (req, res) => {
    res.sendFile('login.html', { root: 'views' });
});

router.post('/login', loginLimiter, async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const password = req.body.password || '';
        const fingerprint = req.body.fingerprint || 'unknown';

        if (!username || !password) {
            return res.json({ success: false, message: 'Please enter username and password.' });
        }

        const rawIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
        const ip = rawIp.split(',')[0].trim().replace('::ffff:', '');

        // 1. Check Working Hours
        if (!isWithinWorkingHours()) {
            return res.json({ success: false, message: 'Access denied: Remote work access restricted during off-hours.' });
        }

        // 2. Check IP Blocklist
        const ipCheck = await checkIPBlockList(ip, username);
        if (ipCheck.blocked) {
            return res.json({ success: false, message: ipCheck.message });
        }

        // 3. Find User
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (!user) {
            logSecurityEvent({ event_type: 'LOGIN_FAILED', username: username, ip: ip, details: { reason: 'User not found' } }).catch(() => {});
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // 4. Status Checks
        if (user.status === 'blocked') {
            await logEvent(user.id, 'LOGIN_BLOCKED', 'Blocked user tried to login', ip);
            return res.json({ success: false, message: 'Your account has been blocked. Contact your administrator.' });
        }

        if (user.status === 'suspended') {
            await logEvent(user.id, 'LOGIN_SUSPENDED', 'Suspended user tried to login', ip);
            return res.json({ success: false, message: 'Your account has been suspended. Contact your administrator.' });
        }

        if (user.failed_attempts >= 5 && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_LOCKED', 'Locked account login attempt', ip);
            return res.json({ success: false, message: 'Account locked after 5 failed attempts. Contact your administrator.' });
        }

        // 5. Password Verification
        const passwordMatch = bcrypt.compareSync(password, user.password_hash);
        if (!passwordMatch) {
            const newAttempts = (user.failed_attempts || 0) + 1;
            await supabase.from('users').update({
                failed_attempts: newAttempts,
                last_failed_at: new Date().toISOString()
            }).eq('id', user.id);

            await logEvent(user.id, 'LOGIN_FAILED', `Wrong password (attempt ${newAttempts})`, ip);
            await logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                user_id: user.id,
                username: user.username,
                ip: ip,
                risk_score: newAttempts * 10,
                details: { reason: 'Wrong password', attempt: newAttempts, role: user.role }
            });
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // 6. Gather Device and Geo Info
        const parser = new UAParser(req.headers['user-agent']);
        const browserInfo = parser.getBrowser();
        const osInfo = parser.getOS();
        const geo = await getGeoFromIP(ip);
        const country = geo.country || 'Unknown';
        const vpn = isVPNConnection(ip) || geo.isProxy || isHostingISP(geo.isp || '');



        const deviceResult = await registerDevice(user.id, {
            fingerprint: fingerprint,
            browser: `${browserInfo.name || 'Unknown'} ${browserInfo.version || ''}`,
            os: `${osInfo.name || 'Unknown'} ${osInfo.version || ''}`,
            ip: ip,
            country: country
        });

        // 7. Validate Device
        const deviceValidation = await validateDevice(user, deviceResult, ip, country, req.headers['user-agent']);
        if (!deviceValidation.success) {
            return res.json(deviceValidation);
        }

        // 8. Geo-Fence Restrictions
        const geoFence = await checkGeoFenceRestriction(user, country, ip);
        if (!geoFence.success) {
            return res.json(geoFence);
        }

        // 9. Location Anomaly Check
        let isNewCountry = false;
        let isImpossibleTravel = false;

        const { data: recentLogins } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);

        if (recentLogins && recentLogins.length > 0) {
            isNewCountry = !recentLogins.some(log => log.country === country);

            const lastLogin = recentLogins[0];
            const timeDiffMinutes = (new Date() - new Date(lastLogin.login_at)) / (1000 * 60);
            isImpossibleTravel = checkImpossibleTravel(country, lastLogin.country, timeDiffMinutes);

            if (isNewCountry || isImpossibleTravel) {
                const anomalyReason = isImpossibleTravel ? 'Impossible travel detected' : 'Unrecognized login location';

                await logEvent(user.id, 'LOCATION_ANOMALY', `${anomalyReason} from ${country}`, ip);
                await logSecurityEvent({
                    event_type: 'LOCATION_ANOMALY',
                    user_id: user.id,
                    username: user.username,
                    ip: ip,
                    location: country,
                    risk_score: 100,
                    details: { reason: anomalyReason, previous_location: lastLogin.country, role: user.role }
                });
                sendAnomalyAlertEmail(user.username, ip, country, anomalyReason).catch(() => {});
            }
        }

        // 10. Calculate Risk Score
        const currentHour = new Date().getHours();
        const isUnusualHours = currentHour >= 22 || currentHour < 6;

        const risk = await calculateRisk({
            userId: user.id,
            isNewDevice: deviceResult.isNew,
            isNewCountry: isNewCountry,
            failedAttempts: user.failed_attempts || 0,
            isVPN: vpn,
            isAdminUnknownIP: false,
            role: user.role,
            isUnusualHours: isUnusualHours
        });

        if (vpn) {
            await logSecurityEvent({
                event_type: 'VPN_DETECTED',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                risk_score: risk.score,
                details: { role: user.role, risk_level: risk.level }
            });
        }

        // 11. Success Updates
        await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);

        const sessionToken = crypto.randomUUID();
        await supabase.from('users').update({ active_session_token: sessionToken }).eq('id', user.id);

        // 12. Save to Session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.department = user.department;
        req.session.riskScore = risk.score;
        req.session.riskLevel = risk.level;
        req.session.riskFactors = risk.factors;
        req.session.loginIP = ip;
        req.session.loginCountry = country;
        req.session.lastActive = Date.now();
        req.session.deviceFingerprint = fingerprint;
        req.session.sessionToken = sessionToken;

        await supabase.from('sessions_log').insert({
            user_id: user.id,
            ip: ip,
            user_agent: req.headers['user-agent'],
            browser: browserInfo.name || 'Unknown',
            os: osInfo.name || 'Unknown',
            device_fingerprint: fingerprint,
            country: country,
            risk_score: risk.score
        });

        // 13. Adaptive MFA Decision
        if (risk.score === 0) {
            req.session.otpVerified = true;
            const csrfToken = generateCSRFToken(req);

            await logEvent(user.id, 'LOGIN_SUCCESS', 'Logged in (Adaptive MFA: OTP Bypassed). Risk: Low (0)', ip);
            await logSecurityEvent({
                event_type: 'LOGIN_SUCCESS',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                risk_score: 0,
                details: { risk_level: 'Low', role: user.role, adaptive_mfa: 'bypassed', department: user.department }
            });

            sendLoginAlertEmail(user.username, ip, country).catch(() => {});

            return res.json({
                success: true,
                risk: { score: 0, level: 'Low' },
                redirect: '/dashboard',
                csrfToken: csrfToken
            });
        }

        req.session.otpVerified = false;
        await generateOTP(user.id);

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', `Password verified, OTP required. Risk: ${risk.level} (${risk.score})`, ip);
        await logSecurityEvent({
            event_type: 'OTP_SENT',
            user_id: user.id,
            username: user.username,
            ip: ip,
            location: country,
            risk_score: risk.score,
            details: { risk_level: risk.level, risk_factors: risk.factors, role: user.role }
        });

        return res.json({
            success: true,
            risk: { score: risk.score, level: risk.level },
            redirect: '/otp'
        });

    } catch (err) {
        console.error('Login error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

router.get('/otp', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile('otp.html', { root: 'views' });
});

router.post('/verify-otp', otpLimiter, async (req, res) => {
    try {
        const code = (req.body.code || '').trim();

        if (!req.session || !req.session.userId) {
            return res.json({ success: false, message: 'Session expired. Please login again.' });
        }

        const userId = req.session.userId;
        const username = req.session.username || 'unknown';
        const riskScore = req.session.riskScore || 0;
        const riskLevel = req.session.riskLevel || 'Low';
        const role = req.session.role || 'User';
        const department = req.session.department || '';
        const loginIP = req.session.loginIP || req.ip;
        const loginCountry = req.session.loginCountry || 'Unknown';

        const result = await verifyOTP(userId, code);

        if (!result.valid) {
            await logEvent(userId, 'OTP_FAILED', result.reason, req.ip);
            await logSecurityEvent({
                event_type: 'OTP_FAILED',
                user_id: userId,
                username: username,
                ip: req.ip,
                risk_score: riskScore,
                details: { reason: result.reason }
            });
            return res.json({ success: false, message: result.reason });
        }

        if (!req.session) {
            return res.json({ success: false, message: 'Session invalidated during verification due to concurrent login. Please login again.' });
        }

        req.session.otpVerified = true;
        req.session.lastActive = Date.now();

        const csrfToken = generateCSRFToken(req);

        await logEvent(userId, 'LOGIN_SUCCESS', `Logged in. Risk: ${riskLevel} (${riskScore})`, req.ip);
        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id: userId,
            username: username,
            ip: loginIP,
            location: loginCountry,
            risk_score: riskScore,
            details: { risk_level: riskLevel, role: role, department: department }
        });

        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id: userId,
            username: username,
            ip: req.ip,
            risk_score: riskScore,
            details: { role: role }
        });

        sendLoginAlertEmail(username, loginIP, loginCountry).catch(err => console.error('Failed to send alert email', err));

        req.session.save(err => {
            if (err) console.error('Session save error:', err);
            return res.json({ success: true, redirect: '/dashboard', csrfToken: csrfToken });
        });

    } catch (err) {
        console.error('OTP error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

router.get('/api/session', (req, res) => {
    if (!req.session.userId || !req.session.otpVerified) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        user: {
            id: req.session.userId,
            username: req.session.username,
            role: req.session.role,
            department: req.session.department
        },
        risk: {
            score: req.session.riskScore,
            level: req.session.riskLevel
        },
        security: {
            sessionToken: req.session.sessionToken ? 'active' : 'none',
            deviceBound: !!req.session.deviceFingerprint,
            passwordExpired: !!req.session.passwordExpired
        }
    });
});

router.get('/logout', async (req, res) => {
    try {
        if (req.session && req.session.userId) {
            const userId = req.session.userId;
            await supabase.from('users').update({ active_session_token: null }).eq('id', userId);
            await logEvent(userId, 'LOGOUT', 'User logged out', req.ip).catch(() => {});
        }

        res.clearCookie('connect.sid');

        if (req.session) {
            req.session.destroy(() => {
                res.redirect('/login');
            });
        } else {
            res.redirect('/login');
        }
    } catch (err) {
        console.error('Logout exception:', err);
        res.redirect('/login');
    }
});

module.exports = router;
