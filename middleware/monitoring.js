/**
 * ZTS ARCHITECTURE: POLICY ENFORCEMENT POINT (PEP)
 * Aligns with NIST SP 800-207 - Continuous Session Monitoring.
 * This middleware ensures the user context (IP, Approval Status) 
 * remains within the trusted "Zero Trust" boundary during the session.
 */

const { supabase } = require('../db');

/**
 * Ensures the session is still valid and the user's context (IP, Approval Status) hasn't changed.
 * This function performs "Stateful Verification" against the database to catch
 * admin-triggered lockouts in real-time.
 */
const continuousMonitoring = async (req, res, next) => {
    // Skip if not logged in
    if (!req.session || !req.session.userId) return next();

    const currentTimespamp = Date.now();
    const lastCheck = req.session.lastDBCheck || 0;
    const CHECK_INTERVAL = 30000; // 30 seconds - Re-verify against database regularly

    // 1. IP Binding Check (Session Hijacking Prevention)
    const currentIp = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().replace('::ffff:', '');
    if (req.session.loginIP && req.session.loginIP !== currentIp) {
        console.warn(`[ZTS Security] IP Change detected for user ${req.session.username}. Session terminated.`);
        return req.session.destroy(() => res.redirect('/login?reason=ip_change'));
    }

    // 2. Stateful Database Check (Zero Latency Enforcement)
    if (currentTimespamp - lastCheck > CHECK_INTERVAL) {
        try {
            const { data: user } = await supabase
                .from('users')
                .select('status, role, active_session_token')
                .eq('id', req.session.userId)
                .single();

            if (!user || user.status === 'blocked' || user.status === 'suspended') {
                return req.session.destroy(() => res.redirect('/login?reason=account_disabled'));
            }

            // Detect concurrent logout or session invalidation
            if (req.session.sessionToken && user.active_session_token !== req.session.sessionToken) {
                return req.session.destroy(() => res.redirect('/login?reason=concurrent_logon'));
            }

            req.session.lastDBCheck = currentTimespamp;
        } catch (e) {
            // If DB fails, we proceed but log error - prefer availability over blocking on DB failure
            console.error('[ZTS PEP] Real-time verification failed:', e.message);
        }
    }

    // 3. High Risk Approval Check
    const isPublicRoute = ['/logout', '/approval-pending', '/api/session', '/login'].includes(req.path);
    if (req.session.otpVerified && req.session.isApproved === false && !isPublicRoute) {
        return res.redirect('/approval-pending');
    }

    next();
};

module.exports = { continuousMonitoring };
