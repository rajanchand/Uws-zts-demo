/**
 * ZTS ARCHITECTURE: POLICY ENGINE (PE)
 * This engine maps directly to the NIST SP 800-207 "Policy Engine."
 * It evaluates user, device, and environmental attributes to 
 * determine a real-time risk score and access decision.
 */

const { supabase } = require('../db');
const { logSecurityEvent } = require('../services/monitorService');

const RISK_WEIGHTS = {
    NEW_DEVICE: 30,
    NEW_COUNTRY: 30,
    MULTIPLE_FAILURES: 20,
    VPN_ANONYMIZER: 40,
    UNUSUAL_HOURS: 10,
    ADMIN_UNKNOWN_IP: 40,
    IMPOSSIBLE_TRAVEL: 60,   // Distinction item: High-velocity travel detected
    OFFICE_REWARD: -20       // Distinction item: Subtracted if from corporate IP
};

function getRiskLevel(score) {
    if (score <= 20) return 'Low'; // Standard office login should be very low
    if (score <= 55) return 'Medium';
    return 'High';
}

// Calculate dynamically requested risk
// params: { userId, isNewDevice, isNewCountry, failedAttempts, isVPN, isAdminUnknownIP, role, isUnusualHours, isImpossibleTravel, isOfficeIP }
async function calculateRisk(params) {
    let score = 0;
    const factors = [];

    // 0. Network Reliability (Distinction Feature)
    if (params.isOfficeIP) {
        score += RISK_WEIGHTS.OFFICE_REWARD;
        factors.push({ factor: 'Secure Corporate Network', points: RISK_WEIGHTS.OFFICE_REWARD });
    }

    // 1. Device Trust
    if (params.isNewDevice) {
        score += RISK_WEIGHTS.NEW_DEVICE;
        factors.push({ factor: 'New Device Detected', points: RISK_WEIGHTS.NEW_DEVICE });
    }

    // 2. Location Anomaly
    if (params.isNewCountry) {
        score += RISK_WEIGHTS.NEW_COUNTRY;
        factors.push({ factor: 'New Country / Location', points: RISK_WEIGHTS.NEW_COUNTRY });
    }

    // 3. Authentication Behavior
    if (params.failedAttempts >= 3) {
        score += RISK_WEIGHTS.MULTIPLE_FAILURES; // Changed from FAILED_LOGINS
        factors.push({ factor: `Multiple Failed Logins (${params.failedAttempts})`, points: RISK_WEIGHTS.MULTIPLE_FAILURES });
    }

    // 4. Network Context
    if (params.isVPN) {
        score += RISK_WEIGHTS.VPN_ANONYMIZER; // Changed from VPN_DETECTED
        factors.push({ factor: 'VPN Connection Detected', points: RISK_WEIGHTS.VPN_ANONYMIZER });
    }

    // 5. Privileged Access
    if (params.isAdminUnknownIP && (params.role === 'SuperAdmin' || params.role === 'IT')) {
        score += RISK_WEIGHTS.ADMIN_UNKNOWN_IP;
        factors.push({ factor: 'Admin Login from Unknown IP', points: RISK_WEIGHTS.ADMIN_UNKNOWN_IP });
    }

    // 6. Remote Work Context: Working Hours Anomaly
    if (params.isUnusualHours) {
        score += RISK_WEIGHTS.UNUSUAL_HOURS;
        factors.push({ factor: 'Login outside typical business hours', points: RISK_WEIGHTS.UNUSUAL_HOURS });
    }

    // 7. Behavioral Anomaly: Impossible Travel
    if (params.isImpossibleTravel) {
        score += RISK_WEIGHTS.IMPOSSIBLE_TRAVEL;
        factors.push({ factor: 'Impossible Travel (Velocity Violation)', points: RISK_WEIGHTS.IMPOSSIBLE_TRAVEL });
    }

    // Handle score bounds
    if (score > 100) score = 100;
    if (score < 0) score = 0;

    const level = getRiskLevel(score);

    await supabase.from('risk_logs').insert({
        user_id: params.userId,
        score: score,
        level: level,
        factors_json: JSON.stringify(factors)
    });

    if (score > 0) {
        logSecurityEvent({
            event_type: 'RISK_SCORE_CHANGED',
            user_id: params.userId,
            username: params.username || '',
            ip: params.ip || '',
            risk_score: score,
            details: { level: level, factors: factors, role: params.role }
        }).catch(() => { });
    }

    return { score, level, factors };
}

async function getRiskHistory(userId, limit = 20) {
    const { data } = await supabase
        .from('risk_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);

    return data || [];
}

async function getAllRiskHistory(limit = 50) {
    const { data: logs } = await supabase
        .from('risk_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs || !logs.length) return [];

    const userIds = [];
    logs.forEach(r => {
        if (r.user_id && !userIds.includes(r.user_id)) userIds.push(r.user_id);
    });

    const userMap = {};
    if (userIds.length > 0) {
        const { data: users } = await supabase.from('users').select('id, username, role').in('id', userIds);
        (users || []).forEach(u => { userMap[u.id] = u; });
    }

    return logs.map(row => {
        const u = userMap[row.user_id] || {};
        return {
            id: row.id,
            user_id: row.user_id,
            score: row.score,
            level: row.level,
            factors_json: row.factors_json,
            created_at: row.created_at,
            username: u.username || 'Unknown',
            role: u.role || 'Unknown'
        };
    });
}

module.exports = { calculateRisk, getRiskHistory, getAllRiskHistory, RISK_WEIGHTS, getRiskLevel };
