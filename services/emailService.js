// services/emailService.js
// sends emails using Gmail via nodemailer

var nodemailer = require('nodemailer');

// Lazy-init transporter so env vars are always fresh when called
// (avoids stale credentials if .env is loaded after module init)
function createTransporter() {
    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.SMTP_EMAIL,
            pass: process.env.SMTP_PASSWORD  // must be a Gmail App Password (16 chars, no spaces)
        }
    });
}

// Verify SMTP config on startup — logs clearly so you know early if email will work
(function verifySMTPOnStartup() {
    if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
        console.warn('[email] WARNING: SMTP_EMAIL or SMTP_PASSWORD not set. Emails will not be sent.');
        return;
    }
    var t = createTransporter();
    t.verify(function (err) {
        if (err) {
            console.error('[email] SMTP Authentication FAILED:', err.message);
            console.error('[email] -> Check your Gmail App Password at https://myaccount.google.com/apppasswords');
            console.error('[email] -> OTPs will be printed to the server console as a fallback.');
        } else {
            console.log('[email] SMTP connection verified. Emails will be sent to Gmail.');
        }
    });
})();

// send the OTP email to the user
async function sendOTPEmail(toEmail, username, otpCode) {
    // if no email credentials set, just log to console (dev mode)
    if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
        console.log('');
        console.log('============================================================');
        console.log('  [OTP FALLBACK] No SMTP config — printing OTP to console');
        console.log('  User     : ' + username);
        console.log('  Email    : ' + toEmail);
        console.log('  OTP Code : ' + otpCode);
        console.log('============================================================');
        console.log('');
        return { sent: false, reason: 'No SMTP credentials configured' };
    }

    var subject = 'Your ZTS Login Code: ' + otpCode;

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">',
        '  <h2 style="color:#0984e3;margin-bottom:4px;">ZTS Zero Trust Security</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">Multi-Factor Authentication</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:15px;">Hello <strong>' + username + '</strong>,</p>',
        '  <p style="font-size:14px;color:#2d3436;">Your one-time login code is:</p>',
        '  <div style="background:#f4f5f7;border-radius:8px;padding:20px;text-align:center;margin:20px 0;">',
        '    <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#0984e3;">' + otpCode + '</span>',
        '  </div>',
        '  <p style="font-size:13px;color:#636e72;">This code expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>',
        '  <p style="font-size:13px;color:#636e72;">If you did not try to log in, please contact your administrator immediately.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;">ZTS — Zero Trust Security Demo &nbsp;|&nbsp; NIST SP 800-207</p>',
        '</div>'
    ].join('\n');

    try {
        var transporter = createTransporter();
        await transporter.sendMail({
            from: '"ZTS Security" <' + process.env.SMTP_EMAIL + '>',
            to: toEmail,
            subject: subject,
            html: html
        });
        console.log('  [email] OTP sent to ' + toEmail);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Failed to send OTP to ' + toEmail + ':', err.message);
        // FALLBACK: always print OTP to console so login is never fully broken
        console.log('');
        console.log('============================================================');
        console.log('  [OTP FALLBACK] Email failed — printing OTP to console');
        console.log('  User     : ' + username);
        console.log('  Email    : ' + toEmail);
        console.log('  OTP Code : ' + otpCode);
        console.log('  Fix      : Update SMTP_PASSWORD in .env with a valid');
        console.log('             Gmail App Password from:');
        console.log('             https://myaccount.google.com/apppasswords');
        console.log('============================================================');
        console.log('');
        return { sent: false, reason: err.message };
    }
}

// send a login alert email to the admin
async function sendLoginAlertEmail(username, ip, country) {
    var adminEmail = process.env.ADMIN_EMAIL || process.env.SMTP_EMAIL;
    if (!adminEmail || !process.env.SMTP_PASSWORD) {
        console.log('  [email] No SMTP config — Login Alert for ' + username);
        return { sent: false, reason: 'No SMTP credentials configured' };
    }

    var subject = 'ZTS Security Alert: New Login Detected';

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">',
        '  <h2 style="color:#e17055;margin-bottom:4px;">ZTS Security Alert</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">New User Login Detected</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:15px;">A user has just logged into the system.</p>',
        '  <ul style="font-size:14px;color:#2d3436;background:#f4f5f7;border-radius:8px;padding:20px;list-style-type:none;">',
        '    <li style="margin-bottom:8px;"><strong>Username:</strong> ' + username + '</li>',
        '    <li style="margin-bottom:8px;"><strong>Source IP Address:</strong> ' + ip + '</li>',
        '    <li><strong>Location:</strong> ' + country + '</li>',
        '  </ul>',
        '  <p style="font-size:13px;color:#636e72;">If this activity appears unusual or unauthorized, administrators are advised to review session logs via the admin dashboard and take necessary actions, including session termination and credential verification.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;">ZTS — Zero Trust Security Demo</p>',
        '</div>'
    ].join('\n');

    try {
        var transporter = createTransporter();
        await transporter.sendMail({
            from: '"ZTS Security Alerts" <' + process.env.SMTP_EMAIL + '>',
            to: adminEmail,
            subject: subject,
            html: html
        });
        console.log('  [email] Login alert sent to admin for user ' + username);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Failed to send login alert:', err.message);
        return { sent: false, reason: err.message };
    }
}

// send an anomaly alert email specifically for new locations/IPs/devices
async function sendAnomalyAlertEmail(username, ip, country, anomalyReason) {
    var adminEmail = 'rajanchand@zero-trust-security.org'; // Hardcoded per requirement
    if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
        console.log('  [email] No SMTP config — Anomaly Alert for ' + username);
        return { sent: false, reason: 'No SMTP credentials configured' };
    }

    var subject = '🚨 ZTS Critical Alert: Anomalous Login Detected';

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #ff7675;border-radius:8px;">',
        '  <h2 style="color:#d63031;margin-bottom:4px;">🚨 Critical Security Alert</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">Suspicious Login Activity</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:15px;color:#2d3436;">The Zero Trust Security system has detected an anomalous login attempt.</p>',
        '  <div style="background:#fff3f3;border-left:4px solid #d63031;padding:12px 16px;margin:20px 0;">',
        '    <p style="margin:0;font-size:14px;color:#d63031;"><strong>Alert Reason:</strong> ' + anomalyReason + '</p>',
        '  </div>',
        '  <ul style="font-size:14px;color:#2d3436;background:#f4f5f7;border-radius:8px;padding:20px;list-style-type:none;margin:0;">',
        '    <li style="margin-bottom:8px;"><strong>Username:</strong> ' + username + '</li>',
        '    <li style="margin-bottom:8px;"><strong>IP Address:</strong> ' + ip + '</li>',
        '    <li><strong>Location:</strong> ' + country + '</li>',
        '  </ul>',
        '  <p style="font-size:13px;color:#636e72;margin-top:20px;">Please investigate this activity immediately in the SuperAdmin dashboard.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;text-align:center;">ZTS — Zero Trust Security Alerts</p>',
        '</div>'
    ].join('\n');

    try {
        var transporter = createTransporter();
        await transporter.sendMail({
            from: '"ZTS Security Alerts" <' + process.env.SMTP_EMAIL + '>',
            to: adminEmail,
            subject: subject,
            html: html
        });
        console.log('  [email] Anomaly alert sent to ' + adminEmail + ' for user ' + username);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Failed to send anomaly alert:', err.message);
        return { sent: false, reason: err.message };
    }
}

module.exports = { sendOTPEmail, sendLoginAlertEmail, sendAnomalyAlertEmail };
