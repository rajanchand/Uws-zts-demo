require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: false
}));

if (isProduction) {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.headers.host + req.url);
        }
        next();
    });
}

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure HTML views are never cached by the browser so updates apply immediately
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Session config (Must be before any middleware using req.session)
app.use(session({
    secret: process.env.SESSION_SECRET || 'zts-default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        sameSite: 'strict'
    },
    rolling: true
}));

const { csrfProtection, generateCSRFToken } = require('./middleware/csrf');
const { apiLimiter } = require('./middleware/rateLimiter');
const { verifyHMAC } = require('./middleware/hmacVerify');

const authRoutes = require('./routes/authRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const profileRoutes = require('./routes/profileRoutes');
const mappingRoutes = require('./routes/mappingRoutes');
const networkRoutes = require('./routes/networkRoutes');
const monitoringRoutes = require('./routes/monitoringRoutes');
const securityPostureRoutes = require('./routes/securityPostureRoutes');
const rbacRoutes = require('./routes/rbacRoutes');

const { requireLogin } = require('./middleware/auth');
const { requireRole, requirePermission } = require('./middleware/rbac');
const { flagHighRisk } = require('./middleware/riskCheck');
const { handleReAuth } = require('./middleware/stepUpAuth');
const { continuousMonitoring } = require('./middleware/monitoring');

app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: generateCSRFToken(req) });
});

// --- 🔓 PUBLIC ROUTES (Excluded from ZT Enforcement) ---
app.use('/', authRoutes); // Includes /login, /logout, /otp etc.

// --- 🔒 GLOBAL ZERO TRUST ENFORCEMENT (Applied to all following routes) ---
app.use(requireLogin);
app.use(continuousMonitoring); // Policy Enforcement Point (PEP)
app.use(flagHighRisk);
app.use(csrfProtection);
app.use(verifyHMAC);

// --- 📂 PROTECTED ROUTES (Only accessible if PEP grants access) ---
app.post('/api/verify-reauth', handleReAuth);
app.use('/api', apiLimiter);

app.use('/', dashboardRoutes);
app.use('/', profileRoutes);

// RBAC & Mapping
app.get('/mapping/user-access', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user-access.html'));
});
app.use('/', rbacRoutes);
app.use('/', mappingRoutes);
app.use('/', monitoringRoutes);
app.use('/', requirePermission('manage_network'), networkRoutes);
app.use('/', requirePermission('view_posture'), securityPostureRoutes);

app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/security-block', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

// Final Error Handler
app.use((err, req, res, next) => {
    console.error(`[ZTS Critical Error] ${err.stack}`);
    res.status(500).json({
        success: false,
        message: 'A critical security server error has occurred.'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
