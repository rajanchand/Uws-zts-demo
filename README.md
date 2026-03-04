# Zero Trust Security (ZTS) Portal

A full-stack web application implementing the **NIST SP 800-207 Zero Trust Architecture** framework. Built as part of an MSc Cyber Security dissertation at the University of the West of Scotland (UWS).

**Live Demo:** [https://zero-trust-security.org](https://zero-trust-security.org)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running the Application](#running-the-application)
- [Deployment (Production VPS)](#deployment-production-vps)
- [Default Roles and Permissions](#default-roles-and-permissions)
- [Author](#author)

---

## Overview

This project demonstrates a practical implementation of the **Zero Trust Security** model as defined by NIST SP 800-207. The system enforces the principle of **"never trust, always verify"** by continuously authenticating and authorizing every user, device, and session — regardless of network location.

The portal provides role-based dashboards, real-time security monitoring, adaptive risk scoring, and full identity lifecycle management.

---

## Architecture

The application follows the three core components of the NIST SP 800-207 framework:

| Component | Role | Implementation |
|---|---|---|
| **Policy Enforcement Point (PEP)** | Intercepts every request | `middleware/monitoring.js`, `middleware/auth.js`, `middleware/rbac.js` |
| **Policy Engine (PE)** | Evaluates trust and risk | `services/riskEngine.js`, `role_permissions.json` |
| **Policy Information Point (PIP)** | Collects session metadata | `services/monitorService.js`, `services/geoService.js`, `services/deviceService.js` |

---

## Features

- **Multi-Factor Authentication** — Password + OTP verification
- **Adaptive Risk Scoring** — Real-time risk calculation based on device, location, VPN, and login behavior
- **Role-Based Access Control (RBAC)** — Dynamic permission matrix with six roles
- **Live Security Monitoring** — Server-Sent Events (SSE) for real-time event streaming
- **Device Trust Management** — Endpoint registration, approval, and posture checks
- **IP Blocklist / Allowlist** — Network-level access control rules
- **Session Security** — IP binding, concurrent session detection, automatic timeout
- **Continuous Monitoring** — Stateful database checks every 30 seconds
- **Admin Kill Switch** — Instant user blocking and forced session revocation
- **Email Alerts** — Automated notifications for suspicious login activity
- **Audit Logging** — Complete trail of all security events

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Database | Supabase (PostgreSQL) |
| Authentication | bcryptjs, express-session |
| Security | Helmet, CSRF tokens, HMAC verification, rate limiting |
| Email | Nodemailer (Gmail SMTP) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Deployment | Nginx, PM2, Let's Encrypt SSL |

---

## Project Structure

```
zts-demo/
├── server.js                  # Express app entry point
├── db.js                      # Supabase database connection
├── role_permissions.json      # RBAC permission matrix (file-based)
├── package.json
├── .env                       # Environment variables (not committed)
│
├── middleware/
│   ├── auth.js                # Login session validation
│   ├── rbac.js                # Role and permission checks
│   ├── monitoring.js          # Continuous session monitoring (PEP)
│   ├── riskCheck.js           # High-risk session flagging
│   ├── stepUpAuth.js          # Step-up re-authentication
│   ├── csrf.js                # CSRF token generation and validation
│   ├── hmacVerify.js          # HMAC request integrity
│   ├── rateLimiter.js         # API rate limiting
│   └── passwordPolicy.js     # Password strength enforcement
│
├── routes/
│   ├── authRoutes.js          # Login, logout, OTP, registration
│   ├── dashboardRoutes.js     # Dashboard API and admin telemetry
│   ├── mappingRoutes.js       # User and department management
│   ├── rbacRoutes.js          # Permission matrix API
│   ├── networkRoutes.js       # IP rules and device health
│   ├── profileRoutes.js       # User profile management
│   ├── monitoringRoutes.js    # Live SSE event stream
│   └── securityPostureRoutes.js  # Security posture overview
│
├── services/
│   ├── riskEngine.js          # Adaptive risk scoring algorithm
│   ├── monitorService.js      # Event logging and broadcasting
│   ├── deviceService.js       # Device fingerprinting and trust
│   ├── geoService.js          # IP geolocation and VPN detection
│   ├── emailService.js        # SMTP email alerts
│   ├── otpService.js          # One-time password generation
│   ├── auditService.js        # Audit log queries
│   └── encryptionService.js   # Data encryption utilities
│
├── views/
│   ├── login.html             # Login page
│   ├── otp.html               # OTP verification page
│   ├── dashboard.html         # Main dashboard
│   ├── mapping.html           # User and department management
│   ├── user-details.html      # User 360-degree profile
│   ├── user-access.html       # Role permission matrix
│   ├── live-monitoring.html   # Real-time security event monitor
│   ├── network.html           # IP rules and device health
│   ├── risk.html              # Personal risk score view
│   ├── profile.html           # User profile settings
│   ├── register-device.html   # Device approval portal
│   └── approval-pending.html  # High-risk session waiting page
│
└── public/
    ├── css/style.css           # Global stylesheet
    └── js/app.js               # Client-side utilities
```

---

## Installation

### Prerequisites

- **Node.js** v18 or higher
- **npm** (comes with Node.js)
- A **Supabase** account (free tier works)

### Step 1: Clone the Repository

```bash
git clone https://github.com/rajanchand/Uws-zts-demo.git
cd Uws-zts-demo
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Set Up Environment Variables

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Then fill in your values (see [Environment Variables](#environment-variables) below).

### Step 4: Set Up the Database

Create the following tables in your Supabase project:

- `users` — User accounts (id, username, password_hash, email, role, department, status, etc.)
- `otp_codes` — Temporary OTP storage
- `devices` — Registered device fingerprints
- `ip_rules` — IP blocklist/allowlist
- `audit_log` — Security event audit trail
- `security_events` — Detailed monitoring events
- `risk_scores` — Historical risk score records
- `departments` — Department management
- `login_history` — Session tracking

### Step 5: Start the Application

```bash
npm start
```

The application will be available at `http://localhost:3000`.

---

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment mode | `development` or `production` |
| `SESSION_SECRET` | Session encryption key | Any random string |
| `SUPABASE_URL` | Your Supabase project URL | `https://xxx.supabase.co` |
| `SUPABASE_KEY` | Your Supabase anonymous key | `eyJhbG...` |
| `SMTP_EMAIL` | Gmail address for email alerts | `your@gmail.com` |
| `SMTP_PASSWORD` | Gmail app password (not your login password) | `xxxx xxxx xxxx xxxx` |
| `ADMIN_EMAIL` | Where to send admin alerts | `admin@yourdomain.org` |

---

## Running the Application

### Development

```bash
npm run dev
```

### Production (VPS)

```bash
npm start
```

Or with PM2 for process management:

```bash
pm2 start server.js --name zts
pm2 save
```

---

## Deployment (Production VPS)

### 1. Server Setup

```bash
# On your VPS (Ubuntu/Debian)
sudo apt update && sudo apt install -y nodejs npm nginx certbot python3-certbot-nginx

# Install PM2 globally
npm install -g pm2
```

### 2. Clone and Install

```bash
git clone https://github.com/rajanchand/Uws-zts-demo.git /var/www/zts
cd /var/www/zts
npm install
cp .env.example .env   # Edit with your production values
```

### 3. Configure Nginx

Create `/etc/nginx/sites-available/zts`:

```nginx
server {
    server_name your-domain.org;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/zts /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

### 4. SSL Certificate

```bash
sudo certbot --nginx -d your-domain.org
```

### 5. Start with PM2

```bash
cd /var/www/zts
pm2 start server.js --name zts
pm2 startup
pm2 save
```

---

## Default Roles and Permissions

| Role | Users | Devices | Monitoring | Risk | Network | Posture |
|---|---|---|---|---|---|---|
| SuperAdmin | Full | Full | Full | Full | Full | Full |
| HR | Manage | Approve | - | - | - | - |
| Finance | Manage | Approve | View | Analyze | Manage | View |
| IT | - | - | View | Analyze | - | View |
| CustomerSupport | Manage | - | - | - | - | - |
| General | - | - | - | - | - | - |

Permissions are managed dynamically via the **Role Entitlement Matrix** (`/mapping/user-access`).

---

## Author

**Rajan Chand**
MSc Cyber Security — University of the West of Scotland (UWS)

---
