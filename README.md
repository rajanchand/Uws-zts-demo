# Zero Trust Security Portal

This is a web-based security portal built for my MSc Cyber Security dissertation at UWS. It demonstrates the Zero Trust model — the idea that no user or device should be trusted by default, even if they're inside the network.

The system checks who you are, what device you're using, and where you're logging in from — every single time.

Live site: [zero-trust-security.org](https://zero-trust-security.org)

## What it does

- Login with password + OTP (two-factor authentication)
- Calculates a risk score for every login based on device, location, and behavior
- Blocks or flags suspicious sessions automatically
- Admins can manage users, assign roles, approve devices, and block IPs
- Real-time security event monitoring dashboard
- Email alerts when something unusual happens
- Full audit trail of every action

## Built with

- Node.js and Express for the backend
- Supabase (PostgreSQL) for the database
- Vanilla HTML/CSS/JS for the frontend
- Nginx + PM2 on a VPS for production
- SSL via Let's Encrypt

## How to run it locally

You'll need Node.js (v18+) and a Supabase account.

```bash
# 1. Clone the repo
git clone https://github.com/rajanchand/Uws-zts-demo.git
cd Uws-zts-demo

# 2. Install dependencies
npm install

# 3. Create your .env file with these values:
#    PORT=3000
#    SESSION_SECRET=any-random-string
#    SUPABASE_URL=your-supabase-url
#    SUPABASE_KEY=your-supabase-key
#    SMTP_EMAIL=your-gmail
#    SMTP_PASSWORD=your-gmail-app-password
#    ADMIN_EMAIL=where-to-send-alerts

# 4. Start the server
npm start
```

Then open `http://localhost:3000` in your browser.

## Deploying to a VPS

```bash
# On your server
git clone https://github.com/rajanchand/Uws-zts-demo.git /var/www/zts
cd /var/www/zts
npm install

# Set up your .env file, then:
pm2 start server.js --name zts
pm2 save
```

Set up Nginx as a reverse proxy pointing to `localhost:3000`, then use Certbot for SSL.

## Project layout

```
server.js               — Main app entry point
db.js                   — Database connection
role_permissions.json   — Who can do what (editable from the UI)

middleware/             — Security checks that run on every request
  auth.js               — Is the user logged in?
  rbac.js               — Does their role allow this?
  monitoring.js         — Continuous session verification
  riskCheck.js          — Flag high-risk sessions
  csrf.js, hmacVerify.js, rateLimiter.js — Request security

routes/                 — API endpoints and page serving
  authRoutes.js         — Login, logout, OTP
  dashboardRoutes.js    — Dashboard data and admin APIs
  mappingRoutes.js      — User and department management
  rbacRoutes.js         — Permission matrix
  networkRoutes.js      — IP rules and device health

services/               — Business logic
  riskEngine.js         — Calculates risk scores
  monitorService.js     — Logs and broadcasts security events
  deviceService.js      — Device fingerprinting
  geoService.js         — IP geolocation and VPN detection
  emailService.js       — Sends alert emails

views/                  — All the HTML pages
public/css/style.css    — Styling
public/js/app.js        — Shared client-side code
```

## Roles

| Role | What they can do |
|------|-----------------|
| SuperAdmin | Everything |
| HR | Manage users, approve devices |
| Finance | Manage users, view monitoring, manage network |
| IT | View monitoring, analyze risk |
| CustomerSupport | Manage users |
| General | View their own dashboard only |

These permissions can be changed live from the Role Entitlement Matrix page.

## Based on

NIST SP 800-207 — Zero Trust Architecture
https://csrc.nist.gov/pubs/sp/800/207/final

## Author

Rajan Chand — MSc Cyber Security, University of the West of Scotland
