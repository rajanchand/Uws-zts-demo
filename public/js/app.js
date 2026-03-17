// app.js - Centralized Client-Side Logic for ZTS
// This file handles common UI tasks like notifications, navigation, and security tokens.

/**
 * showToast: Displays a modern notification bubble.
 * @param {string} message - The text to show.
 * @param {string} type - 'success', 'error', or 'info'.
 */
function showToast(message, type = 'info') {
    // Remove any existing toast to prevent stacking clutter
    const oldToast = document.querySelector('.toast');
    if (oldToast) oldToast.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    // Trigger the CSS 'show' animation after a tiny delay
    setTimeout(() => toast.classList.add('show'), 10);

    // Automatically hide and remove the toast after 3.5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

/**
 * getFingerprint: Generates a unique-ish ID for the browser/device.
 * This helps us detect if a session was hijacked or moved to a new machine.
 */
function getFingerprint() {
    const parts = [
        navigator.userAgent,
        `${screen.width}x${screen.height}`,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.language,
        navigator.platform
    ];

    // Simple hash function for the fingerprint string
    let hash = 0;
    const str = parts.join('|');
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0; // Convert to 32-bit integer
    }
    return `fp-${Math.abs(hash).toString(16)}`;
}

/**
 * formatDate: Converts a standard ISO date string into something a human can read.
 */
function formatDate(dateStr) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    const day = String(d.getDate()).padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[d.getMonth()];
    const year = d.getFullYear();
    const hours = String(d.getHours()).padStart(2, '0');
    const mins = String(d.getMinutes()).padStart(2, '0');
    return `${day} ${month} ${year}, ${hours}:${mins}`;
}

// Global CSRF Token storage for authorized requests
let csrfToken = '';

/**
 * fetchCSRFToken: Retrieves a fresh CSRF token from the server.
 * This is a critical security step for all POST/PUT/DELETE actions.
 */
async function fetchCSRFToken() {
    try {
        const res = await fetch('/api/csrf-token');
        const data = await res.json();
        if (data.csrfToken) {
            csrfToken = data.csrfToken;
        }
    } catch (e) {
        console.error('Security alert: Failed to fetch CSRF token.');
    }
}

// Fetch the token immediately on script load
fetchCSRFToken();

/**
 * postJSON: A specialized helper for sending JSON data securely with CSRF protection.
 */
async function postJSON(url, data) {
    const headers = { 'Content-Type': 'application/json' };
    
    // Always include the security token if available
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    
    const response = await fetch(url, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(data)
    });
    return response.json();
}

/**
 * buildNavbar: Dynamically constructs the navigation menu based on user permissions.
 */
function buildNavbar(role, activePage, username, permissions = []) {
    const nav = document.getElementById('mainNav');
    if (!nav) return;

    let html = '';

    // Standard Dashboard Link
    html += `
        <div class="nav-item ${activePage === 'dashboard' ? 'active' : ''}">
            <a href="/dashboard" class="nav-link ${activePage === 'dashboard' ? 'active' : ''}">Dashboard</a>
        </div>
    `;

    // Network Management (Requires specific power)
    if (permissions.includes('manage_network')) {
        const active = (activePage === 'network') ? 'active' : '';
        html += `
            <div class="nav-item ${active}">
                <button class="nav-link ${active}" onclick="toggleDropdown(this)">Network <span class="arrow">▾</span></button>
                <div class="dropdown-menu">
                    <a href="/network" ${activePage === 'network' ? 'class="active"' : ''}>IP Rule</a>
                </div>
            </div>
        `;
    }

    // Security / Risk Analysis & Live Monitoring dropdown
    const canSeeSecurity = permissions.includes('analyze_risk') || permissions.includes('view_monitoring');
    if (canSeeSecurity) {
        const isActive = (activePage === 'risk' || activePage === 'live-monitoring');
        html += `
            <div class="nav-item ${isActive ? 'active' : ''}">
                <button class="nav-link ${isActive ? 'active' : ''}" onclick="toggleDropdown(this)">Security <span class="arrow">▾</span></button>
                <div class="dropdown-menu">
                    ${permissions.includes('view_monitoring') ? `
                        <a href="/admin/live-monitoring" ${activePage === 'live-monitoring' ? 'class="active"' : ''}>
                            <span style="display:inline-flex;align-items:center;gap:5px;">
                                <span style="width:7px;height:7px;border-radius:50%;background:#27ae60;display:inline-block;animation:blink 1.4s infinite;"></span>
                                Live Logs
                            </span>
                        </a>` : ''}
                    ${permissions.includes('analyze_risk') ? `<a href="/risk" ${activePage === 'risk' ? 'class="active"' : ''}>System Risk</a>` : ''}
                </div>
            </div>
        `;
    }

    // Mapping & User Registry
    const canSeeMapping = permissions.includes('manage_users') || 
                         permissions.includes('manage_depts') || 
                         permissions.includes('approve_devices');

    if (canSeeMapping) {
        const active = (activePage === 'mapping' || activePage === 'register-device' || activePage === 'user-access') ? 'active' : '';
        html += `
            <div class="nav-item ${active}">
                <button class="nav-link ${active}" onclick="toggleDropdown(this)">Mapping <span class="arrow">▾</span></button>
                <div class="dropdown-menu">
                    ${(permissions.includes('manage_users') || permissions.includes('manage_depts')) ? 
                        `<a href="/mapping" ${activePage === 'mapping' ? 'class="active"' : ''}>User Management</a>` : ''}
                    ${role === 'SuperAdmin' || role === 'Owner' ? `<a href="/mapping/user-access" ${activePage === 'user-access' ? 'class="active"' : ''}>User Access</a>` : ''}
                    ${permissions.includes('approve_devices') ? `<a href="/register-device" ${activePage === 'register-device' ? 'class="active"' : ''}>Register Device</a>` : ''}
                </div>
            </div>
        `;
    }

    nav.innerHTML = html;

    // User Profile Menu (Standard for all logged-in users)
    const userMenu = document.getElementById('userMenu');
    if (userMenu) {
        const initial = username ? username.charAt(0).toUpperCase() : '?';
        userMenu.innerHTML = `
            <button class="user-menu-btn" onclick="toggleUserMenu(this)">
                <div class="user-avatar">${initial}</div>
                <span>${username}</span>
                <span class="arrow">▾</span>
            </button>
            <div class="dropdown-menu">
                <a href="/profile" ${activePage === 'profile' ? 'class="active"' : ''}>Profile</a>
                <div class="dropdown-divider"></div>
                <a href="/logout" style="color:#e74c3c;">Logout</a>
            </div>
        `;
    }
}

// --- Menu Interaction Helpers ---

function toggleDropdown(btn) {
    const item = btn.closest('.nav-item');
    const wasOpen = item.classList.contains('open');

    // Close others
    document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(el => el.classList.remove('open'));

    if (!wasOpen) item.classList.add('open');
}

function toggleUserMenu(btn) {
    const menu = btn.closest('.user-menu');
    const wasOpen = menu.classList.contains('open');

    // Close others
    document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(el => el.classList.remove('open'));

    if (!wasOpen) menu.classList.add('open');
}

// Close dropdowns if clicking anywhere outside
document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav-item') && !e.target.closest('.user-menu')) {
        document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(el => el.classList.remove('open'));
    }
});

// Sidebar/Mobile Menu toggle
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.menu-toggle');
    const navMenu = document.querySelector('.nav-menu');
    if (toggle && navMenu) {
        toggle.addEventListener('click', () => navMenu.classList.toggle('open'));
    }
});
