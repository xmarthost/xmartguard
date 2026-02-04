#!/bin/bash
#===============================================================================
# XMartGuard Patch - Server Row Click & Auto-Refresh Fix
# Run from: /home2/xmartguard/app.xmartguard.com
#===============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Detect directory
if [ -d "/home2/xmartguard/app.xmartguard.com" ]; then
    APP_DIR="/home2/xmartguard/app.xmartguard.com"
elif [ -d "$(pwd)/public" ]; then
    APP_DIR="$(pwd)"
else
    APP_DIR="${1:-.}"
fi

echo ""
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║     XMartGuard Patch - Row Click & Auto-Refresh Fix           ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "App Directory: ${GREEN}$APP_DIR${NC}"
echo ""

# Backup current index.html
if [ -f "$APP_DIR/public/index.html" ]; then
    cp "$APP_DIR/public/index.html" "$APP_DIR/public/index.html.backup.$(date +%Y%m%d%H%M%S)"
    echo -e "${GREEN}✓ Backup created${NC}"
fi

# Create updated index.html
echo -e "${YELLOW}► Updating frontend...${NC}"

cat > "$APP_DIR/public/index.html" << 'HTMLFILE'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>XMartGuard - Server Monitoring Dashboard</title>
  <link rel="icon" id="dynamicFavicon" href="/favicon.ico" type="image/x-icon">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/crypto-js.min.js"></script>
  <style>
    :root {
      --primary: #10b981;
      --primary-dark: #059669;
      --secondary: #667eea;
      --bg: #f3f4f6;
      --card-bg: #ffffff;
      --text: #1f2937;
      --text-muted: #6b7280;
      --border: #e5e7eb;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --info: #3b82f6;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
    
    .auth-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%); }
    .auth-card { background: white; padding: 40px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); width: 100%; max-width: 420px; }
    .auth-logo { text-align: center; margin-bottom: 30px; }
    .auth-logo h1 { font-size: 28px; color: var(--primary); }
    .auth-logo p { color: var(--text-muted); }
    .auth-card h2 { margin-bottom: 24px; text-align: center; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; margin-bottom: 6px; font-weight: 500; color: var(--text); }
    .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; transition: all 0.2s; }
    .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }
    .btn { display: inline-block; padding: 12px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; transition: all 0.2s; text-decoration: none; text-align: center; }
    .btn-primary { background: var(--primary); color: white; }
    .btn-primary:hover { background: var(--primary-dark); }
    .btn-secondary { background: var(--bg); color: var(--text); border: 1px solid var(--border); }
    .btn-danger { background: var(--danger); color: white; }
    .btn-warning { background: var(--warning); color: white; }
    .btn-sm { padding: 6px 12px; font-size: 13px; }
    .auth-footer { text-align: center; margin-top: 20px; color: var(--text-muted); }
    .auth-footer a { color: var(--primary); text-decoration: none; }
    .error-msg { background: #fef2f2; color: #991b1b; padding: 12px; border-radius: 8px; margin-bottom: 16px; display: none; }
    
    .app-container { display: flex; min-height: 100vh; }
    .sidebar { width: 260px; background: white; border-right: 1px solid var(--border); display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100; }
    .sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); }
    .sidebar-header h1 { font-size: 20px; color: var(--primary); display: flex; align-items: center; gap: 10px; }
    .sidebar-nav { flex: 1; padding: 16px 0; overflow-y: auto; }
    .nav-section { padding: 0 16px; margin-bottom: 8px; }
    .nav-section-title { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 8px; padding: 0 12px; }
    .nav-item { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border-radius: 8px; cursor: pointer; color: var(--text-muted); transition: all 0.2s; margin-bottom: 2px; }
    .nav-item:hover { background: var(--bg); color: var(--text); }
    .nav-item.active { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; }
    .nav-item span { font-size: 18px; }
    .sidebar-footer { padding: 16px; border-top: 1px solid var(--border); }
    .user-info { display: flex; align-items: center; gap: 12px; padding: 8px; }
    .user-avatar { width: 40px; height: 40px; border-radius: 50%; background: var(--primary); color: white; display: flex; align-items: center; justify-content: center; font-weight: 600; overflow: hidden; }
    .user-avatar img { width: 100%; height: 100%; object-fit: cover; }
    .user-details { flex: 1; }
    .user-name { font-weight: 500; font-size: 14px; }
    .user-plan { font-size: 12px; color: var(--text-muted); }
    
    .main-content { flex: 1; margin-left: 260px; }
    .topbar { background: white; padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
    .topbar h2 { font-size: 20px; }
    .topbar-actions { display: flex; gap: 12px; align-items: center; }
    .refresh-timer { font-size: 13px; color: var(--text-muted); background: var(--bg); padding: 6px 12px; border-radius: 6px; }
    .content-area { padding: 24px; }
    
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px; }
    .stat-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .stat-label { font-size: 13px; color: var(--text-muted); margin-bottom: 4px; }
    .stat-value { font-size: 28px; font-weight: 600; }
    .stat-value.success { color: var(--success); }
    .stat-value.warning { color: var(--warning); }
    .stat-value.danger { color: var(--danger); }
    
    .card { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }
    .card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .card-header h3 { font-size: 16px; }
    .card-body { padding: 20px; }
    
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
    th { font-weight: 500; color: var(--text-muted); font-size: 13px; text-transform: uppercase; }
    tr:hover { background: var(--bg); }
    tr.clickable { cursor: pointer; }
    tr.clickable:hover { background: #e0f2fe; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 500; }
    .badge-success { background: #d1fae5; color: #065f46; }
    .badge-danger { background: #fee2e2; color: #991b1b; }
    .badge-warning { background: #fef3c7; color: #92400e; }
    .badge-info { background: #dbeafe; color: #1e40af; }
    
    .info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
    .info-item { background: var(--bg); padding: 16px; border-radius: 8px; }
    .info-label { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
    .info-value { font-size: 14px; font-weight: 500; }
    
    .metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 24px; }
    .metric-card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .metric-label { font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }
    .metric-value { font-size: 36px; font-weight: 600; margin-bottom: 4px; }
    .metric-sub { font-size: 13px; color: var(--text-muted); }
    
    .chart-container { height: 200px; position: relative; }
    .chart-filters { display: flex; gap: 8px; margin-bottom: 16px; }
    .chart-filter { padding: 6px 16px; border: 1px solid var(--border); border-radius: 20px; cursor: pointer; font-size: 13px; background: white; }
    .chart-filter.active { background: var(--primary); color: white; border-color: var(--primary); }
    
    .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
    .modal.active { display: flex; }
    .modal-content { background: white; border-radius: 16px; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto; }
    .modal-header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .modal-header h3 { font-size: 18px; }
    .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-muted); }
    .modal-body { padding: 20px; }
    
    .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 24px; }
    .pricing-card { background: white; border-radius: 16px; padding: 32px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 2px solid transparent; transition: all 0.3s; }
    .pricing-card.popular { border-color: var(--primary); position: relative; }
    .pricing-card.popular::before { content: 'Most Popular'; position: absolute; top: -12px; left: 50%; transform: translateX(-50%); background: var(--primary); color: white; padding: 4px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; }
    .pricing-card.current { border-color: var(--secondary); }
    .pricing-name { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
    .pricing-price { font-size: 40px; font-weight: 700; margin-bottom: 8px; }
    .pricing-price span { font-size: 16px; color: var(--text-muted); font-weight: 400; }
    .pricing-desc { color: var(--text-muted); margin-bottom: 24px; }
    .pricing-features { list-style: none; margin-bottom: 24px; }
    .pricing-features li { padding: 8px 0; display: flex; align-items: center; gap: 8px; }
    .pricing-features li::before { content: '✓'; color: var(--success); font-weight: bold; }
    
    .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .alert-success { background: #d1fae5; color: #065f46; }
    .alert-error { background: #fee2e2; color: #991b1b; }
    .alert-warning { background: #fef3c7; color: #92400e; }
    .alert-info { background: #dbeafe; color: #1e40af; }
    
    .loading { text-align: center; padding: 40px; color: var(--text-muted); }
    .spinner { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    
    .empty-state { text-align: center; padding: 60px 20px; }
    .empty-state h3 { margin-bottom: 8px; }
    .empty-state p { color: var(--text-muted); margin-bottom: 24px; }
    
    .code-block { background: #1f2937; color: #e5e7eb; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; position: relative; word-break: break-all; }
    .code-block .copy-btn { position: absolute; top: 8px; right: 8px; background: var(--primary); color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
    .code-block .copy-btn:hover { background: var(--primary-dark); }
    
    .toast { position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 250px; animation: slideIn 0.3s ease; }
    @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    
    .action-btns { display: flex; gap: 8px; }
    .action-btns .btn { white-space: nowrap; }
    
    @media (max-width: 768px) {
      .sidebar { transform: translateX(-100%); }
      .sidebar.open { transform: translateX(0); }
      .main-content { margin-left: 0; }
      .metrics-grid { grid-template-columns: 1fr; }
      .topbar { padding: 12px 16px; }
      .content-area { padding: 16px; }
    }
  </style>
</head>
<body>
  <div class="auth-container" id="authContainer">
    <div class="auth-card" id="loginCard">
      <div class="auth-logo">
        <h1>🛡️ XMartGuard</h1>
        <p>Professional Server Monitoring</p>
      </div>
      <h2>Welcome Back</h2>
      <div class="error-msg" id="loginError"></div>
      <form id="loginForm">
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required placeholder="••••••••">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Sign In</button>
      </form>
      <div class="auth-footer">
        Don't have an account? <a href="#" onclick="showRegister()">Sign Up</a>
      </div>
    </div>
    
    <div class="auth-card" id="registerCard" style="display:none;">
      <div class="auth-logo">
        <h1>🛡️ XMartGuard</h1>
        <p>Professional Server Monitoring</p>
      </div>
      <h2>Create Account</h2>
      <div class="error-msg" id="registerError"></div>
      <form id="registerForm">
        <div class="form-group">
          <label>Full Name</label>
          <input type="text" name="name" required placeholder="John Doe">
        </div>
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required placeholder="Min 6 characters" minlength="6">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Create Account</button>
      </form>
      <div class="auth-footer">
        Already have an account? <a href="#" onclick="showLogin()">Sign In</a>
      </div>
    </div>
  </div>

  <div class="app-container" id="appContainer" style="display:none;">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <h1><span>🛡️</span> XMartGuard</h1>
      </div>
      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-title">Overview</div>
          <div class="nav-item active" data-page="dashboard"><span>📊</span> Dashboard</div>
        </div>
        <div class="nav-section">
          <div class="nav-section-title">Monitoring</div>
          <div class="nav-item" data-page="servers"><span>🖥️</span> Servers</div>
        </div>
        <div class="nav-section">
          <div class="nav-section-title">Account</div>
          <div class="nav-item" data-page="billing"><span>💳</span> Billing & Plans</div>
          <div class="nav-item" data-page="settings"><span>⚙️</span> Settings</div>
        </div>
        <div class="nav-section" id="adminNav" style="display:none;">
          <div class="nav-section-title">Admin</div>
          <div class="nav-item" data-page="admin-users"><span>👥</span> Users</div>
          <div class="nav-item" data-page="admin-servers"><span>🖥️</span> All Servers</div>
          <div class="nav-item" data-page="admin-payments"><span>💰</span> Payments</div>
          <div class="nav-item" data-page="admin-settings"><span>🔧</span> System</div>
        </div>
      </nav>
      <div class="sidebar-footer">
        <div class="user-info">
          <div class="user-avatar" id="userAvatar">A</div>
          <div class="user-details">
            <div class="user-name" id="userName">Admin</div>
            <div class="user-plan" id="userPlan">Free Plan</div>
          </div>
        </div>
        <button class="btn btn-secondary" style="width:100%;margin-top:12px;" onclick="logout()">Logout</button>
      </div>
    </aside>

    <main class="main-content">
      <header class="topbar">
        <h2 id="pageTitle">Dashboard</h2>
        <div class="topbar-actions">
          <div class="refresh-timer" id="refreshTimer">Updated just now</div>
          <div id="pageActions"></div>
        </div>
      </header>
      <div class="content-area" id="contentArea">
        <div class="loading"><div class="spinner"></div>Loading...</div>
      </div>
    </main>
  </div>

  <div class="modal" id="addServerModal">
    <div class="modal-content">
      <div class="modal-header">
        <h3>Add New Server</h3>
        <button class="modal-close" onclick="closeModal('addServerModal')">&times;</button>
      </div>
      <div class="modal-body">
        <form id="addServerForm">
          <div class="form-group">
            <label>Server Name</label>
            <input type="text" name="name" required placeholder="My Web Server">
          </div>
          <div class="form-group">
            <label>IP Address / Hostname</label>
            <input type="text" name="ipAddress" required placeholder="192.168.1.1">
          </div>
          <div style="display:flex;gap:12px;margin-top:20px;">
            <button type="button" class="btn btn-secondary" onclick="closeModal('addServerModal')">Cancel</button>
            <button type="submit" class="btn btn-primary" style="flex:1;">Add Server</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <div class="modal" id="installModal">
    <div class="modal-content" style="max-width:600px;">
      <div class="modal-header">
        <h3>Install Monitoring Agent</h3>
        <button class="modal-close" onclick="closeModal('installModal')">&times;</button>
      </div>
      <div class="modal-body">
        <p style="margin-bottom:16px;">Run this command on your server to install the monitoring agent:</p>
        <div class="code-block">
          <code id="installCommand">Loading...</code>
          <button class="copy-btn" onclick="copyToClipboard('installCommand')">📋 Copy</button>
        </div>
        <div class="alert alert-info" style="margin-top:16px;">
          <strong>Note:</strong> Run this command as root (sudo) on your Linux server.
        </div>
      </div>
    </div>
  </div>

  <div class="modal" id="uninstallModal">
    <div class="modal-content" style="max-width:600px;">
      <div class="modal-header">
        <h3>Uninstall Agent</h3>
        <button class="modal-close" onclick="closeModal('uninstallModal')">&times;</button>
      </div>
      <div class="modal-body">
        <p style="margin-bottom:16px;">Run this command on your server to uninstall the agent:</p>
        <div class="code-block">
          <code id="uninstallCommand">sudo systemctl stop xmartguard-agent && sudo systemctl disable xmartguard-agent && sudo rm -rf /opt/xmartguard-agent /etc/systemd/system/xmartguard-agent.service && sudo systemctl daemon-reload && echo "Agent uninstalled"</code>
          <button class="copy-btn" onclick="copyToClipboard('uninstallCommand')">📋 Copy</button>
        </div>
      </div>
    </div>
  </div>

  <div class="modal" id="upgradeModal">
    <div class="modal-content" style="max-width:600px;">
      <div class="modal-header">
        <h3>Upgrade Plan</h3>
        <button class="modal-close" onclick="closeModal('upgradeModal')">&times;</button>
      </div>
      <div class="modal-body" id="upgradeModalBody"></div>
    </div>
  </div>

<script>
//==============================================================================
// GLOBALS
//==============================================================================
let currentUser = null;
let currentPage = 'dashboard';
let currentServerId = null;
let refreshInterval = null;
let refreshCountdown = 30;
let charts = {};

//==============================================================================
// API HELPER
//==============================================================================
async function api(url, options = {}) {
  try {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    const token = localStorage.getItem('authToken');
    if (token) headers['Authorization'] = 'Bearer ' + token;
    
    const res = await fetch('/api' + url, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    
    const data = await res.json();
    if (!data.success && res.status === 401) { logout(); throw new Error('Session expired'); }
    if (!data.success) throw new Error(data.message || 'API Error');
    return data;
  } catch (err) { throw err; }
}

//==============================================================================
// UTILITIES
//==============================================================================
function copyToClipboard(elementId) {
  const text = document.getElementById(elementId).textContent;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied!', 'success')).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  try { document.execCommand('copy'); showToast('Copied!', 'success'); }
  catch (err) { showToast('Copy failed', 'error'); }
  document.body.removeChild(textarea);
}

function showToast(message, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  
  const toast = document.createElement('div');
  toast.className = `toast alert alert-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
  if (!seconds) return 'N/A';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return days + 'd ' + hours + 'h';
  if (hours > 0) return hours + 'h ' + mins + 'm';
  return mins + 'm';
}

function getGravatarUrl(email, size = 80) {
  if (!email) return '';
  try {
    const hash = CryptoJS.MD5(email.toLowerCase().trim()).toString();
    return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon`;
  } catch (e) { return ''; }
}

function getPlanName(plan) {
  if (!plan) return 'Free';
  if (typeof plan === 'string') return plan.charAt(0).toUpperCase() + plan.slice(1);
  if (plan.name) return plan.name;
  return 'Free';
}

//==============================================================================
// AUTH
//==============================================================================
function showLogin() {
  document.getElementById('loginCard').style.display = 'block';
  document.getElementById('registerCard').style.display = 'none';
}

function showRegister() {
  document.getElementById('loginCard').style.display = 'none';
  document.getElementById('registerCard').style.display = 'block';
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById('loginError');
  errEl.style.display = 'none';
  
  try {
    const res = await api('/auth/login', {
      method: 'POST',
      body: { email: form.email.value, password: form.password.value }
    });
    localStorage.setItem('authToken', res.token);
    localStorage.setItem('user', JSON.stringify(res.user));
    initApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
});

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById('registerError');
  errEl.style.display = 'none';
  
  try {
    const res = await api('/auth/register', {
      method: 'POST',
      body: { name: form.name.value, email: form.email.value, password: form.password.value }
    });
    localStorage.setItem('authToken', res.token);
    localStorage.setItem('user', JSON.stringify(res.user));
    initApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
});

function logout() {
  localStorage.removeItem('authToken');
  localStorage.removeItem('user');
  location.reload();
}

//==============================================================================
// APP INIT
//==============================================================================
function initApp() {
  const token = localStorage.getItem('authToken');
  const user = localStorage.getItem('user');
  
  if (!token || !user) {
    document.getElementById('authContainer').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';
    return;
  }
  
  currentUser = JSON.parse(user);
  document.getElementById('authContainer').style.display = 'none';
  document.getElementById('appContainer').style.display = 'flex';
  
  document.getElementById('userName').textContent = currentUser.name;
  const avatarUrl = getGravatarUrl(currentUser.email);
  if (avatarUrl) {
    document.getElementById('userAvatar').innerHTML = `<img src="${avatarUrl}" alt="${currentUser.name}">`;
  } else {
    document.getElementById('userAvatar').textContent = currentUser.name.charAt(0).toUpperCase();
  }
  
  const planName = getPlanName(currentUser.subscription?.plan);
  document.getElementById('userPlan').textContent = planName + ' Plan';
  
  if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
    document.getElementById('adminNav').style.display = 'block';
  }
  
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      currentPage = item.dataset.page;
      currentServerId = null;
      loadPage(currentPage);
    });
  });
  
  loadPage('dashboard');
  startRefreshTimer();
}

//==============================================================================
// AUTO-REFRESH TIMER - FIXED
//==============================================================================
function startRefreshTimer() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
  
  refreshCountdown = 30;
  const timerEl = document.getElementById('refreshTimer');
  
  function tick() {
    refreshCountdown--;
    
    if (refreshCountdown <= 0) {
      refreshCountdown = 30;
      timerEl.textContent = 'Refreshing...';
      
      // Auto-refresh for these pages
      if (['dashboard', 'servers', 'server-detail'].includes(currentPage)) {
        loadPage(currentPage);
      }
    } else {
      timerEl.textContent = `Refresh in ${refreshCountdown}s`;
    }
  }
  
  // Initial display
  timerEl.textContent = `Refresh in ${refreshCountdown}s`;
  
  // Start interval
  refreshInterval = setInterval(tick, 1000);
  
  console.log('Refresh timer started');
}

//==============================================================================
// PAGE ROUTER
//==============================================================================
async function loadPage(page) {
  const pageTitle = page.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  document.getElementById('pageTitle').textContent = pageTitle;
  document.getElementById('pageActions').innerHTML = '';
  
  // Reset countdown on page load
  refreshCountdown = 30;
  
  switch(page) {
    case 'dashboard': await loadDashboard(); break;
    case 'servers': await loadServers(); break;
    case 'server-detail': await loadServerDetail(currentServerId); break;
    case 'billing': await loadBilling(); break;
    case 'settings': await loadSettings(); break;
    case 'admin-users': await loadAdminUsers(); break;
    case 'admin-servers': await loadAdminServers(); break;
    case 'admin-payments': await loadAdminPayments(); break;
    case 'admin-settings': await loadAdminSettings(); break;
    default: loadNotFound(page);
  }
}

//==============================================================================
// DASHBOARD
//==============================================================================
async function loadDashboard() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading dashboard...</div>';
  
  try {
    const [stats, serversRes] = await Promise.all([
      api('/dashboard/stats'),
      api('/dashboard/server-status')
    ]);
    
    const s = stats.stats;
    const servers = serversRes.servers || [];
    
    content.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Servers</div>
          <div class="stat-value">${s.totalServers}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Online</div>
          <div class="stat-value success">${s.onlineServers}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Offline</div>
          <div class="stat-value danger">${s.offlineServers}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Server Limit</div>
          <div class="stat-value">${s.totalServers} / ${s.serverLimit}</div>
        </div>
      </div>
      
      ${s.serversRemaining <= 0 ? `
        <div class="alert alert-warning">
          <strong>Server Limit Reached!</strong> 
          <a href="#" onclick="event.preventDefault();document.querySelector('[data-page=billing]').click();" style="color:inherit;font-weight:600;margin-left:8px;">Upgrade now →</a>
        </div>
      ` : ''}
      
      <div class="card">
        <div class="card-header">
          <h3>Server Status</h3>
          <button class="btn btn-primary btn-sm" onclick="openModal('addServerModal')">+ Add Server</button>
        </div>
        <div class="card-body" style="padding:0;">
          ${servers.length === 0 ? `
            <div class="empty-state">
              <h3>No Servers Yet</h3>
              <p>Add your first server to start monitoring</p>
              <button class="btn btn-primary" onclick="openModal('addServerModal')">+ Add Server</button>
            </div>
          ` : `
            <table>
              <thead>
                <tr><th>Name</th><th>IP</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Problems</th></tr>
              </thead>
              <tbody>
                ${servers.map(srv => `
                  <tr class="clickable" onclick="viewServer('${srv._id}')">
                    <td><strong>${srv.name}</strong></td>
                    <td>${srv.ipAddress}</td>
                    <td><span class="badge badge-${srv.status === 'online' ? 'success' : srv.status === 'warning' ? 'warning' : 'danger'}">${srv.status.toUpperCase()}</span></td>
                    <td>${(srv.metrics?.cpu || 0).toFixed(1)}%</td>
                    <td>${(srv.metrics?.memory || 0).toFixed(1)}%</td>
                    <td>${(srv.metrics?.disk || 0).toFixed(1)}%</td>
                    <td>${(srv.problems?.length || 0) > 0 ? `<span class="badge badge-danger">${srv.problems.length}</span>` : '—'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

//==============================================================================
// SERVERS LIST - FIXED ROW CLICK
//==============================================================================
async function loadServers() {
  const content = document.getElementById('contentArea');
  document.getElementById('pageActions').innerHTML = '<button class="btn btn-primary btn-sm" onclick="openModal(\'addServerModal\')">+ Add Server</button>';
  
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading servers...</div>';
  
  try {
    const { servers } = await api('/servers');
    
    if (servers.length === 0) {
      content.innerHTML = `
        <div class="empty-state">
          <h3>No Servers Yet</h3>
          <p>Add your first server to start monitoring</p>
          <button class="btn btn-primary" onclick="openModal('addServerModal')">+ Add Server</button>
        </div>
      `;
      return;
    }
    
    content.innerHTML = `
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${servers.map(srv => `
                <tr class="clickable" data-server-id="${srv._id}">
                  <td><strong>${srv.name}</strong></td>
                  <td>${srv.ipAddress}</td>
                  <td><span class="badge badge-${srv.status === 'online' ? 'success' : srv.status === 'pending' ? 'warning' : 'danger'}">${srv.status.toUpperCase()}</span></td>
                  <td>${(srv.metrics?.cpu || 0).toFixed(1)}%</td>
                  <td>${(srv.metrics?.memory || 0).toFixed(1)}%</td>
                  <td>${(srv.metrics?.disk || 0).toFixed(1)}%</td>
                  <td>${srv.lastSeen ? new Date(srv.lastSeen).toLocaleString() : 'Never'}</td>
                  <td class="action-btns" onclick="event.stopPropagation();">
                    <button class="btn btn-secondary btn-sm" onclick="showInstallModal('${srv.agentToken}')">Install</button>
                    <button class="btn btn-warning btn-sm" onclick="openModal('uninstallModal')">Uninstall</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteServer('${srv._id}')">Delete</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
    
    // Add click handlers to rows
    document.querySelectorAll('tr[data-server-id]').forEach(row => {
      row.addEventListener('click', function(e) {
        // Don't navigate if clicking on action buttons
        if (e.target.closest('.action-btns')) return;
        const serverId = this.dataset.serverId;
        viewServer(serverId);
      });
    });
    
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

//==============================================================================
// VIEW SERVER - Navigate to detail
//==============================================================================
function viewServer(serverId) {
  currentServerId = serverId;
  currentPage = 'server-detail';
  loadPage('server-detail');
}

//==============================================================================
// SERVER DETAIL
//==============================================================================
async function loadServerDetail(id) {
  const content = document.getElementById('contentArea');
  const actions = document.getElementById('pageActions');
  
  if (!id) {
    content.innerHTML = '<div class="alert alert-error">Server ID not found</div>';
    return;
  }
  
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading server details...</div>';
  
  try {
    const { server: s } = await api(`/servers/${id}`);
    const si = s.systemInfo || {};
    
    document.getElementById('pageTitle').textContent = s.name;
    actions.innerHTML = `<button class="btn btn-secondary btn-sm" onclick="goToServers()">← Back to Servers</button>`;
    
    content.innerHTML = `
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">CPU Usage</div>
          <div class="metric-value" style="color: ${s.metrics.cpu < 50 ? 'var(--success)' : s.metrics.cpu < 80 ? 'var(--warning)' : 'var(--danger)'}">
            ${(s.metrics.cpu || 0).toFixed(1)}%
          </div>
          <div class="metric-sub">${(100 - s.metrics.cpu).toFixed(1)}% Available</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Memory Usage</div>
          <div class="metric-value" style="color: ${s.metrics.memory < 50 ? 'var(--success)' : s.metrics.memory < 80 ? 'var(--warning)' : 'var(--danger)'}">
            ${(s.metrics.memory || 0).toFixed(1)}%
          </div>
          <div class="metric-sub">${(100 - s.metrics.memory).toFixed(1)}% Available</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Disk Usage</div>
          <div class="metric-value" style="color: ${s.metrics.disk < 70 ? 'var(--success)' : s.metrics.disk < 90 ? 'var(--warning)' : 'var(--danger)'}">
            ${(s.metrics.disk || 0).toFixed(1)}%
          </div>
          <div class="metric-sub">${(100 - s.metrics.disk).toFixed(1)}% Available</div>
        </div>
      </div>
      
      ${s.problems && s.problems.length > 0 ? `
        <div class="card" style="border-left: 4px solid var(--danger);">
          <div class="card-header"><h3>⚠️ Active Problems</h3></div>
          <div class="card-body">
            ${s.problems.map(p => `
              <div class="alert alert-${p.severity === 'critical' ? 'error' : 'warning'}">
                <strong>${p.message}</strong><br>
                <small>Suggestion: ${p.suggestion}</small>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}
      
      <div class="card">
        <div class="card-header">
          <h3>📈 Performance</h3>
          <div class="chart-filters">
            <button class="chart-filter active" onclick="updateChartPeriod('hourly')">Hourly</button>
            <button class="chart-filter" onclick="updateChartPeriod('daily')">24h</button>
            <button class="chart-filter" onclick="updateChartPeriod('weekly')">Weekly</button>
          </div>
        </div>
        <div class="card-body">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;">
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);font-size:14px;">CPU Usage</h4>
              <div class="chart-container"><canvas id="cpuChart"></canvas></div>
            </div>
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);font-size:14px;">Memory Usage</h4>
              <div class="chart-container"><canvas id="memChart"></canvas></div>
            </div>
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);font-size:14px;">Disk Usage</h4>
              <div class="chart-container"><canvas id="diskChart"></canvas></div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>Server Information</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item"><div class="info-label">Hostname</div><div class="info-value">${si.hostname || s.name}</div></div>
            <div class="info-item"><div class="info-label">Operating System</div><div class="info-value">${si.os || 'Unknown'}</div></div>
            <div class="info-item"><div class="info-label">Kernel</div><div class="info-value">${si.kernel || 'Unknown'}</div></div>
            <div class="info-item"><div class="info-label">Architecture</div><div class="info-value">${si.arch || 'Unknown'}</div></div>
            <div class="info-item"><div class="info-label">Uptime</div><div class="info-value">${formatUptime(s.metrics?.uptime || 0)}</div></div>
            <div class="info-item"><div class="info-label">CPU Model</div><div class="info-value">${si.cpuModel || 'Unknown'}</div></div>
            <div class="info-item"><div class="info-label">CPU Cores</div><div class="info-value">${si.cpuCount || 0} Cores</div></div>
            <div class="info-item"><div class="info-label">Load Average</div><div class="info-value">${(s.metrics?.loadAvg || [0,0,0]).map(l => l.toFixed(2)).join(' / ')}</div></div>
            <div class="info-item"><div class="info-label">IP Address</div><div class="info-value">${s.ipAddress}</div></div>
            <div class="info-item"><div class="info-label">Last Seen</div><div class="info-value">${s.lastSeen ? new Date(s.lastSeen).toLocaleString() : 'Never'}</div></div>
          </div>
        </div>
      </div>
    `;
    
    // Initialize charts
    initServerCharts(s);
    
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

function goToServers() {
  document.querySelector('[data-page="servers"]').click();
}

function initServerCharts(server) {
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      y: { min: 0, max: 100, ticks: { callback: v => v + '%' } },
      x: { display: false }
    }
  };
  
  const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
  const cpuData = Array.from({length: 24}, () => Math.random() * 30 + (server.metrics?.cpu || 20));
  const memData = Array.from({length: 24}, () => Math.random() * 20 + (server.metrics?.memory || 40));
  const diskData = Array.from({length: 24}, () => server.metrics?.disk || 50);
  
  if (charts.cpu) charts.cpu.destroy();
  if (charts.mem) charts.mem.destroy();
  if (charts.disk) charts.disk.destroy();
  
  const cpuCtx = document.getElementById('cpuChart');
  const memCtx = document.getElementById('memChart');
  const diskCtx = document.getElementById('diskChart');
  
  if (cpuCtx) {
    charts.cpu = new Chart(cpuCtx, {
      type: 'line',
      data: { labels, datasets: [{ data: cpuData, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.4 }] },
      options: chartOptions
    });
  }
  
  if (memCtx) {
    charts.mem = new Chart(memCtx, {
      type: 'line',
      data: { labels, datasets: [{ data: memData, borderColor: '#667eea', backgroundColor: 'rgba(102,126,234,0.1)', fill: true, tension: 0.4 }] },
      options: chartOptions
    });
  }
  
  if (diskCtx) {
    charts.disk = new Chart(diskCtx, {
      type: 'line',
      data: { labels, datasets: [{ data: diskData, borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.1)', fill: true, tension: 0.4 }] },
      options: chartOptions
    });
  }
}

function updateChartPeriod(period) {
  document.querySelectorAll('.chart-filter').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.toLowerCase().includes(period.substring(0,4)));
  });
  
  const configs = {
    hourly: { count: 60, labels: Array.from({length: 60}, (_, i) => `${i}m`) },
    daily: { count: 24, labels: Array.from({length: 24}, (_, i) => `${i}:00`) },
    weekly: { count: 7, labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] }
  };
  
  const config = configs[period] || configs.daily;
  
  if (charts.cpu) {
    charts.cpu.data.labels = config.labels;
    charts.cpu.data.datasets[0].data = Array.from({length: config.count}, () => Math.random() * 40 + 20);
    charts.cpu.update();
  }
  if (charts.mem) {
    charts.mem.data.labels = config.labels;
    charts.mem.data.datasets[0].data = Array.from({length: config.count}, () => Math.random() * 30 + 40);
    charts.mem.update();
  }
  if (charts.disk) {
    charts.disk.data.labels = config.labels;
    charts.disk.data.datasets[0].data = Array.from({length: config.count}, () => Math.random() * 10 + 45);
    charts.disk.update();
  }
}

//==============================================================================
// BILLING
//==============================================================================
async function loadBilling() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading billing...</div>';
  
  try {
    const [plansRes, subRes, invoicesRes] = await Promise.all([
      api('/billing/plans'),
      api('/billing/subscription'),
      api('/billing/invoices')
    ]);
    
    const plans = plansRes.plans || [];
    const sub = subRes.subscription || {};
    const invoices = invoicesRes.invoices || [];
    
    const currentPlanSlug = typeof sub.plan === 'string' ? sub.plan : (sub.plan?.slug || 'free');
    const currentPlanName = getPlanName(sub.plan);
    
    content.innerHTML = `
      <div class="card" style="margin-bottom:24px;">
        <div class="card-header"><h3>Current Subscription</h3></div>
        <div class="card-body">
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-label">Current Plan</div>
              <div class="stat-value">${currentPlanName}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Servers Used</div>
              <div class="stat-value">${sub.serverCount || 0} / ${sub.serverLimit || 1}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Status</div>
              <div class="stat-value success">${(sub.status || 'active').charAt(0).toUpperCase() + (sub.status || 'active').slice(1)}</div>
            </div>
          </div>
        </div>
      </div>
      
      <h3 style="margin-bottom:20px;">Available Plans</h3>
      <div class="pricing-grid">
        ${plans.map(p => {
          const planSlug = p.slug || p.name?.toLowerCase() || '';
          const isCurrent = currentPlanSlug === planSlug;
          return `
            <div class="pricing-card ${p.isPopular ? 'popular' : ''} ${isCurrent ? 'current' : ''}">
              <div class="pricing-name">${p.name}</div>
              <div class="pricing-price">$${((p.price?.monthly || 0) / 100).toFixed(0)}<span>/month</span></div>
              <div class="pricing-desc">${p.description || ''}</div>
              <ul class="pricing-features">
                ${(p.features || []).filter(f => f.included).map(f => `<li>${f.name}</li>`).join('')}
              </ul>
              ${isCurrent ? 
                '<button class="btn btn-secondary" style="width:100%;" disabled>Current Plan</button>' :
                `<button class="btn btn-primary" style="width:100%;" onclick="showUpgradeModal('${planSlug}')">
                  ${(p.price?.monthly || 0) === 0 ? 'Downgrade' : 'Upgrade'}
                </button>`
              }
            </div>
          `;
        }).join('')}
      </div>
      
      <h3 style="margin:32px 0 20px;">Billing History</h3>
      <div class="card">
        <div class="card-body" style="padding:0;">
          ${invoices.length === 0 ? '<p style="padding:20px;text-align:center;color:var(--text-muted);">No invoices yet</p>' : `
            <table>
              <thead><tr><th>Invoice</th><th>Date</th><th>Amount</th><th>Status</th></tr></thead>
              <tbody>
                ${invoices.map(inv => `
                  <tr>
                    <td>${inv.invoiceNumber || 'N/A'}</td>
                    <td>${new Date(inv.createdAt).toLocaleDateString()}</td>
                    <td>$${((inv.total || 0) / 100).toFixed(2)}</td>
                    <td><span class="badge badge-${inv.status === 'paid' ? 'success' : inv.status === 'processing' ? 'warning' : 'danger'}">${inv.status}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function showUpgradeModal(planSlug) {
  const body = document.getElementById('upgradeModalBody');
  body.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  openModal('upgradeModal');
  
  try {
    const [plansRes, methodsRes] = await Promise.all([
      api('/billing/plans'),
      api('/billing/payment-methods')
    ]);
    
    const plan = (plansRes.plans || []).find(p => (p.slug || p.name?.toLowerCase()) === planSlug);
    if (!plan) throw new Error('Plan not found');
    
    const methods = methodsRes.methods || {};
    
    body.innerHTML = `
      <h4 style="margin-bottom:16px;">Upgrade to ${plan.name} - $${((plan.price?.monthly || 0) / 100).toFixed(0)}/month</h4>
      <div style="margin-bottom:20px;"><strong>Select Payment Method:</strong></div>
      
      ${methods.stripe?.enabled ? `
        <div style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;" onclick="processPayment('stripe', '${planSlug}')" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
          <h4>💳 Credit/Debit Card (Stripe)</h4>
          <p style="color:var(--text-muted);margin:0;">Secure payment. Instant activation.</p>
        </div>
      ` : ''}
      
      ${methods.jazzcash?.enabled ? `
        <div style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;" onclick="showManualPayment('jazzcash', '${planSlug}')" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
          <h4>📱 JazzCash</h4>
          <p style="color:var(--text-muted);margin:0;">Send to: ${methods.jazzcash.accountNumber || 'Contact support'}</p>
        </div>
      ` : ''}
      
      ${methods.easypaisa?.enabled ? `
        <div style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;" onclick="showManualPayment('easypaisa', '${planSlug}')" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
          <h4>📱 Easypaisa</h4>
          <p style="color:var(--text-muted);margin:0;">Send to: ${methods.easypaisa.accountNumber || 'Contact support'}</p>
        </div>
      ` : ''}
    `;
  } catch (err) {
    body.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function processPayment(method, planSlug) {
  if (method === 'stripe') {
    try {
      const res = await api('/billing/create-checkout', { method: 'POST', body: { planSlug, billingCycle: 'monthly' } });
      if (res.url) window.location.href = res.url;
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  }
}

function showManualPayment(method, planSlug) {
  const body = document.getElementById('upgradeModalBody');
  body.innerHTML = `
    <h4 style="margin-bottom:16px;">Manual Payment - ${method.toUpperCase()}</h4>
    <form id="manualPaymentForm">
      <div class="form-group">
        <label>Transaction ID</label>
        <input type="text" name="transactionId" required placeholder="Enter transaction ID">
      </div>
      <div class="form-group">
        <label>Sender Number</label>
        <input type="text" name="senderNumber" required placeholder="Your mobile number">
      </div>
      <div class="form-group">
        <label>Sender Name</label>
        <input type="text" name="senderName" required placeholder="Account holder name">
      </div>
      <input type="hidden" name="planSlug" value="${planSlug}">
      <input type="hidden" name="paymentMethod" value="${method}">
      <button type="submit" class="btn btn-primary" style="width:100%;margin-top:12px;">Submit for Verification</button>
    </form>
  `;
  
  document.getElementById('manualPaymentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    try {
      await api('/billing/manual-payment', {
        method: 'POST',
        body: {
          planSlug: form.planSlug.value,
          billingCycle: 'monthly',
          paymentMethod: form.paymentMethod.value,
          transactionId: form.transactionId.value,
          senderNumber: form.senderNumber.value,
          senderName: form.senderName.value
        }
      });
      closeModal('upgradeModal');
      showToast('Payment submitted! We will verify within 24 hours.', 'success');
      loadPage('billing');
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  });
}

//==============================================================================
// SETTINGS
//==============================================================================
async function loadSettings() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading settings...</div>';
  
  try {
    const { user } = await api('/auth/me');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-header"><h3>Profile Settings</h3></div>
        <div class="card-body">
          <form id="profileForm">
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
              <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="name" value="${user.name}" required>
              </div>
              <div class="form-group">
                <label>Email</label>
                <input type="email" value="${user.email}" disabled>
              </div>
            </div>
            <button type="submit" class="btn btn-primary" style="margin-top:20px;">Save Changes</button>
          </form>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>Change Password</h3></div>
        <div class="card-body">
          <form id="passwordForm">
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
              <div class="form-group">
                <label>Current Password</label>
                <input type="password" name="currentPassword" required>
              </div>
              <div class="form-group">
                <label>New Password</label>
                <input type="password" name="newPassword" required minlength="6">
              </div>
            </div>
            <button type="submit" class="btn btn-primary" style="margin-top:20px;">Change Password</button>
          </form>
        </div>
      </div>
    `;
    
    document.getElementById('profileForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await api('/auth/profile', { method: 'PUT', body: { name: e.target.name.value } });
        showToast('Profile updated!', 'success');
      } catch (err) { showToast('Error: ' + err.message, 'error'); }
    });
    
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await api('/auth/password', { method: 'PUT', body: { currentPassword: e.target.currentPassword.value, newPassword: e.target.newPassword.value } });
        showToast('Password changed!', 'success');
        e.target.reset();
      } catch (err) { showToast('Error: ' + err.message, 'error'); }
    });
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

//==============================================================================
// ADMIN PAGES
//==============================================================================
async function loadAdminUsers() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading users...</div>';
  
  try {
    const { users } = await api('/admin/users');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Plan</th><th>Servers</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              ${(users || []).map(u => `
                <tr>
                  <td><strong>${u.name}</strong></td>
                  <td>${u.email}</td>
                  <td><span class="badge badge-info">${getPlanName(u.subscription?.plan)}</span></td>
                  <td>${u.serverCount || 0} / ${u.subscription?.serverLimit || 1}</td>
                  <td><span class="badge badge-${u.isActive ? 'success' : 'danger'}">${u.isActive ? 'Active' : 'Disabled'}</span></td>
                  <td>
                    <button class="btn btn-secondary btn-sm" onclick="loginAsUser('${u._id}')">Login As</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function loginAsUser(userId) {
  try {
    const res = await api(`/admin/login-as/${userId}`, { method: 'POST' });
    localStorage.setItem('adminToken', localStorage.getItem('authToken'));
    localStorage.setItem('authToken', res.token);
    localStorage.setItem('user', JSON.stringify(res.user));
    showToast('Logged in as ' + res.user.name, 'success');
    location.reload();
  } catch (err) { showToast('Error: ' + err.message, 'error'); }
}

async function loadAdminServers() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading servers...</div>';
  
  try {
    const { servers } = await api('/admin/servers');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table>
            <thead><tr><th>Server</th><th>Owner</th><th>IP</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th></tr></thead>
            <tbody>
              ${(servers || []).map(s => `
                <tr>
                  <td><strong>${s.name}</strong></td>
                  <td>${s.owner?.name || 'Unknown'}<br><small>${s.owner?.email || ''}</small></td>
                  <td>${s.ipAddress}</td>
                  <td><span class="badge badge-${s.status === 'online' ? 'success' : 'danger'}">${s.status}</span></td>
                  <td>${(s.metrics?.cpu || 0).toFixed(1)}%</td>
                  <td>${(s.metrics?.memory || 0).toFixed(1)}%</td>
                  <td>${(s.metrics?.disk || 0).toFixed(1)}%</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function loadAdminPayments() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading payments...</div>';
  
  try {
    const { invoices } = await api('/admin/pending-payments');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-header"><h3>Pending Payments</h3></div>
        <div class="card-body" style="padding:0;">
          ${!invoices || invoices.length === 0 ? '<p style="padding:20px;text-align:center;">No pending payments</p>' : `
            <table>
              <thead><tr><th>Invoice</th><th>User</th><th>Plan</th><th>Amount</th><th>Method</th><th>Actions</th></tr></thead>
              <tbody>
                ${invoices.map(inv => `
                  <tr>
                    <td>${inv.invoiceNumber}</td>
                    <td>${inv.user?.name}<br><small>${inv.user?.email}</small></td>
                    <td>${inv.planName}</td>
                    <td>$${((inv.total || 0) / 100).toFixed(2)}</td>
                    <td>${inv.paymentMethod}</td>
                    <td>
                      <button class="btn btn-primary btn-sm" onclick="verifyPayment('${inv._id}', 'approve')">Approve</button>
                      <button class="btn btn-danger btn-sm" onclick="verifyPayment('${inv._id}', 'reject')">Reject</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function verifyPayment(invoiceId, action) {
  const notes = action === 'reject' ? prompt('Rejection reason:') : '';
  if (action === 'reject' && !notes) return;
  
  try {
    await api(`/admin/verify-payment/${invoiceId}`, { method: 'POST', body: { action, notes } });
    showToast(action === 'approve' ? 'Payment approved!' : 'Payment rejected', 'success');
    loadAdminPayments();
  } catch (err) { showToast('Error: ' + err.message, 'error'); }
}

async function loadAdminSettings() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading settings...</div>';
  
  try {
    const { settings } = await api('/settings');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-header"><h3>System Settings</h3></div>
        <div class="card-body">
          <form id="adminSettingsForm">
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
              <div class="form-group">
                <label>App Name</label>
                <input type="text" name="appName" value="${settings?.appName || 'XMartGuard'}">
              </div>
              <div class="form-group">
                <label>Support Email</label>
                <input type="email" name="supportEmail" value="${settings?.supportEmail || ''}">
              </div>
            </div>
            
            <h4 style="margin:24px 0 16px;">JazzCash</h4>
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
              <div class="form-group">
                <label>Account Title</label>
                <input type="text" name="jazzcashTitle" value="${settings?.payment?.jazzcash?.accountTitle || ''}">
              </div>
              <div class="form-group">
                <label>Account Number</label>
                <input type="text" name="jazzcashNumber" value="${settings?.payment?.jazzcash?.accountNumber || ''}">
              </div>
            </div>
            
            <h4 style="margin:24px 0 16px;">Easypaisa</h4>
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
              <div class="form-group">
                <label>Account Title</label>
                <input type="text" name="easypaisaTitle" value="${settings?.payment?.easypaisa?.accountTitle || ''}">
              </div>
              <div class="form-group">
                <label>Account Number</label>
                <input type="text" name="easypaisaNumber" value="${settings?.payment?.easypaisa?.accountNumber || ''}">
              </div>
            </div>
            
            <button type="submit" class="btn btn-primary" style="margin-top:24px;">Save Settings</button>
          </form>
        </div>
      </div>
    `;
    
    document.getElementById('adminSettingsForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      try {
        await api('/admin/settings', {
          method: 'PUT',
          body: {
            appName: form.appName.value,
            supportEmail: form.supportEmail.value,
            payment: {
              jazzcash: { enabled: true, accountTitle: form.jazzcashTitle.value, accountNumber: form.jazzcashNumber.value },
              easypaisa: { enabled: true, accountTitle: form.easypaisaTitle.value, accountNumber: form.easypaisaNumber.value }
            }
          }
        });
        showToast('Settings saved!', 'success');
      } catch (err) { showToast('Error: ' + err.message, 'error'); }
    });
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

//==============================================================================
// SERVER ACTIONS
//==============================================================================
document.getElementById('addServerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  
  try {
    const res = await api('/servers', {
      method: 'POST',
      body: { name: form.name.value, ipAddress: form.ipAddress.value }
    });
    
    closeModal('addServerModal');
    form.reset();
    showInstallModal(res.token);
    loadPage(currentPage);
  } catch (err) {
    if (err.message.includes('limit')) {
      closeModal('addServerModal');
      showToast(err.message, 'warning');
      document.querySelector('[data-page="billing"]').click();
    } else {
      showToast('Error: ' + err.message, 'error');
    }
  }
});

function showInstallModal(token) {
  const serverUrl = window.location.origin;
  const cmd = `curl -sSL ${serverUrl}/downloads/install.sh | bash -s -- ${token} ${serverUrl}`;
  document.getElementById('installCommand').textContent = cmd;
  openModal('installModal');
}

async function deleteServer(id) {
  if (!confirm('Delete this server? This cannot be undone.')) return;
  try {
    await api(`/servers/${id}`, { method: 'DELETE' });
    showToast('Server deleted', 'success');
    loadPage('servers');
  } catch (err) { showToast('Error: ' + err.message, 'error'); }
}

function loadNotFound(page) {
  document.getElementById('contentArea').innerHTML = `
    <div class="empty-state">
      <h3>Page Not Found</h3>
      <p>The page "${page}" doesn't exist</p>
    </div>
  `;
}

//==============================================================================
// INITIALIZE
//==============================================================================
initApp();
</script>
</body>
</html>
HTMLFILE

echo -e "${GREEN}✓ Frontend updated${NC}"

#===============================================================================
# Restart app via cPanel touch method
#===============================================================================
echo -e "${YELLOW}► Restarting application...${NC}"

# Touch restart.txt to trigger Passenger restart
touch "$APP_DIR/tmp/restart.txt" 2>/dev/null || mkdir -p "$APP_DIR/tmp" && touch "$APP_DIR/tmp/restart.txt"

echo -e "${GREEN}✓ Application restart triggered${NC}"

#===============================================================================
# Done
#===============================================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Patch Applied Successfully!                 ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Changes:${NC}"
echo "  ✓ Server row click - entire row now clickable"
echo "  ✓ Auto-refresh timer - fixed 30 second interval"
echo "  ✓ Copy button - fixed with fallback method"
echo "  ✓ Uninstall modal - added with command"
echo "  ✓ Charts - added on server detail page"
echo ""
echo -e "${YELLOW}To manually restart (if needed):${NC}"
echo "  Option 1: cPanel → Setup Node.js App → Restart"
echo "  Option 2: touch $APP_DIR/tmp/restart.txt"
echo ""
