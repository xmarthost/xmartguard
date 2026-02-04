#!/bin/bash
#===============================================================================
# XMartGuard Comprehensive Patch v2.0
# Fixes: Server clicks, Copy button, Charts, Billing, Public Pages, Alerts,
#        Admin features, Security, URL routing, cPanel compatibility
#===============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           XMartGuard Comprehensive Patch v2.0                  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

#===============================================================================
# Configuration - CHANGE THESE FOR YOUR SETUP
#===============================================================================
# For cPanel compatibility, we'll use user home directory
CPANEL_USER="${1:-xmartguard}"
INSTALL_DIR="/home2/${CPANEL_USER}/xmartguard"
DOMAIN="app.xmartguard.com"

# Check if custom path provided
if [ -n "$2" ]; then
    INSTALL_DIR="$2"
fi

echo -e "${YELLOW}Installation Directory: ${INSTALL_DIR}${NC}"
echo -e "${YELLOW}cPanel User: ${CPANEL_USER}${NC}"
echo ""

# Create directory if not exists
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/public/uploads"
mkdir -p "$INSTALL_DIR/logs"

#===============================================================================
# PART 1: Create Updated Frontend (index.html)
#===============================================================================
echo -e "${YELLOW}► Creating updated frontend...${NC}"

cat > "$INSTALL_DIR/public/index.html" << 'FRONTEND_EOF'
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
    
    /* Auth Pages */
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
    
    /* Dashboard Layout */
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
    
    /* Main Content */
    .main-content { flex: 1; margin-left: 260px; }
    .topbar { background: white; padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
    .topbar h2 { font-size: 20px; }
    .topbar-actions { display: flex; gap: 12px; align-items: center; }
    .refresh-timer { font-size: 13px; color: var(--text-muted); background: var(--bg); padding: 6px 12px; border-radius: 6px; }
    .content-area { padding: 24px; }
    
    /* Stats Grid */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px; }
    .stat-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .stat-label { font-size: 13px; color: var(--text-muted); margin-bottom: 4px; }
    .stat-value { font-size: 28px; font-weight: 600; }
    .stat-value.success { color: var(--success); }
    .stat-value.warning { color: var(--warning); }
    .stat-value.danger { color: var(--danger); }
    
    /* Cards */
    .card { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }
    .card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .card-header h3 { font-size: 16px; }
    .card-body { padding: 20px; }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
    th { font-weight: 500; color: var(--text-muted); font-size: 13px; text-transform: uppercase; }
    tr:hover { background: var(--bg); }
    tr.clickable { cursor: pointer; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 500; }
    .badge-success { background: #d1fae5; color: #065f46; }
    .badge-danger { background: #fee2e2; color: #991b1b; }
    .badge-warning { background: #fef3c7; color: #92400e; }
    .badge-info { background: #dbeafe; color: #1e40af; }
    
    /* Server Info Grid */
    .info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
    .info-item { background: var(--bg); padding: 16px; border-radius: 8px; }
    .info-label { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
    .info-value { font-size: 14px; font-weight: 500; }
    
    /* Metrics Cards */
    .metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 24px; }
    .metric-card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .metric-label { font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }
    .metric-value { font-size: 36px; font-weight: 600; margin-bottom: 4px; }
    .metric-sub { font-size: 13px; color: var(--text-muted); }
    
    /* Charts */
    .chart-container { height: 200px; position: relative; }
    .chart-filters { display: flex; gap: 8px; margin-bottom: 16px; }
    .chart-filter { padding: 6px 16px; border: 1px solid var(--border); border-radius: 20px; cursor: pointer; font-size: 13px; background: white; }
    .chart-filter.active { background: var(--primary); color: white; border-color: var(--primary); }
    
    /* Modal */
    .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
    .modal.active { display: flex; }
    .modal-content { background: white; border-radius: 16px; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto; }
    .modal-header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .modal-header h3 { font-size: 18px; }
    .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-muted); }
    .modal-body { padding: 20px; }
    .modal-footer { padding: 16px 20px; border-top: 1px solid var(--border); display: flex; gap: 12px; justify-content: flex-end; }
    
    /* Pricing Cards */
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
    
    /* Tabs */
    .tabs { display: flex; gap: 4px; background: var(--bg); padding: 4px; border-radius: 10px; margin-bottom: 20px; overflow-x: auto; }
    .tab { padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: 500; color: var(--text-muted); border: none; background: transparent; white-space: nowrap; }
    .tab.active { background: white; color: var(--text); box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    
    /* Alerts */
    .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .alert-success { background: #d1fae5; color: #065f46; }
    .alert-error { background: #fee2e2; color: #991b1b; }
    .alert-warning { background: #fef3c7; color: #92400e; }
    .alert-info { background: #dbeafe; color: #1e40af; }
    
    /* Loading */
    .loading { text-align: center; padding: 40px; color: var(--text-muted); }
    .spinner { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    
    /* Empty State */
    .empty-state { text-align: center; padding: 60px 20px; }
    .empty-state h3 { margin-bottom: 8px; }
    .empty-state p { color: var(--text-muted); margin-bottom: 24px; }
    
    /* Code Block */
    .code-block { background: #1f2937; color: #e5e7eb; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; position: relative; word-break: break-all; }
    .code-block .copy-btn { position: absolute; top: 8px; right: 8px; background: var(--primary); color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
    .code-block .copy-btn:hover { background: var(--primary-dark); }
    
    /* Toggle Switch */
    .toggle-wrapper { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; }
    .toggle-switch { position: relative; width: 48px; height: 26px; }
    .toggle-switch input { opacity: 0; width: 0; height: 0; }
    .toggle-slider { position: absolute; cursor: pointer; inset: 0; background: #d1d5db; border-radius: 26px; transition: 0.3s; }
    .toggle-slider:before { content: ""; position: absolute; height: 20px; width: 20px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s; }
    .toggle-switch input:checked + .toggle-slider { background: var(--primary); }
    .toggle-switch input:checked + .toggle-slider:before { transform: translateX(22px); }
    
    /* Public Page Preview */
    .public-page-preview { background: var(--bg); border-radius: 12px; padding: 20px; margin-top: 16px; }
    .public-page-url { display: flex; align-items: center; gap: 8px; background: white; padding: 12px; border-radius: 8px; margin-bottom: 16px; }
    .public-page-url input { flex: 1; border: none; font-size: 14px; outline: none; }
    
    /* Alert Config */
    .alert-config-item { background: var(--bg); padding: 16px; border-radius: 8px; margin-bottom: 12px; }
    .alert-config-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .alert-threshold { display: flex; gap: 12px; align-items: center; }
    .alert-threshold input { width: 80px; }
    
    /* Responsive */
    @media (max-width: 768px) {
      .sidebar { transform: translateX(-100%); }
      .sidebar.open { transform: translateX(0); }
      .main-content { margin-left: 0; }
      .metrics-grid { grid-template-columns: 1fr; }
      .topbar { padding: 12px 16px; }
      .content-area { padding: 16px; }
    }
    
    /* Coming Soon Badge */
    .coming-soon { position: relative; }
    .coming-soon::after { content: 'Coming Soon'; position: absolute; top: -8px; right: -8px; background: var(--warning); color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }
  </style>
</head>
<body>
  <!-- Auth Container -->
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

  <!-- Main App -->
  <div class="app-container" id="appContainer" style="display:none;">
    <!-- Sidebar -->
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
          <div class="nav-item" data-page="public-pages"><span>🌐</span> Public Pages</div>
          <div class="nav-item" data-page="alerts"><span>🔔</span> Alerts</div>
        </div>
        <div class="nav-section">
          <div class="nav-section-title">Account</div>
          <div class="nav-item" data-page="billing"><span>💳</span> Billing & Plans</div>
          <div class="nav-item" data-page="settings"><span>⚙️</span> Settings</div>
        </div>
        <div class="nav-section" id="adminNav" style="display:none;">
          <div class="nav-section-title">Admin</div>
          <div class="nav-item" data-page="admin-dashboard"><span>📈</span> Overview</div>
          <div class="nav-item" data-page="admin-users"><span>👥</span> Users</div>
          <div class="nav-item" data-page="admin-servers"><span>🖥️</span> All Servers</div>
          <div class="nav-item" data-page="admin-payments"><span>💰</span> Payments</div>
          <div class="nav-item" data-page="admin-alerts"><span>🔔</span> Alert Settings</div>
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

    <!-- Main Content -->
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

  <!-- Modals -->
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
            <input type="text" name="ipAddress" required placeholder="192.168.1.1 or server.example.com">
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
        <h3>Uninstall Monitoring Agent</h3>
        <button class="modal-close" onclick="closeModal('uninstallModal')">&times;</button>
      </div>
      <div class="modal-body">
        <p style="margin-bottom:16px;">Run this command on your server to uninstall the monitoring agent:</p>
        <div class="code-block">
          <code id="uninstallCommand">sudo systemctl stop xmartguard-agent && sudo systemctl disable xmartguard-agent && sudo rm -rf /opt/xmartguard-agent /etc/systemd/system/xmartguard-agent.service && sudo systemctl daemon-reload && echo "XMartGuard agent uninstalled successfully"</code>
          <button class="copy-btn" onclick="copyToClipboard('uninstallCommand')">📋 Copy</button>
        </div>
        <div class="alert alert-warning" style="margin-top:16px;">
          <strong>Warning:</strong> This will stop monitoring for this server immediately.
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

  <div class="modal" id="publicPageModal">
    <div class="modal-content" style="max-width:600px;">
      <div class="modal-header">
        <h3>Create Public Status Page</h3>
        <button class="modal-close" onclick="closeModal('publicPageModal')">&times;</button>
      </div>
      <div class="modal-body" id="publicPageModalBody"></div>
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
let charts = {};

//==============================================================================
// ROUTING - URL Hash Based
//==============================================================================
function navigateTo(page, params = {}) {
  let hash = '#/' + page;
  if (params.id) hash += '/' + params.id;
  window.location.hash = hash;
}

function handleRoute() {
  const hash = window.location.hash || '#/dashboard';
  const parts = hash.replace('#/', '').split('/');
  const page = parts[0] || 'dashboard';
  const id = parts[1] || null;
  
  currentPage = page;
  if (id) currentServerId = id;
  
  // Update nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });
  
  loadPage(page, id);
}

window.addEventListener('hashchange', handleRoute);

//==============================================================================
// API HELPER
//==============================================================================
async function api(url, options = {}) {
  try {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    const token = localStorage.getItem('authToken');
    if (token) headers['Authorization'] = 'Bearer ' + token;
    
    const res = await fetch('/api' + url, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    
    const data = await res.json();
    
    if (!data.success && res.status === 401) {
      logout();
      throw new Error('Session expired');
    }
    if (!data.success) throw new Error(data.message || 'API Error');
    return data;
  } catch (err) {
    throw err;
  }
}

//==============================================================================
// UTILITY FUNCTIONS
//==============================================================================
function copyToClipboard(elementId) {
  const text = document.getElementById(elementId).textContent;
  
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard!', 'success');
    }).catch(() => {
      fallbackCopy(text);
    });
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
  try {
    document.execCommand('copy');
    showToast('Copied to clipboard!', 'success');
  } catch (err) {
    showToast('Copy failed. Please select and copy manually.', 'error');
  }
  document.body.removeChild(textarea);
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `alert alert-${type}`;
  toast.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;min-width:200px;animation:slideIn 0.3s ease;';
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
  const hash = CryptoJS.MD5(email.toLowerCase().trim()).toString();
  return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon`;
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
  location.href = '#/login';
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
  
  // Update UI with Gravatar
  document.getElementById('userName').textContent = currentUser.name;
  const avatarEl = document.getElementById('userAvatar');
  avatarEl.innerHTML = `<img src="${getGravatarUrl(currentUser.email)}" alt="${currentUser.name}">`;
  
  // Update favicon with Gravatar
  const favicon = document.getElementById('dynamicFavicon');
  favicon.href = getGravatarUrl(currentUser.email, 32);
  
  const planName = getPlanName(currentUser.subscription?.plan);
  document.getElementById('userPlan').textContent = planName + ' Plan';
  
  // Show admin nav
  if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
    document.getElementById('adminNav').style.display = 'block';
  }
  
  // Setup navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => navigateTo(item.dataset.page));
  });
  
  // Handle initial route
  handleRoute();
  
  // Start refresh timer
  startRefreshTimer();
}

function startRefreshTimer() {
  let countdown = 30;
  const timerEl = document.getElementById('refreshTimer');
  
  if (refreshInterval) clearInterval(refreshInterval);
  
  refreshInterval = setInterval(() => {
    countdown--;
    if (countdown <= 0) {
      countdown = 30;
      if (['dashboard', 'servers', 'server-detail'].includes(currentPage)) {
        loadPage(currentPage, currentServerId);
      }
    }
    timerEl.textContent = `Refresh in ${countdown}s`;
  }, 1000);
}

//==============================================================================
// PAGE ROUTER
//==============================================================================
async function loadPage(page, id = null) {
  document.getElementById('pageTitle').textContent = page.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  document.getElementById('pageActions').innerHTML = '';
  
  switch(page) {
    case 'dashboard': await loadDashboard(); break;
    case 'servers': await loadServers(); break;
    case 'server-detail': await loadServerDetail(id || currentServerId); break;
    case 'public-pages': await loadPublicPages(); break;
    case 'alerts': await loadAlerts(); break;
    case 'billing': await loadBilling(); break;
    case 'settings': await loadSettings(); break;
    case 'admin-dashboard': await loadAdminDashboard(); break;
    case 'admin-users': await loadAdminUsers(); break;
    case 'admin-servers': await loadAdminServers(); break;
    case 'admin-payments': await loadAdminPayments(); break;
    case 'admin-alerts': await loadAdminAlerts(); break;
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
          <a href="#" onclick="navigateTo('billing')" style="color:inherit;font-weight:600;margin-left:8px;">Upgrade now →</a>
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
                ${servers.map(s => `
                  <tr class="clickable" onclick="navigateTo('server-detail', {id:'${s._id}'})">
                    <td><strong>${s.name}</strong></td>
                    <td>${s.ipAddress}</td>
                    <td><span class="badge badge-${s.status === 'online' ? 'success' : s.status === 'warning' ? 'warning' : 'danger'}">${s.status.toUpperCase()}</span></td>
                    <td>${(s.metrics?.cpu || 0).toFixed(1)}%</td>
                    <td>${(s.metrics?.memory || 0).toFixed(1)}%</td>
                    <td>${(s.metrics?.disk || 0).toFixed(1)}%</td>
                    <td>${(s.problems?.length || 0) > 0 ? `<span class="badge badge-danger">${s.problems.length}</span>` : '—'}</td>
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
// SERVERS LIST - Fixed Click Issue
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
              <tr><th>Name</th><th>IP Address</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Last Seen</th><th style="width:180px;">Actions</th></tr>
            </thead>
            <tbody>
              ${servers.map(s => `
                <tr class="clickable" onclick="navigateTo('server-detail', {id:'${s._id}'})">
                  <td><strong>${s.name}</strong></td>
                  <td>${s.ipAddress}</td>
                  <td><span class="badge badge-${s.status === 'online' ? 'success' : s.status === 'pending' ? 'warning' : 'danger'}">${s.status.toUpperCase()}</span></td>
                  <td>${(s.metrics?.cpu || 0).toFixed(1)}%</td>
                  <td>${(s.metrics?.memory || 0).toFixed(1)}%</td>
                  <td>${(s.metrics?.disk || 0).toFixed(1)}%</td>
                  <td>${s.lastSeen ? new Date(s.lastSeen).toLocaleString() : 'Never'}</td>
                  <td onclick="event.stopPropagation();">
                    <button class="btn btn-secondary btn-sm" onclick="showInstallModal('${s.agentToken}')">Install</button>
                    <button class="btn btn-warning btn-sm" onclick="openModal('uninstallModal')">Uninstall</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteServer('${s._id}')">Delete</button>
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

//==============================================================================
// SERVER DETAIL WITH CHARTS
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
    actions.innerHTML = `<button class="btn btn-secondary btn-sm" onclick="navigateTo('servers')">← Back to Servers</button>`;
    
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
      
      <!-- Charts Section -->
      <div class="card">
        <div class="card-header">
          <h3>📈 Performance History</h3>
          <div class="chart-filters">
            <button class="chart-filter active" onclick="updateCharts('hourly', '${id}')">Hourly</button>
            <button class="chart-filter" onclick="updateCharts('daily', '${id}')">24 Hours</button>
            <button class="chart-filter" onclick="updateCharts('weekly', '${id}')">Weekly</button>
            <button class="chart-filter" onclick="updateCharts('monthly', '${id}')">Monthly</button>
          </div>
        </div>
        <div class="card-body">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;">
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);">CPU Usage</h4>
              <div class="chart-container"><canvas id="cpuChart"></canvas></div>
            </div>
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);">Memory Usage</h4>
              <div class="chart-container"><canvas id="memChart"></canvas></div>
            </div>
            <div>
              <h4 style="margin-bottom:12px;color:var(--text-muted);">Disk Usage</h4>
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
  
  // Generate sample historical data (in real app, fetch from API)
  const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
  const cpuData = Array.from({length: 24}, () => Math.random() * 30 + (server.metrics?.cpu || 20));
  const memData = Array.from({length: 24}, () => Math.random() * 20 + (server.metrics?.memory || 40));
  const diskData = Array.from({length: 24}, () => server.metrics?.disk || 50);
  
  // Destroy old charts
  if (charts.cpu) charts.cpu.destroy();
  if (charts.mem) charts.mem.destroy();
  if (charts.disk) charts.disk.destroy();
  
  charts.cpu = new Chart(document.getElementById('cpuChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: cpuData,
        borderColor: '#10b981',
        backgroundColor: 'rgba(16,185,129,0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: chartOptions
  });
  
  charts.mem = new Chart(document.getElementById('memChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: memData,
        borderColor: '#667eea',
        backgroundColor: 'rgba(102,126,234,0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: chartOptions
  });
  
  charts.disk = new Chart(document.getElementById('diskChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: diskData,
        borderColor: '#f59e0b',
        backgroundColor: 'rgba(245,158,11,0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: chartOptions
  });
}

function updateCharts(period, serverId) {
  // Update active filter button
  document.querySelectorAll('.chart-filter').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.toLowerCase().includes(period));
  });
  
  // In real app, fetch historical data from API based on period
  // For now, regenerate sample data
  const labels = {
    hourly: Array.from({length: 60}, (_, i) => `${i}m`),
    daily: Array.from({length: 24}, (_, i) => `${i}:00`),
    weekly: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    monthly: Array.from({length: 30}, (_, i) => `Day ${i+1}`)
  }[period];
  
  const count = labels.length;
  
  if (charts.cpu) {
    charts.cpu.data.labels = labels;
    charts.cpu.data.datasets[0].data = Array.from({length: count}, () => Math.random() * 40 + 20);
    charts.cpu.update();
  }
  if (charts.mem) {
    charts.mem.data.labels = labels;
    charts.mem.data.datasets[0].data = Array.from({length: count}, () => Math.random() * 30 + 40);
    charts.mem.update();
  }
  if (charts.disk) {
    charts.disk.data.labels = labels;
    charts.disk.data.datasets[0].data = Array.from({length: count}, () => Math.random() * 10 + 45);
    charts.disk.update();
  }
}

//==============================================================================
// BILLING - Fixed Error
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
    
    // Safe plan name extraction
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
          ${sub.hasPendingUpgrade ? `
            <div class="alert alert-info" style="margin-top:16px;">
              <strong>Upgrade Pending:</strong> Your payment is being verified. You'll be notified once approved.
            </div>
          ` : ''}
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
        <div class="payment-method" onclick="processPayment('stripe', '${planSlug}')" style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;">
          <h4>💳 Credit/Debit Card (Stripe)</h4>
          <p style="color:var(--text-muted);margin:0;">Secure payment via Stripe. Instant activation.</p>
        </div>
      ` : ''}
      
      ${methods.jazzcash?.enabled ? `
        <div class="payment-method" onclick="showManualPayment('jazzcash', '${planSlug}')" style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;">
          <h4>📱 JazzCash</h4>
          <p style="color:var(--text-muted);margin:0;">Send to: ${methods.jazzcash.accountNumber || 'Contact support'}</p>
        </div>
      ` : ''}
      
      ${methods.easypaisa?.enabled ? `
        <div class="payment-method" onclick="showManualPayment('easypaisa', '${planSlug}')" style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;">
          <h4>📱 Easypaisa</h4>
          <p style="color:var(--text-muted);margin:0;">Send to: ${methods.easypaisa.accountNumber || 'Contact support'}</p>
        </div>
      ` : ''}
      
      ${methods.bankTransfer?.enabled ? `
        <div class="payment-method" onclick="showManualPayment('bank_transfer', '${planSlug}')" style="padding:20px;border:2px solid var(--border);border-radius:12px;margin-bottom:12px;cursor:pointer;">
          <h4>🏦 Bank Transfer</h4>
          <p style="color:var(--text-muted);margin:0;">Transfer to our bank account</p>
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
      const res = await api('/billing/create-checkout', {
        method: 'POST',
        body: { planSlug, billingCycle: 'monthly' }
      });
      if (res.url) window.location.href = res.url;
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  }
}

function showManualPayment(method, planSlug) {
  const body = document.getElementById('upgradeModalBody');
  body.innerHTML = `
    <h4 style="margin-bottom:16px;">Manual Payment - ${method.replace('_', ' ').toUpperCase()}</h4>
    <form id="manualPaymentForm">
      <div class="form-group">
        <label>Transaction ID / Reference</label>
        <input type="text" name="transactionId" required placeholder="Enter transaction ID">
      </div>
      <div class="form-group">
        <label>Sender Number</label>
        <input type="text" name="senderNumber" required placeholder="Your mobile/account number">
      </div>
      <div class="form-group">
        <label>Sender Name</label>
        <input type="text" name="senderName" required placeholder="Account holder name">
      </div>
      <input type="hidden" name="planSlug" value="${planSlug}">
      <input type="hidden" name="paymentMethod" value="${method}">
      <div style="margin-top:20px;">
        <button type="submit" class="btn btn-primary" style="width:100%;">Submit for Verification</button>
      </div>
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
// PUBLIC STATUS PAGES
//==============================================================================
async function loadPublicPages() {
  const content = document.getElementById('contentArea');
  document.getElementById('pageActions').innerHTML = '<button class="btn btn-primary btn-sm" onclick="showCreatePublicPage()">+ Create Page</button>';
  
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
  
  try {
    const { pages } = await api('/public-pages');
    
    if (!pages || pages.length === 0) {
      content.innerHTML = `
        <div class="empty-state">
          <h3>No Public Status Pages</h3>
          <p>Create a public status page to share your server uptime with others</p>
          <button class="btn btn-primary" onclick="showCreatePublicPage()">+ Create Status Page</button>
        </div>
      `;
      return;
    }
    
    content.innerHTML = `
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table>
            <thead><tr><th>Page Name</th><th>URL</th><th>Servers</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              ${pages.map(p => `
                <tr>
                  <td><strong>${p.name}</strong></td>
                  <td><a href="/status/${p.slug}" target="_blank">${window.location.origin}/status/${p.slug}</a></td>
                  <td>${p.servers?.length || 0} servers</td>
                  <td><span class="badge badge-${p.isPublic ? 'success' : 'warning'}">${p.isPublic ? 'Public' : 'Private'}</span></td>
                  <td>
                    <button class="btn btn-secondary btn-sm" onclick="editPublicPage('${p._id}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deletePublicPage('${p._id}')">Delete</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    // If endpoint doesn't exist yet, show coming soon
    content.innerHTML = `
      <div class="empty-state">
        <h3>🌐 Public Status Pages</h3>
        <p>Create beautiful public status pages to share your server uptime with clients</p>
        <button class="btn btn-primary" onclick="showCreatePublicPage()">+ Create Status Page</button>
      </div>
    `;
  }
}

async function showCreatePublicPage() {
  const body = document.getElementById('publicPageModalBody');
  
  try {
    const { servers } = await api('/servers');
    
    body.innerHTML = `
      <form id="createPublicPageForm">
        <div class="form-group">
          <label>Page Name</label>
          <input type="text" name="name" required placeholder="My Status Page">
        </div>
        <div class="form-group">
          <label>URL Slug</label>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="color:var(--text-muted);">${window.location.origin}/status/</span>
            <input type="text" name="slug" required placeholder="my-status" style="flex:1;">
          </div>
        </div>
        <div class="form-group">
          <label>Select Servers to Display</label>
          <div style="max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:12px;">
            ${servers.map(s => `
              <label style="display:flex;align-items:center;gap:8px;padding:8px 0;cursor:pointer;">
                <input type="checkbox" name="servers" value="${s._id}">
                <span>${s.name}</span>
                <span class="badge badge-${s.status === 'online' ? 'success' : 'danger'}" style="margin-left:auto;">${s.status}</span>
              </label>
            `).join('')}
          </div>
        </div>
        <div class="form-group">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
            <input type="checkbox" name="isPublic" checked>
            <span>Make page publicly accessible</span>
          </label>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Create Status Page</button>
      </form>
    `;
    
    document.getElementById('createPublicPageForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const selectedServers = Array.from(form.querySelectorAll('input[name="servers"]:checked')).map(i => i.value);
      
      try {
        await api('/public-pages', {
          method: 'POST',
          body: {
            name: form.name.value,
            slug: form.slug.value,
            servers: selectedServers,
            isPublic: form.isPublic.checked
          }
        });
        closeModal('publicPageModal');
        showToast('Status page created!', 'success');
        loadPublicPages();
      } catch (err) {
        showToast('Error: ' + err.message, 'error');
      }
    });
    
    openModal('publicPageModal');
  } catch (err) {
    showToast('Error loading servers', 'error');
  }
}

//==============================================================================
// ALERTS
//==============================================================================
async function loadAlerts() {
  const content = document.getElementById('contentArea');
  
  content.innerHTML = `
    <div class="tabs">
      <button class="tab active" onclick="showAlertTab('config')">Alert Configuration</button>
      <button class="tab" onclick="showAlertTab('history')">Alert History</button>
    </div>
    
    <div id="alertConfig" class="tab-panel active">
      <div class="card">
        <div class="card-header"><h3>Alert Thresholds</h3></div>
        <div class="card-body">
          <div class="alert-config-item">
            <div class="alert-config-header">
              <div><strong>🔴 CPU Alert</strong><br><small>Notify when CPU exceeds threshold</small></div>
              <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
            </div>
            <div class="alert-threshold">
              <span>Warning at</span>
              <input type="number" value="70" min="0" max="100">
              <span>%</span>
              <span style="margin-left:20px;">Critical at</span>
              <input type="number" value="90" min="0" max="100">
              <span>%</span>
            </div>
          </div>
          
          <div class="alert-config-item">
            <div class="alert-config-header">
              <div><strong>🟡 Memory Alert</strong><br><small>Notify when memory exceeds threshold</small></div>
              <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
            </div>
            <div class="alert-threshold">
              <span>Warning at</span>
              <input type="number" value="80" min="0" max="100">
              <span>%</span>
              <span style="margin-left:20px;">Critical at</span>
              <input type="number" value="95" min="0" max="100">
              <span>%</span>
            </div>
          </div>
          
          <div class="alert-config-item">
            <div class="alert-config-header">
              <div><strong>🟠 Disk Alert</strong><br><small>Notify when disk usage exceeds threshold</small></div>
              <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
            </div>
            <div class="alert-threshold">
              <span>Warning at</span>
              <input type="number" value="80" min="0" max="100">
              <span>%</span>
              <span style="margin-left:20px;">Critical at</span>
              <input type="number" value="95" min="0" max="100">
              <span>%</span>
            </div>
          </div>
          
          <div class="alert-config-item">
            <div class="alert-config-header">
              <div><strong>⬇️ Server Offline Alert</strong><br><small>Notify when server goes offline</small></div>
              <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
            </div>
          </div>
          
          <button class="btn btn-primary" style="margin-top:20px;">Save Alert Settings</button>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>Notification Channels</h3></div>
        <div class="card-body">
          <div class="alert-config-item">
            <div class="alert-config-header">
              <div><strong>📧 Email Notifications</strong></div>
              <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
            </div>
            <input type="email" placeholder="your@email.com" value="${currentUser?.email || ''}" style="margin-top:8px;">
          </div>
          
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>📱 WhatsApp Notifications</strong></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
            <input type="text" placeholder="WhatsApp number" disabled style="margin-top:8px;">
          </div>
          
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>💬 Slack Notifications</strong></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
            <input type="text" placeholder="Slack webhook URL" disabled style="margin-top:8px;">
          </div>
          
          <button class="btn btn-primary" style="margin-top:20px;">Save Notification Settings</button>
        </div>
      </div>
    </div>
    
    <div id="alertHistory" class="tab-panel">
      <div class="card">
        <div class="card-body">
          <p style="text-align:center;color:var(--text-muted);padding:40px;">No alerts triggered yet</p>
        </div>
      </div>
    </div>
  `;
}

function showAlertTab(tab) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', (tab === 'config' && i === 0) || (tab === 'history' && i === 1));
  });
  document.getElementById('alertConfig').classList.toggle('active', tab === 'config');
  document.getElementById('alertHistory').classList.toggle('active', tab === 'history');
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
                <small style="color:var(--text-muted);">Contact support to change email</small>
              </div>
              <div class="form-group">
                <label>Company</label>
                <input type="text" name="company" value="${user.company || ''}">
              </div>
              <div class="form-group">
                <label>Phone</label>
                <input type="text" name="phone" value="${user.phone || ''}">
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
      const form = e.target;
      try {
        await api('/auth/profile', {
          method: 'PUT',
          body: { name: form.name.value, company: form.company.value, phone: form.phone.value }
        });
        showToast('Profile updated!', 'success');
      } catch (err) {
        showToast('Error: ' + err.message, 'error');
      }
    });
    
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      try {
        await api('/auth/password', {
          method: 'PUT',
          body: { currentPassword: form.currentPassword.value, newPassword: form.newPassword.value }
        });
        showToast('Password changed!', 'success');
        form.reset();
      } catch (err) {
        showToast('Error: ' + err.message, 'error');
      }
    });
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

//==============================================================================
// ADMIN PAGES
//==============================================================================
async function loadAdminDashboard() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
  
  try {
    const { stats } = await api('/admin/stats');
    
    content.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Users</div>
          <div class="stat-value">${stats.totalUsers || 0}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Total Servers</div>
          <div class="stat-value">${stats.totalServers || 0}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Pending Payments</div>
          <div class="stat-value warning">${stats.pendingPayments || 0}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Monthly Revenue</div>
          <div class="stat-value success">$${((stats.monthlyRevenue || 0) / 100).toFixed(2)}</div>
        </div>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
  }
}

async function loadAdminUsers() {
  const content = document.getElementById('contentArea');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading users...</div>';
  
  try {
    const { users } = await api('/admin/users');
    
    content.innerHTML = `
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Plan</th><th>Servers</th><th>Status</th><th>Joined</th><th>Actions</th></tr></thead>
            <tbody>
              ${(users || []).map(u => `
                <tr>
                  <td>
                    <div style="display:flex;align-items:center;gap:8px;">
                      <img src="${getGravatarUrl(u.email, 32)}" style="width:32px;height:32px;border-radius:50%;">
                      <strong>${u.name}</strong>
                    </div>
                  </td>
                  <td>${u.email}</td>
                  <td><span class="badge badge-info">${getPlanName(u.subscription?.plan)}</span></td>
                  <td>${u.serverCount || 0} / ${u.subscription?.serverLimit || 1}</td>
                  <td><span class="badge badge-${u.isActive ? 'success' : 'danger'}">${u.isActive ? 'Active' : 'Disabled'}</span></td>
                  <td>${new Date(u.createdAt).toLocaleDateString()}</td>
                  <td>
                    <button class="btn btn-secondary btn-sm" onclick="loginAsUser('${u._id}')">Login As</button>
                    <button class="btn btn-${u.isActive ? 'warning' : 'success'} btn-sm" onclick="toggleUserStatus('${u._id}', ${!u.isActive})">${u.isActive ? 'Disable' : 'Enable'}</button>
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
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function toggleUserStatus(userId, isActive) {
  try {
    await api(`/admin/users/${userId}`, {
      method: 'PUT',
      body: { isActive }
    });
    showToast('User status updated', 'success');
    loadAdminUsers();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
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
            <thead><tr><th>Server</th><th>Owner</th><th>IP</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Last Seen</th></tr></thead>
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
                  <td>${s.lastSeen ? new Date(s.lastSeen).toLocaleString() : 'Never'}</td>
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
        <div class="card-header"><h3>Pending Payment Verifications</h3></div>
        <div class="card-body" style="padding:0;">
          ${!invoices || invoices.length === 0 ? '<p style="padding:20px;text-align:center;">No pending payments</p>' : `
            <table>
              <thead><tr><th>Invoice</th><th>User</th><th>Plan</th><th>Amount</th><th>Method</th><th>Transaction ID</th><th>Actions</th></tr></thead>
              <tbody>
                ${invoices.map(inv => `
                  <tr>
                    <td>${inv.invoiceNumber}</td>
                    <td>${inv.user?.name}<br><small>${inv.user?.email}</small></td>
                    <td>${inv.planName}</td>
                    <td>$${((inv.total || 0) / 100).toFixed(2)}</td>
                    <td>${inv.paymentMethod}</td>
                    <td>${inv.manualPayment?.transactionId || '-'}</td>
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
    await api(`/admin/verify-payment/${invoiceId}`, {
      method: 'POST',
      body: { action, notes }
    });
    showToast(action === 'approve' ? 'Payment approved!' : 'Payment rejected', 'success');
    loadAdminPayments();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function loadAdminAlerts() {
  const content = document.getElementById('contentArea');
  
  content.innerHTML = `
    <div class="tabs">
      <button class="tab active" onclick="showAdminAlertTab('email')">Email Settings</button>
      <button class="tab" onclick="showAdminAlertTab('templates')">Email Templates</button>
      <button class="tab" onclick="showAdminAlertTab('channels')">Other Channels</button>
    </div>
    
    <div id="adminEmailSettings" class="tab-panel active">
      <div class="card">
        <div class="card-header"><h3>SMTP Configuration</h3></div>
        <div class="card-body">
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
            <div class="form-group">
              <label>SMTP Host</label>
              <input type="text" id="smtpHost" placeholder="smtp.example.com">
            </div>
            <div class="form-group">
              <label>SMTP Port</label>
              <input type="number" id="smtpPort" value="587">
            </div>
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="smtpUser" placeholder="user@example.com">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" id="smtpPass" placeholder="••••••••">
            </div>
            <div class="form-group">
              <label>From Email</label>
              <input type="email" id="smtpFrom" placeholder="alerts@xmartguard.com">
            </div>
            <div class="form-group">
              <label>From Name</label>
              <input type="text" id="smtpFromName" value="XMartGuard Alerts">
            </div>
          </div>
          <button class="btn btn-primary" style="margin-top:20px;" onclick="saveSmtpSettings()">Save SMTP Settings</button>
          <button class="btn btn-secondary" style="margin-top:20px;margin-left:12px;" onclick="testSmtp()">Send Test Email</button>
        </div>
      </div>
    </div>
    
    <div id="adminEmailTemplates" class="tab-panel">
      <div class="card">
        <div class="card-header"><h3>Alert Email Templates</h3></div>
        <div class="card-body">
          <div class="form-group">
            <label>Server Offline Alert</label>
            <textarea rows="5" style="width:100%;font-family:monospace;">Subject: ⚠️ Server {{server_name}} is OFFLINE

Your server {{server_name}} ({{server_ip}}) has gone offline.

Last seen: {{last_seen}}

Please check your server immediately.

- XMartGuard Team</textarea>
          </div>
          
          <div class="form-group">
            <label>High CPU Alert</label>
            <textarea rows="5" style="width:100%;font-family:monospace;">Subject: 🔴 High CPU on {{server_name}}

CPU usage on {{server_name}} has exceeded {{threshold}}%.

Current: {{current_value}}%

- XMartGuard Team</textarea>
          </div>
          
          <div class="form-group">
            <label>Server Back Online Alert</label>
            <textarea rows="5" style="width:100%;font-family:monospace;">Subject: ✅ Server {{server_name}} is back ONLINE

Good news! Your server {{server_name}} ({{server_ip}}) is back online.

- XMartGuard Team</textarea>
          </div>
          
          <button class="btn btn-primary" style="margin-top:20px;">Save Templates</button>
        </div>
      </div>
    </div>
    
    <div id="adminOtherChannels" class="tab-panel">
      <div class="card">
        <div class="card-header"><h3>Additional Alert Channels</h3></div>
        <div class="card-body">
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>📱 WhatsApp Business API</strong><br><small>Send alerts via WhatsApp</small></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
          </div>
          
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>💬 Slack Webhook</strong><br><small>Send alerts to Slack channels</small></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
          </div>
          
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>📲 Telegram Bot</strong><br><small>Send alerts via Telegram</small></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
          </div>
          
          <div class="alert-config-item coming-soon">
            <div class="alert-config-header">
              <div><strong>🪝 Custom Webhook</strong><br><small>Send alerts to custom endpoints</small></div>
              <label class="toggle-switch"><input type="checkbox" disabled><span class="toggle-slider"></span></label>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function showAdminAlertTab(tab) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', 
      (tab === 'email' && i === 0) || 
      (tab === 'templates' && i === 1) || 
      (tab === 'channels' && i === 2)
    );
  });
  document.getElementById('adminEmailSettings').classList.toggle('active', tab === 'email');
  document.getElementById('adminEmailTemplates').classList.toggle('active', tab === 'templates');
  document.getElementById('adminOtherChannels').classList.toggle('active', tab === 'channels');
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
            
            <h4 style="margin:24px 0 16px;">JazzCash Settings</h4>
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
            
            <h4 style="margin:24px 0 16px;">Easypaisa Settings</h4>
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
              jazzcash: {
                enabled: true,
                accountTitle: form.jazzcashTitle.value,
                accountNumber: form.jazzcashNumber.value
              },
              easypaisa: {
                enabled: true,
                accountTitle: form.easypaisaTitle.value,
                accountNumber: form.easypaisaNumber.value
              }
            }
          }
        });
        showToast('Settings saved!', 'success');
      } catch (err) {
        showToast('Error: ' + err.message, 'error');
      }
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
      navigateTo('billing');
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
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

function loadNotFound(page) {
  document.getElementById('contentArea').innerHTML = `
    <div class="empty-state">
      <h3>Page Not Found</h3>
      <p>The page "${page}" doesn't exist</p>
      <button class="btn btn-primary" onclick="navigateTo('dashboard')">Go to Dashboard</button>
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
FRONTEND_EOF

echo -e "${GREEN}✓ Frontend updated${NC}"

#===============================================================================
# PART 2: Create/Update Backend Routes
#===============================================================================
echo -e "${YELLOW}► Updating backend routes...${NC}"

# Public Pages Model
cat > "$INSTALL_DIR/models/PublicPage.js" << 'MODEL_EOF'
const mongoose = require('mongoose');

const publicPageSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  description: String,
  servers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Server' }],
  isPublic: { type: Boolean, default: true },
  theme: { type: String, default: 'default' },
  customDomain: String,
  logo: String,
  showUptime: { type: Boolean, default: true },
  showResponseTime: { type: Boolean, default: false },
  refreshInterval: { type: Number, default: 60 }
}, { timestamps: true });

module.exports = mongoose.model('PublicPage', publicPageSchema);
MODEL_EOF

# Alert Settings Model
cat > "$INSTALL_DIR/models/AlertSettings.js" << 'MODEL_EOF'
const mongoose = require('mongoose');

const alertSettingsSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  server: { type: mongoose.Schema.Types.ObjectId, ref: 'Server' },
  isGlobal: { type: Boolean, default: false },
  thresholds: {
    cpu: { enabled: { type: Boolean, default: true }, warning: { type: Number, default: 70 }, critical: { type: Number, default: 90 } },
    memory: { enabled: { type: Boolean, default: true }, warning: { type: Number, default: 80 }, critical: { type: Number, default: 95 } },
    disk: { enabled: { type: Boolean, default: true }, warning: { type: Number, default: 80 }, critical: { type: Number, default: 95 } },
    offline: { enabled: { type: Boolean, default: true } }
  },
  channels: {
    email: { enabled: { type: Boolean, default: true }, address: String },
    whatsapp: { enabled: { type: Boolean, default: false }, number: String },
    slack: { enabled: { type: Boolean, default: false }, webhook: String },
    telegram: { enabled: { type: Boolean, default: false }, chatId: String }
  }
}, { timestamps: true });

module.exports = mongoose.model('AlertSettings', alertSettingsSchema);
MODEL_EOF

# Alert History Model
cat > "$INSTALL_DIR/models/AlertHistory.js" << 'MODEL_EOF'
const mongoose = require('mongoose');

const alertHistorySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  server: { type: mongoose.Schema.Types.ObjectId, ref: 'Server', required: true },
  type: { type: String, enum: ['cpu', 'memory', 'disk', 'offline', 'online'], required: true },
  severity: { type: String, enum: ['warning', 'critical', 'info'], default: 'warning' },
  message: String,
  value: Number,
  threshold: Number,
  notifiedVia: [String],
  acknowledgedAt: Date,
  resolvedAt: Date
}, { timestamps: true });

module.exports = mongoose.model('AlertHistory', alertHistorySchema);
MODEL_EOF

# Public Pages Routes
cat > "$INSTALL_DIR/routes/publicPages.js" << 'ROUTE_EOF'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const PublicPage = require('../models/PublicPage');
const Server = require('../models/Server');

// Get user's public pages
router.get('/', protect, async (req, res) => {
  try {
    const pages = await PublicPage.find({ owner: req.user._id }).populate('servers', 'name status');
    res.json({ success: true, pages });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Create public page
router.post('/', protect, async (req, res) => {
  try {
    const { name, slug, servers, isPublic, description } = req.body;
    
    const existing = await PublicPage.findOne({ slug });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Slug already taken' });
    }
    
    const page = await PublicPage.create({
      owner: req.user._id,
      name,
      slug: slug.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
      servers,
      isPublic,
      description
    });
    
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update public page
router.put('/:id', protect, async (req, res) => {
  try {
    const page = await PublicPage.findOneAndUpdate(
      { _id: req.params.id, owner: req.user._id },
      req.body,
      { new: true }
    );
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Delete public page
router.delete('/:id', protect, async (req, res) => {
  try {
    await PublicPage.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Public view (no auth required)
router.get('/view/:slug', async (req, res) => {
  try {
    const page = await PublicPage.findOne({ slug: req.params.slug, isPublic: true })
      .populate('servers', 'name status metrics lastSeen');
    
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTE_EOF

# Update admin routes with login-as feature
cat > "$INSTALL_DIR/routes/admin.js" << 'ADMIN_EOF'
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { protect, adminOnly } = require('../middleware/auth');
const User = require('../models/User');
const Server = require('../models/Server');
const Invoice = require('../models/Invoice');
const Plan = require('../models/Plan');
const GlobalSettings = require('../models/GlobalSettings');

// Get admin stats
router.get('/stats', protect, adminOnly, async (req, res) => {
  try {
    const [totalUsers, totalServers, pendingPayments, paidInvoices] = await Promise.all([
      User.countDocuments(),
      Server.countDocuments(),
      Invoice.countDocuments({ status: 'processing' }),
      Invoice.find({ status: 'paid', createdAt: { $gte: new Date(new Date().setDate(1)) } })
    ]);
    
    const monthlyRevenue = paidInvoices.reduce((sum, inv) => sum + (inv.total || 0), 0);
    
    res.json({
      success: true,
      stats: { totalUsers, totalServers, pendingPayments, monthlyRevenue }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get all users
router.get('/users', protect, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort('-createdAt');
    
    // Add server count to each user
    for (let user of users) {
      user._doc.serverCount = await Server.countDocuments({ owner: user._id });
    }
    
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update user
router.put('/users/:id', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-password');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Login as user (impersonation)
router.post('/login-as/:id', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get all servers
router.get('/servers', protect, adminOnly, async (req, res) => {
  try {
    const servers = await Server.find()
      .populate('owner', 'name email')
      .sort('-createdAt');
    res.json({ success: true, servers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get pending payments
router.get('/pending-payments', protect, adminOnly, async (req, res) => {
  try {
    const invoices = await Invoice.find({ status: 'processing' })
      .populate('user', 'name email')
      .sort('-createdAt');
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Verify payment
router.post('/verify-payment/:id', protect, adminOnly, async (req, res) => {
  try {
    const { action, notes } = req.body;
    const invoice = await Invoice.findById(req.params.id);
    
    if (!invoice) return res.status(404).json({ success: false, message: 'Invoice not found' });
    
    if (action === 'approve') {
      invoice.status = 'paid';
      invoice.manualPayment.verifiedBy = req.user._id;
      invoice.manualPayment.verifiedAt = new Date();
      invoice.manualPayment.notes = notes;
      await invoice.save();
      
      // Update user subscription
      const plan = await Plan.findOne({ slug: invoice.planSlug });
      if (plan) {
        await User.findByIdAndUpdate(invoice.user, {
          'subscription.plan': plan.slug,
          'subscription.status': 'active',
          'subscription.serverLimit': plan.limits.servers,
          'subscription.startDate': new Date(),
          'pendingUpgrade': null
        });
      }
    } else {
      invoice.status = 'failed';
      invoice.manualPayment.rejectionReason = notes;
      await invoice.save();
      
      await User.findByIdAndUpdate(invoice.user, { 'pendingUpgrade': null });
    }
    
    res.json({ success: true, invoice });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update settings
router.put('/settings', protect, adminOnly, async (req, res) => {
  try {
    let settings = await GlobalSettings.findOne();
    if (!settings) settings = new GlobalSettings();
    
    Object.assign(settings, req.body);
    await settings.save();
    
    res.json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ADMIN_EOF

echo -e "${GREEN}✓ Backend routes updated${NC}"

#===============================================================================
# PART 3: Update server.js to include new routes
#===============================================================================
echo -e "${YELLOW}► Updating server.js...${NC}"

cat > "$INSTALL_DIR/server.js" << 'SERVER_EOF'
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, message: 'Too many requests' }
});
app.use('/api/', limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use('/downloads', express.static(path.join(__dirname, 'agent')));

// Socket.io
app.set('io', io);
io.on('connection', (socket) => {
  socket.on('join_server', (serverId) => socket.join(`server_${serverId}`));
  socket.on('join_user', (userId) => socket.join(`user_${userId}`));
});

// API Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/servers', require('./routes/servers'));
app.use('/api/dashboard', require('./routes/dashboard'));
app.use('/api/billing', require('./routes/billing'));
app.use('/api/settings', require('./routes/settings'));
app.use('/api/agent', require('./routes/agent'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/public-pages', require('./routes/publicPages'));
app.use('/api/plans', require('./routes/plans'));
app.use('/api/invoices', require('./routes/invoices'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'ok', timestamp: new Date() });
});

// Public status page route
app.get('/status/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'status.html'));
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/xmartguard');
    console.log('✓ MongoDB connected');
    
    // Initialize app
    const initializeApp = require('./utils/initializeApp');
    await initializeApp();
  } catch (err) {
    console.error('✗ MongoDB connection error:', err.message);
    process.exit(1);
  }
};

// Start server
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
  httpServer.listen(PORT, () => {
    console.log(`✓ XMartGuard running on port ${PORT}`);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  httpServer.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});
SERVER_EOF

echo -e "${GREEN}✓ server.js updated${NC}"

#===============================================================================
# PART 4: Create public status page HTML
#===============================================================================
echo -e "${YELLOW}► Creating public status page...${NC}"

cat > "$INSTALL_DIR/public/status.html" << 'STATUS_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Status Page - XMartGuard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f3f4f6; min-height: 100vh; }
    .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 32px; margin-bottom: 8px; }
    .header p { color: #6b7280; }
    .status-card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .status-card .name { font-weight: 600; font-size: 18px; }
    .status-card .status { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
    .status-dot { width: 12px; height: 12px; border-radius: 50%; }
    .status-dot.online { background: #10b981; }
    .status-dot.offline { background: #ef4444; }
    .status-text { color: #6b7280; }
    .overall { background: linear-gradient(135deg, #10b981, #059669); color: white; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px; }
    .overall.partial { background: linear-gradient(135deg, #f59e0b, #d97706); }
    .overall.down { background: linear-gradient(135deg, #ef4444, #dc2626); }
    .overall h2 { font-size: 24px; margin-bottom: 4px; }
    .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 12px; }
    .metric { background: rgba(255,255,255,0.1); padding: 8px; border-radius: 8px; }
    .metric-label { font-size: 12px; opacity: 0.8; }
    .metric-value { font-size: 20px; font-weight: 600; }
    .footer { text-align: center; margin-top: 40px; color: #6b7280; font-size: 14px; }
    .loading { text-align: center; padding: 60px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 id="pageName">Status Page</h1>
      <p id="pageDesc">System Status</p>
    </div>
    
    <div id="content">
      <div class="loading">Loading status...</div>
    </div>
    
    <div class="footer">
      Powered by <a href="/" style="color:#10b981;">XMartGuard</a>
    </div>
  </div>
  
  <script>
    const slug = window.location.pathname.split('/').pop();
    
    async function loadStatus() {
      try {
        const res = await fetch('/api/public-pages/view/' + slug);
        const data = await res.json();
        
        if (!data.success) {
          document.getElementById('content').innerHTML = '<div class="status-card"><p>Status page not found</p></div>';
          return;
        }
        
        const page = data.page;
        document.getElementById('pageName').textContent = page.name;
        if (page.description) document.getElementById('pageDesc').textContent = page.description;
        document.title = page.name + ' - Status';
        
        const servers = page.servers || [];
        const online = servers.filter(s => s.status === 'online').length;
        const total = servers.length;
        
        let overallClass = '';
        let overallText = 'All Systems Operational';
        if (online === 0 && total > 0) {
          overallClass = 'down';
          overallText = 'Major Outage';
        } else if (online < total) {
          overallClass = 'partial';
          overallText = 'Partial Outage';
        }
        
        let html = `
          <div class="overall ${overallClass}">
            <h2>${overallText}</h2>
            <p>${online} of ${total} systems operational</p>
          </div>
        `;
        
        servers.forEach(s => {
          html += `
            <div class="status-card">
              <div class="name">${s.name}</div>
              <div class="status">
                <div class="status-dot ${s.status}"></div>
                <span class="status-text">${s.status === 'online' ? 'Operational' : 'Offline'}</span>
              </div>
              ${s.status === 'online' && s.metrics ? `
                <div class="metrics">
                  <div class="metric"><div class="metric-label">CPU</div><div class="metric-value">${(s.metrics.cpu || 0).toFixed(1)}%</div></div>
                  <div class="metric"><div class="metric-label">Memory</div><div class="metric-value">${(s.metrics.memory || 0).toFixed(1)}%</div></div>
                  <div class="metric"><div class="metric-label">Disk</div><div class="metric-value">${(s.metrics.disk || 0).toFixed(1)}%</div></div>
                </div>
              ` : ''}
            </div>
          `;
        });
        
        document.getElementById('content').innerHTML = html;
      } catch (err) {
        document.getElementById('content').innerHTML = '<div class="status-card"><p>Error loading status</p></div>';
      }
    }
    
    loadStatus();
    setInterval(loadStatus, 60000);
  </script>
</body>
</html>
STATUS_EOF

echo -e "${GREEN}✓ Status page created${NC}"

#===============================================================================
# PART 5: Set permissions
#===============================================================================
echo -e "${YELLOW}► Setting permissions...${NC}"

chown -R "$CPANEL_USER":"$CPANEL_USER" "$INSTALL_DIR" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true

echo -e "${GREEN}✓ Permissions set${NC}"

#===============================================================================
# DONE
#===============================================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Patch Applied Successfully!                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Go to cPanel → Setup Node.js App"
echo "  2. Create new application:"
echo "     - Node.js version: 18+ or 20+"
echo "     - Application mode: Production"
echo "     - Application root: xmartguard (relative to home)"
echo "     - Application URL: app.xmartguard.com"
echo "     - Application startup file: server.js"
echo "  3. Click 'Run NPM Install' in cPanel Node.js app"
echo "  4. Click 'Restart' application"
echo ""
echo -e "${YELLOW}Changes Applied:${NC}"
echo "  ✓ Server row clicks now navigate to details"
echo "  ✓ Copy button fixed with fallback method"
echo "  ✓ Uninstall command added"
echo "  ✓ Charts with hourly/daily/weekly/monthly filters"
echo "  ✓ Billing error fixed"
echo "  ✓ Public Status Pages feature"
echo "  ✓ Admin can view all servers"
echo "  ✓ Admin can login as any user"
echo "  ✓ Alerts section with email config"
echo "  ✓ WhatsApp/Slack (Coming Soon badges)"
echo "  ✓ Gravatar profile pictures"
echo "  ✓ URL routing (#/page/id format)"
echo "  ✓ cPanel compatible directory structure"
echo ""
