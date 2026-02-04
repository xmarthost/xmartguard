#!/bin/bash
#===============================================================================
# XMartGuard cPanel Migration Patch
# Moves app from /opt to user home directory for cPanel Node.js App (Passenger)
#===============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        XMartGuard cPanel Migration Patch                       ║${NC}"
echo -e "${CYAN}║        Passenger + LiteSpeed Compatible                        ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

#===============================================================================
# Get cPanel username
#===============================================================================
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <cpanel_username>${NC}"
    echo ""
    echo "Example: $0 xmartguard"
    echo ""
    
    # Try to detect
    if [ -d "/home2" ]; then
        echo "Available users in /home2:"
        ls /home2/
    elif [ -d "/home" ]; then
        echo "Available users in /home:"
        ls /home/
    fi
    exit 1
fi

CPANEL_USER="$1"

# Detect home directory
if [ -d "/home2/$CPANEL_USER" ]; then
    HOME_DIR="/home2/$CPANEL_USER"
elif [ -d "/home/$CPANEL_USER" ]; then
    HOME_DIR="/home/$CPANEL_USER"
else
    echo -e "${RED}✗ User home directory not found for: $CPANEL_USER${NC}"
    exit 1
fi

INSTALL_DIR="$HOME_DIR/xmartguard"
OLD_DIR="/opt/xmartguard"

echo -e "${GREEN}cPanel User:${NC} $CPANEL_USER"
echo -e "${GREEN}Home Directory:${NC} $HOME_DIR"
echo -e "${GREEN}App Directory:${NC} $INSTALL_DIR"
echo ""

#===============================================================================
# Step 1: Create directory structure
#===============================================================================
echo -e "${YELLOW}[1/6] Creating directory structure...${NC}"

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/public/uploads"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/models"
mkdir -p "$INSTALL_DIR/routes"
mkdir -p "$INSTALL_DIR/routes/webhooks"
mkdir -p "$INSTALL_DIR/middleware"
mkdir -p "$INSTALL_DIR/utils"
mkdir -p "$INSTALL_DIR/services"
mkdir -p "$INSTALL_DIR/agent"

echo -e "${GREEN}✓ Directories created${NC}"

#===============================================================================
# Step 2: Copy existing files if they exist
#===============================================================================
echo -e "${YELLOW}[2/6] Copying existing files...${NC}"

if [ -d "$OLD_DIR" ]; then
    echo "  Copying from $OLD_DIR..."
    cp -r "$OLD_DIR"/* "$INSTALL_DIR"/ 2>/dev/null || true
    
    # Preserve .env if exists
    if [ -f "$OLD_DIR/.env" ]; then
        cp "$OLD_DIR/.env" "$INSTALL_DIR/.env.backup"
        echo "  ✓ .env backed up"
    fi
fi

echo -e "${GREEN}✓ Files copied${NC}"

#===============================================================================
# Step 3: Create/Update server.js for Passenger
#===============================================================================
echo -e "${YELLOW}[3/6] Creating Passenger-compatible server.js...${NC}"

cat > "$INSTALL_DIR/server.js" << 'SERVERJS'
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
const io = new Server(httpServer, { 
  cors: { origin: '*' },
  transports: ['websocket', 'polling']
});

// Trust proxy (important for cPanel/Passenger)
app.set('trust proxy', 1);

// Middleware
app.use(helmet({ 
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
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
  console.log('Socket connected:', socket.id);
  socket.on('join_server', (serverId) => socket.join(`server_${serverId}`));
  socket.on('join_user', (userId) => socket.join(`user_${userId}`));
  socket.on('disconnect', () => console.log('Socket disconnected:', socket.id));
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
  res.json({ 
    success: true, 
    status: 'ok', 
    timestamp: new Date(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Public status page
app.get('/status/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'status.html'));
});

// SPA fallback - serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/xmartguard', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✓ MongoDB connected');
    
    // Initialize app (create admin, plans, settings)
    const initializeApp = require('./utils/initializeApp');
    await initializeApp();
  } catch (err) {
    console.error('✗ MongoDB connection error:', err.message);
    // Don't exit, let it retry
    setTimeout(connectDB, 5000);
  }
};

// IMPORTANT: Passenger assigns PORT automatically
// When PORT=0 or undefined, Passenger handles it via socket
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`✓ XMartGuard server started`);
    console.log(`  Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`  Port: ${PORT}`);
  });
});

// Handle Passenger startup
if (typeof(PhusionPassenger) !== 'undefined') {
  PhusionPassenger.configure({ autoInstall: false });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  httpServer.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  httpServer.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});
SERVERJS

echo -e "${GREEN}✓ server.js created (Passenger compatible)${NC}"

#===============================================================================
# Step 4: Create .env file
#===============================================================================
echo -e "${YELLOW}[4/6] Creating .env file...${NC}"

# Generate random JWT secret
JWT_SECRET=$(openssl rand -base64 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
ADMIN_PASS=$(openssl rand -base64 12 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)

# Check if .env.backup exists and extract old values
OLD_JWT=""
OLD_ADMIN_EMAIL=""
OLD_ADMIN_PASS=""
OLD_MONGODB=""

if [ -f "$INSTALL_DIR/.env.backup" ]; then
    OLD_JWT=$(grep "JWT_SECRET=" "$INSTALL_DIR/.env.backup" 2>/dev/null | cut -d'=' -f2)
    OLD_ADMIN_EMAIL=$(grep "ADMIN_EMAIL=" "$INSTALL_DIR/.env.backup" 2>/dev/null | cut -d'=' -f2)
    OLD_ADMIN_PASS=$(grep "ADMIN_PASSWORD=" "$INSTALL_DIR/.env.backup" 2>/dev/null | cut -d'=' -f2)
    OLD_MONGODB=$(grep "MONGODB_URI=" "$INSTALL_DIR/.env.backup" 2>/dev/null | cut -d'=' -f2)
fi

# Use old values if they exist
[ -n "$OLD_JWT" ] && JWT_SECRET="$OLD_JWT"
[ -n "$OLD_ADMIN_PASS" ] && ADMIN_PASS="$OLD_ADMIN_PASS"

cat > "$INSTALL_DIR/.env" << ENVFILE
# XMartGuard Configuration
# Generated: $(date)

# Environment
NODE_ENV=production

# IMPORTANT: Set PORT=0 for Passenger (cPanel auto-assigns port)
PORT=0

# Domain Configuration
DOMAIN=xmartguard.com
APP_URL=https://app.xmartguard.com

# MongoDB Connection
MONGODB_URI=${OLD_MONGODB:-mongodb://127.0.0.1:27017/xmartguard}

# Security - JWT Secret (DO NOT SHARE)
JWT_SECRET=${JWT_SECRET}

# Admin Account
ADMIN_EMAIL=${OLD_ADMIN_EMAIL:-admin@xmartguard.com}
ADMIN_PASSWORD=${ADMIN_PASS}

# Stripe Configuration (Add your keys)
STRIPE_SECRET_KEY=sk_live_YOUR_STRIPE_SECRET_KEY
STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_STRIPE_PUBLISHABLE_KEY
STRIPE_WEBHOOK_SECRET=whsec_YOUR_WEBHOOK_SECRET

# SMTP Configuration (for email alerts)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=alerts@xmartguard.com
SMTP_FROM_NAME=XMartGuard Alerts
ENVFILE

chmod 600 "$INSTALL_DIR/.env"

echo -e "${GREEN}✓ .env created${NC}"
echo -e "  Admin Email: ${OLD_ADMIN_EMAIL:-admin@xmartguard.com}"
echo -e "  Admin Password: $ADMIN_PASS"

#===============================================================================
# Step 5: Create package.json
#===============================================================================
echo -e "${YELLOW}[5/6] Creating package.json...${NC}"

cat > "$INSTALL_DIR/package.json" << 'PACKAGEJSON'
{
  "name": "xmartguard",
  "version": "2.0.0",
  "description": "Professional Server Monitoring Platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.0.3",
    "multer": "^1.4.5-lts.1",
    "nodemailer": "^6.9.7",
    "socket.io": "^4.6.1",
    "stripe": "^14.10.0"
  }
}
PACKAGEJSON

echo -e "${GREEN}✓ package.json created${NC}"

#===============================================================================
# Step 6: Create all necessary model and route files
#===============================================================================
echo -e "${YELLOW}[6/6] Creating all necessary files...${NC}"

# ========== MODELS ==========

# User Model
cat > "$INSTALL_DIR/models/User.js" << 'MODELFILE'
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
  isActive: { type: Boolean, default: true },
  emailVerified: { type: Boolean, default: false },
  company: String,
  phone: String,
  subscription: {
    plan: { type: String, default: 'free' },
    status: { type: String, enum: ['active', 'cancelled', 'expired', 'pending'], default: 'active' },
    serverLimit: { type: Number, default: 1 },
    startDate: Date,
    endDate: Date
  },
  stripeCustomerId: String,
  stripeSubscriptionId: String,
  pendingUpgrade: {
    plan: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'] },
    transactionId: String,
    screenshotUrl: String,
    submittedAt: Date
  },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: String,
  referralCode: String,
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.canAddServer = async function() {
  const Server = mongoose.model('Server');
  const count = await Server.countDocuments({ owner: this._id });
  return count < this.subscription.serverLimit;
};

module.exports = mongoose.model('User', userSchema);
MODELFILE

# Server Model
cat > "$INSTALL_DIR/models/Server.js" << 'MODELFILE'
const mongoose = require('mongoose');
const crypto = require('crypto');

const problemSchema = new mongoose.Schema({
  problemType: { type: String, required: true },
  severity: { type: String, enum: ['warning', 'critical'], default: 'warning' },
  message: String,
  suggestion: String,
  detectedAt: { type: Date, default: Date.now }
}, { _id: false });

const serverSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  ipAddress: { type: String, required: true },
  agentToken: { type: String, unique: true },
  status: { type: String, enum: ['online', 'offline', 'warning', 'pending'], default: 'pending' },
  lastSeen: Date,
  agentVersion: String,
  metrics: {
    cpu: { type: Number, default: 0 },
    memory: { type: Number, default: 0 },
    disk: { type: Number, default: 0 },
    loadAvg: { type: [Number], default: [0, 0, 0] },
    uptime: { type: Number, default: 0 },
    network: { rx: { type: Number, default: 0 }, tx: { type: Number, default: 0 } }
  },
  systemInfo: {
    hostname: String,
    os: String,
    kernel: String,
    arch: String,
    cpuModel: String,
    cpuCount: Number,
    cpuFreq: Number,
    sshSessions: Number,
    activeConnections: Number
  },
  detailedMetrics: {
    memory: mongoose.Schema.Types.Mixed,
    disks: [mongoose.Schema.Types.Mixed],
    interfaces: [mongoose.Schema.Types.Mixed]
  },
  problems: [problemSchema],
  tags: [String],
  group: String,
  notes: String,
  location: String,
  alertSettings: {
    cpuThreshold: { type: Number, default: 80 },
    memoryThreshold: { type: Number, default: 85 },
    diskThreshold: { type: Number, default: 90 },
    emailAlerts: { type: Boolean, default: true }
  }
}, { timestamps: true });

serverSchema.pre('save', function(next) {
  if (!this.agentToken) {
    this.agentToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

module.exports = mongoose.model('Server', serverSchema);
MODELFILE

# Plan Model
cat > "$INSTALL_DIR/models/Plan.js" << 'MODELFILE'
const mongoose = require('mongoose');

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  description: String,
  price: {
    monthly: { type: Number, default: 0 },
    yearly: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' }
  },
  stripePriceId: { monthly: String, yearly: String },
  limits: {
    servers: { type: Number, default: 1 },
    users: { type: Number, default: 1 },
    alertsPerDay: { type: Number, default: 10 },
    dataRetentionDays: { type: Number, default: 1 },
    apiRequestsPerHour: { type: Number, default: 100 }
  },
  features: [{
    name: String,
    included: { type: Boolean, default: false }
  }],
  isPopular: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  displayOrder: { type: Number, default: 0 },
  color: String
}, { timestamps: true });

module.exports = mongoose.model('Plan', planSchema);
MODELFILE

# Invoice Model
cat > "$INSTALL_DIR/models/Invoice.js" << 'MODELFILE'
const mongoose = require('mongoose');

const invoiceSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  invoiceNumber: { type: String, unique: true },
  planName: String,
  planSlug: String,
  billingCycle: { type: String, enum: ['monthly', 'yearly'], default: 'monthly' },
  subtotal: { type: Number, default: 0 },
  discount: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  total: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'paid', 'failed', 'cancelled', 'refunded', 'processing'], default: 'pending' },
  paymentMethod: { type: String, enum: ['stripe', 'jazzcash', 'easypaisa', 'bank_transfer', 'manual'] },
  stripePaymentIntentId: String,
  stripeInvoiceId: String,
  manualPayment: {
    transactionId: String,
    senderNumber: String,
    senderName: String,
    screenshotUrl: String,
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedAt: Date,
    notes: String,
    rejectionReason: String
  },
  periodStart: Date,
  periodEnd: Date,
  pdfUrl: String
}, { timestamps: true });

invoiceSchema.pre('save', async function(next) {
  if (!this.invoiceNumber) {
    const year = new Date().getFullYear();
    const count = await mongoose.model('Invoice').countDocuments();
    this.invoiceNumber = `XMG-${year}-${String(count + 1).padStart(6, '0')}`;
  }
  next();
});

module.exports = mongoose.model('Invoice', invoiceSchema);
MODELFILE

# GlobalSettings Model
cat > "$INSTALL_DIR/models/GlobalSettings.js" << 'MODELFILE'
const mongoose = require('mongoose');

const globalSettingsSchema = new mongoose.Schema({
  appName: { type: String, default: 'XMartGuard' },
  appTagline: { type: String, default: 'Professional Server Monitoring' },
  appDescription: String,
  logo: String,
  logoDark: String,
  favicon: String,
  theme: { type: String, default: 'light' },
  primaryColor: { type: String, default: '#10b981' },
  secondaryColor: { type: String, default: '#667eea' },
  supportEmail: String,
  salesEmail: String,
  phone: String,
  address: String,
  social: { twitter: String, facebook: String, linkedin: String, github: String },
  timezone: { type: String, default: 'UTC' },
  dateFormat: { type: String, default: 'YYYY-MM-DD' },
  timeFormat: { type: String, default: 'HH:mm:ss' },
  defaultAlertThresholds: {
    cpu: { type: Number, default: 80 },
    memory: { type: Number, default: 85 },
    disk: { type: Number, default: 90 }
  },
  payment: {
    currency: { type: String, default: 'USD' },
    stripeEnabled: { type: Boolean, default: true },
    manualPaymentEnabled: { type: Boolean, default: true },
    jazzcash: { enabled: Boolean, accountTitle: String, accountNumber: String, instructions: String },
    easypaisa: { enabled: Boolean, accountTitle: String, accountNumber: String, instructions: String },
    bankTransfer: { enabled: Boolean, bankName: String, accountTitle: String, accountNumber: String, iban: String, instructions: String }
  },
  smtp: { host: String, port: Number, user: String, pass: String, from: String, fromName: String, secure: Boolean },
  maintenance: { enabled: { type: Boolean, default: false }, message: String },
  security: { sessionTimeout: { type: Number, default: 30 }, maxLoginAttempts: { type: Number, default: 5 }, lockoutDuration: { type: Number, default: 15 } },
  legal: { termsUrl: String, privacyUrl: String, refundUrl: String },
  customCss: String,
  customJs: String,
  footerText: String,
  showPoweredBy: { type: Boolean, default: true },
  googleAnalyticsId: String
}, { timestamps: true });

module.exports = mongoose.model('GlobalSettings', globalSettingsSchema);
MODELFILE

# PublicPage Model
cat > "$INSTALL_DIR/models/PublicPage.js" << 'MODELFILE'
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
MODELFILE

# ========== MIDDLEWARE ==========

cat > "$INSTALL_DIR/middleware/auth.js" << 'MIDDLEWAREFILE'
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ success: false, message: 'Account disabled' });
    }
    
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

exports.adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

exports.superAdminOnly = (req, res, next) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ success: false, message: 'Super admin access required' });
  }
  next();
};
MIDDLEWAREFILE

# ========== UTILS ==========

cat > "$INSTALL_DIR/utils/initializeApp.js" << 'UTILFILE'
const User = require('../models/User');
const Plan = require('../models/Plan');
const GlobalSettings = require('../models/GlobalSettings');

async function initializeApp() {
  try {
    // Create default admin
    const adminExists = await User.findOne({ role: 'super_admin' });
    if (!adminExists) {
      await User.create({
        name: 'Administrator',
        email: process.env.ADMIN_EMAIL || 'admin@xmartguard.com',
        password: process.env.ADMIN_PASSWORD || 'XMartGuard@2024',
        role: 'super_admin',
        isActive: true,
        emailVerified: true,
        subscription: { plan: 'enterprise', status: 'active', serverLimit: 1000 }
      });
      console.log('  ✓ Default admin created');
    }
    
    // Create default plans
    const plansExist = await Plan.countDocuments();
    if (plansExist === 0) {
      await Plan.insertMany([
        {
          name: 'Free', slug: 'free', description: 'Perfect for getting started',
          price: { monthly: 0, yearly: 0, currency: 'USD' },
          limits: { servers: 1, users: 1, alertsPerDay: 10, dataRetentionDays: 1, apiRequestsPerHour: 100 },
          features: [
            { name: '1 Server Monitoring', included: true },
            { name: 'Basic Alerts', included: true },
            { name: '1 Day Data Retention', included: true },
            { name: 'Email Support', included: false },
            { name: 'API Access', included: false }
          ],
          isActive: true, displayOrder: 1, color: '#6b7280'
        },
        {
          name: 'Starter', slug: 'starter', description: 'For small teams and projects',
          price: { monthly: 999, yearly: 9990, currency: 'USD' },
          limits: { servers: 5, users: 3, alertsPerDay: 100, dataRetentionDays: 7, apiRequestsPerHour: 1000 },
          features: [
            { name: '5 Server Monitoring', included: true },
            { name: 'Advanced Alerts', included: true },
            { name: '7 Days Data Retention', included: true },
            { name: 'Email Support', included: true },
            { name: 'API Access', included: true }
          ],
          isActive: true, displayOrder: 2, color: '#10b981'
        },
        {
          name: 'Pro', slug: 'pro', description: 'For growing businesses',
          price: { monthly: 2499, yearly: 24990, currency: 'USD' },
          limits: { servers: 20, users: 10, alertsPerDay: 500, dataRetentionDays: 30, apiRequestsPerHour: 5000 },
          features: [
            { name: '20 Server Monitoring', included: true },
            { name: 'Advanced Alerts', included: true },
            { name: '30 Days Data Retention', included: true },
            { name: 'Priority Support', included: true },
            { name: 'Full API Access', included: true },
            { name: 'Custom Alerts', included: true }
          ],
          isPopular: true, isActive: true, displayOrder: 3, color: '#667eea'
        },
        {
          name: 'Enterprise', slug: 'enterprise', description: 'For large organizations',
          price: { monthly: 4999, yearly: 49990, currency: 'USD' },
          limits: { servers: 100, users: 50, alertsPerDay: 2000, dataRetentionDays: 90, apiRequestsPerHour: 20000 },
          features: [
            { name: '100 Server Monitoring', included: true },
            { name: 'Unlimited Alerts', included: true },
            { name: '90 Days Data Retention', included: true },
            { name: '24/7 Phone Support', included: true },
            { name: 'Full API Access', included: true },
            { name: 'Custom Integration', included: true }
          ],
          isActive: true, displayOrder: 4, color: '#8b5cf6'
        }
      ]);
      console.log('  ✓ Default plans created');
    }
    
    // Create default settings
    const settingsExist = await GlobalSettings.findOne();
    if (!settingsExist) {
      await GlobalSettings.create({
        appName: 'XMartGuard',
        appTagline: 'Professional Server Monitoring',
        primaryColor: '#10b981',
        secondaryColor: '#667eea',
        supportEmail: 'support@xmartguard.com',
        payment: {
          currency: 'USD',
          stripeEnabled: true,
          manualPaymentEnabled: true,
          jazzcash: { enabled: true, accountTitle: 'XMartGuard', accountNumber: '' },
          easypaisa: { enabled: true, accountTitle: 'XMartGuard', accountNumber: '' }
        }
      });
      console.log('  ✓ Default settings created');
    }
    
    console.log('  ✓ App initialization complete');
  } catch (err) {
    console.error('  ✗ Initialization error:', err.message);
  }
}

module.exports = initializeApp;
UTILFILE

# ========== ROUTES ==========

# Auth Routes
cat > "$INSTALL_DIR/routes/auth.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Server = require('../models/Server');
const { protect } = require('../middleware/auth');

router.post('/register', async (req, res) => {
  try {
    const { name, email, password, referralCode } = req.body;
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    const userData = {
      name,
      email: email.toLowerCase(),
      password,
      subscription: { plan: 'free', status: 'active', serverLimit: 1 }
    };
    
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) userData.referredBy = referrer._id;
    }
    
    const user = await User.create(userData);
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, subscription: user.subscription }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(401).json({ success: false, message: 'Account locked. Try again later.' });
    }
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
      }
      await user.save();
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ success: false, message: 'Account disabled' });
    }
    
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, subscription: user.subscription }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    const serverCount = await Server.countDocuments({ owner: req.user._id });
    res.json({ success: true, user: { ...user.toObject(), serverCount } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/profile', protect, async (req, res) => {
  try {
    const { name, company, phone } = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, { name, company, phone }, { new: true }).select('-password');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);
    
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password incorrect' });
    }
    
    user.password = newPassword;
    await user.save();
    
    res.json({ success: true, message: 'Password updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Servers Routes
cat > "$INSTALL_DIR/routes/servers.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Server = require('../models/Server');
const User = require('../models/User');

router.get('/', protect, async (req, res) => {
  try {
    const servers = await Server.find({ owner: req.user._id }).sort('-createdAt');
    res.json({ success: true, servers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/:id', protect, async (req, res) => {
  try {
    const server = await Server.findOne({ _id: req.params.id, owner: req.user._id });
    if (!server) return res.status(404).json({ success: false, message: 'Server not found' });
    res.json({ success: true, server });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const serverCount = await Server.countDocuments({ owner: req.user._id });
    
    if (serverCount >= user.subscription.serverLimit) {
      return res.status(400).json({
        success: false,
        message: `Server limit reached (${user.subscription.serverLimit}). Please upgrade your plan.`,
        upgradeRequired: true
      });
    }
    
    const { name, ipAddress } = req.body;
    const server = await Server.create({ owner: req.user._id, name, ipAddress });
    
    res.status(201).json({ success: true, server, token: server.agentToken });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/:id', protect, async (req, res) => {
  try {
    const server = await Server.findOneAndUpdate(
      { _id: req.params.id, owner: req.user._id },
      req.body,
      { new: true }
    );
    if (!server) return res.status(404).json({ success: false, message: 'Server not found' });
    res.json({ success: true, server });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.delete('/:id', protect, async (req, res) => {
  try {
    await Server.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    res.json({ success: true, message: 'Server deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/:id/regenerate-token', protect, async (req, res) => {
  try {
    const server = await Server.findOne({ _id: req.params.id, owner: req.user._id });
    if (!server) return res.status(404).json({ success: false, message: 'Server not found' });
    
    server.agentToken = require('crypto').randomBytes(32).toString('hex');
    await server.save();
    
    res.json({ success: true, token: server.agentToken });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Dashboard Routes
cat > "$INSTALL_DIR/routes/dashboard.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Server = require('../models/Server');
const User = require('../models/User');

router.get('/stats', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const [totalServers, onlineServers, offlineServers, serverData] = await Promise.all([
      Server.countDocuments({ owner: req.user._id }),
      Server.countDocuments({ owner: req.user._id, status: 'online' }),
      Server.countDocuments({ owner: req.user._id, status: { $in: ['offline', 'pending'] } }),
      Server.find({ owner: req.user._id }).select('problems')
    ]);
    
    let openIncidents = 0;
    serverData.forEach(s => { if (s.problems?.length) openIncidents += s.problems.length; });
    
    res.json({
      success: true,
      stats: {
        totalServers, onlineServers, offlineServers, openIncidents,
        serverLimit: user.subscription.serverLimit,
        serversRemaining: user.subscription.serverLimit - totalServers,
        plan: user.subscription.plan
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/server-status', protect, async (req, res) => {
  try {
    const servers = await Server.find({ owner: req.user._id })
      .select('name ipAddress status metrics problems lastSeen systemInfo')
      .sort('-lastSeen');
    res.json({ success: true, servers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/subscription', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const serverCount = await Server.countDocuments({ owner: req.user._id });
    const hasPendingUpgrade = user.pendingUpgrade?.status === 'pending';
    
    res.json({
      success: true,
      subscription: {
        plan: user.subscription.plan,
        status: user.subscription.status,
        serverLimit: user.subscription.serverLimit,
        serverCount,
        serversRemaining: user.subscription.serverLimit - serverCount,
        endDate: user.subscription.endDate,
        hasPendingUpgrade,
        pendingUpgrade: hasPendingUpgrade ? user.pendingUpgrade : null
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Billing Routes
cat > "$INSTALL_DIR/routes/billing.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const User = require('../models/User');
const Plan = require('../models/Plan');
const Invoice = require('../models/Invoice');
const GlobalSettings = require('../models/GlobalSettings');

router.get('/plans', async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true }).sort('displayOrder');
    res.json({ success: true, plans });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/subscription', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const Server = require('../models/Server');
    const serverCount = await Server.countDocuments({ owner: req.user._id });
    
    res.json({
      success: true,
      subscription: {
        plan: user.subscription.plan,
        status: user.subscription.status,
        serverLimit: user.subscription.serverLimit,
        serverCount,
        serversRemaining: user.subscription.serverLimit - serverCount,
        endDate: user.subscription.endDate,
        hasPendingUpgrade: user.pendingUpgrade?.status === 'pending',
        pendingUpgrade: user.pendingUpgrade
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/invoices', protect, async (req, res) => {
  try {
    const invoices = await Invoice.find({ user: req.user._id }).sort('-createdAt');
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/payment-methods', protect, async (req, res) => {
  try {
    const settings = await GlobalSettings.findOne();
    res.json({
      success: true,
      methods: {
        stripe: { enabled: settings?.payment?.stripeEnabled ?? true },
        jazzcash: settings?.payment?.jazzcash || { enabled: true },
        easypaisa: settings?.payment?.easypaisa || { enabled: true },
        bankTransfer: settings?.payment?.bankTransfer || { enabled: false }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/create-checkout', protect, async (req, res) => {
  try {
    const { planSlug, billingCycle } = req.body;
    const plan = await Plan.findOne({ slug: planSlug });
    if (!plan) return res.status(404).json({ success: false, message: 'Plan not found' });
    
    // Stripe checkout would go here
    res.json({ success: false, message: 'Stripe not configured. Use manual payment.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/manual-payment', protect, async (req, res) => {
  try {
    const { planSlug, billingCycle, paymentMethod, transactionId, senderNumber, senderName } = req.body;
    
    const plan = await Plan.findOne({ slug: planSlug });
    if (!plan) return res.status(404).json({ success: false, message: 'Plan not found' });
    
    const amount = billingCycle === 'yearly' ? plan.price.yearly : plan.price.monthly;
    
    const invoice = await Invoice.create({
      user: req.user._id,
      planName: plan.name,
      planSlug: plan.slug,
      billingCycle,
      subtotal: amount,
      total: amount,
      status: 'processing',
      paymentMethod,
      manualPayment: { transactionId, senderNumber, senderName }
    });
    
    await User.findByIdAndUpdate(req.user._id, {
      pendingUpgrade: { plan: planSlug, status: 'pending', transactionId, submittedAt: new Date() }
    });
    
    res.json({ success: true, invoice, message: 'Payment submitted for verification' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Agent Routes
cat > "$INSTALL_DIR/routes/agent.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const Server = require('../models/Server');

function detectProblems(metrics) {
  const problems = [];
  if (metrics.cpu > 80) {
    problems.push({
      problemType: 'cpu',
      severity: metrics.cpu > 90 ? 'critical' : 'warning',
      message: `High CPU usage: ${metrics.cpu}%`,
      suggestion: 'Check top processes: top -bn1 | head -20',
      detectedAt: new Date()
    });
  }
  if (metrics.memory > 85) {
    problems.push({
      problemType: 'memory',
      severity: metrics.memory > 95 ? 'critical' : 'warning',
      message: `High memory usage: ${metrics.memory}%`,
      suggestion: 'Free cache: sync && echo 3 > /proc/sys/vm/drop_caches',
      detectedAt: new Date()
    });
  }
  if (metrics.disk > 90) {
    problems.push({
      problemType: 'disk',
      severity: metrics.disk > 95 ? 'critical' : 'warning',
      message: `Low disk space: ${metrics.disk}% used`,
      suggestion: 'Find large files: du -h / | sort -rh | head -20',
      detectedAt: new Date()
    });
  }
  return problems;
}

router.post('/metrics', async (req, res) => {
  try {
    const token = req.headers['x-agent-token'];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });
    
    const server = await Server.findOne({ agentToken: token });
    if (!server) return res.status(404).json({ success: false, message: 'Invalid token' });
    
    const metrics = req.body;
    const problems = detectProblems(metrics);
    
    const updateData = {
      status: 'online',
      lastSeen: new Date(),
      'metrics.cpu': metrics.cpu || 0,
      'metrics.memory': metrics.memory || 0,
      'metrics.disk': metrics.disk || 0,
      'metrics.loadAvg': metrics.load_avg || [0, 0, 0],
      'metrics.uptime': metrics.uptime || 0,
      'metrics.network': metrics.network || { rx: 0, tx: 0 },
      problems,
      agentVersion: req.headers['x-agent-version'] || 'unknown'
    };
    
    if (metrics.system_info) {
      updateData['systemInfo.hostname'] = metrics.system_info.hostname;
      updateData['systemInfo.os'] = metrics.system_info.os;
      updateData['systemInfo.kernel'] = metrics.system_info.kernel;
      updateData['systemInfo.arch'] = metrics.system_info.arch;
      updateData['systemInfo.cpuModel'] = metrics.system_info.cpu_model;
      updateData['systemInfo.cpuCount'] = metrics.system_info.cpu_count;
    }
    
    await Server.findByIdAndUpdate(server._id, updateData);
    
    const io = req.app.get('io');
    if (io) {
      io.to(`server_${server._id}`).emit('metrics_update', { serverId: server._id, metrics, problems, status: 'online' });
    }
    
    res.json({ success: true, message: 'Metrics received', problems });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/info', async (req, res) => {
  try {
    const token = req.headers['x-agent-token'];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });
    
    const server = await Server.findOne({ agentToken: token });
    if (!server) return res.status(404).json({ success: false, message: 'Invalid token' });
    
    res.json({ success: true, server: { name: server.name, ipAddress: server.ipAddress, id: server._id } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Admin Routes
cat > "$INSTALL_DIR/routes/admin.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { protect, adminOnly } = require('../middleware/auth');
const User = require('../models/User');
const Server = require('../models/Server');
const Invoice = require('../models/Invoice');
const Plan = require('../models/Plan');
const GlobalSettings = require('../models/GlobalSettings');

router.get('/stats', protect, adminOnly, async (req, res) => {
  try {
    const [totalUsers, totalServers, pendingPayments, paidInvoices] = await Promise.all([
      User.countDocuments(),
      Server.countDocuments(),
      Invoice.countDocuments({ status: 'processing' }),
      Invoice.find({ status: 'paid', createdAt: { $gte: new Date(new Date().setDate(1)) } })
    ]);
    const monthlyRevenue = paidInvoices.reduce((sum, inv) => sum + (inv.total || 0), 0);
    res.json({ success: true, stats: { totalUsers, totalServers, pendingPayments, monthlyRevenue } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/users', protect, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort('-createdAt');
    for (let user of users) {
      user._doc.serverCount = await Server.countDocuments({ owner: user._id });
    }
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/users/:id', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-password');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

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

router.get('/servers', protect, adminOnly, async (req, res) => {
  try {
    const servers = await Server.find().populate('owner', 'name email').sort('-createdAt');
    res.json({ success: true, servers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/pending-payments', protect, adminOnly, async (req, res) => {
  try {
    const invoices = await Invoice.find({ status: 'processing' }).populate('user', 'name email').sort('-createdAt');
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

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
ROUTEFILE

# Settings Routes
cat > "$INSTALL_DIR/routes/settings.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect, adminOnly } = require('../middleware/auth');
const GlobalSettings = require('../models/GlobalSettings');

router.get('/public', async (req, res) => {
  try {
    let settings = await GlobalSettings.findOne();
    if (!settings) settings = await GlobalSettings.create({});
    res.json({
      success: true,
      settings: {
        appName: settings.appName,
        appTagline: settings.appTagline,
        logo: settings.logo,
        favicon: settings.favicon,
        primaryColor: settings.primaryColor,
        secondaryColor: settings.secondaryColor
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/', protect, async (req, res) => {
  try {
    let settings = await GlobalSettings.findOne();
    if (!settings) settings = await GlobalSettings.create({});
    res.json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/', protect, adminOnly, async (req, res) => {
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
ROUTEFILE

# Plans Routes
cat > "$INSTALL_DIR/routes/plans.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const Plan = require('../models/Plan');

router.get('/', async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true }).sort('displayOrder');
    res.json({ success: true, plans });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Invoices Routes
cat > "$INSTALL_DIR/routes/invoices.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Invoice = require('../models/Invoice');

router.get('/', protect, async (req, res) => {
  try {
    const invoices = await Invoice.find({ user: req.user._id }).sort('-createdAt');
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

# Public Pages Routes
cat > "$INSTALL_DIR/routes/publicPages.js" << 'ROUTEFILE'
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const PublicPage = require('../models/PublicPage');

router.get('/', protect, async (req, res) => {
  try {
    const pages = await PublicPage.find({ owner: req.user._id }).populate('servers', 'name status');
    res.json({ success: true, pages });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/', protect, async (req, res) => {
  try {
    const { name, slug, servers, isPublic, description } = req.body;
    const existing = await PublicPage.findOne({ slug });
    if (existing) return res.status(400).json({ success: false, message: 'Slug already taken' });
    
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

router.put('/:id', protect, async (req, res) => {
  try {
    const page = await PublicPage.findOneAndUpdate({ _id: req.params.id, owner: req.user._id }, req.body, { new: true });
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.delete('/:id', protect, async (req, res) => {
  try {
    await PublicPage.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/view/:slug', async (req, res) => {
  try {
    const page = await PublicPage.findOne({ slug: req.params.slug, isPublic: true }).populate('servers', 'name status metrics lastSeen');
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
ROUTEFILE

echo -e "${GREEN}✓ All route files created${NC}"

#===============================================================================
# Create agent files
#===============================================================================
echo -e "${YELLOW}Creating agent files...${NC}"

mkdir -p "$INSTALL_DIR/agent"

cat > "$INSTALL_DIR/agent/install.sh" << 'AGENTINSTALL'
#!/bin/bash
set -e
TOKEN="$1"
SERVER_URL="$2"
if [ -z "$TOKEN" ] || [ -z "$SERVER_URL" ]; then
    echo "Usage: $0 <TOKEN> <SERVER_URL>"
    exit 1
fi
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

INSTALL_DIR="/opt/xmartguard-agent"
mkdir -p "$INSTALL_DIR"

echo "Installing XMartGuard Agent..."

# Install dependencies
if command -v apt-get &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq python3 python3-pip curl
elif command -v yum &> /dev/null; then
    yum install -y -q python3 python3-pip curl
fi

pip3 install psutil requests --quiet 2>/dev/null || pip install psutil requests --quiet

# Download agent
curl -sSL "${SERVER_URL}/downloads/agent.py" -o "$INSTALL_DIR/agent.py"
chmod +x "$INSTALL_DIR/agent.py"

# Create systemd service
cat > /etc/systemd/system/xmartguard-agent.service << EOF
[Unit]
Description=XMartGuard Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agent.py --server ${SERVER_URL} --token ${TOKEN} --interval 60
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xmartguard-agent
systemctl start xmartguard-agent

echo ""
echo "✓ XMartGuard Agent installed successfully!"
echo "  Status: $(systemctl is-active xmartguard-agent)"
echo ""
AGENTINSTALL

chmod +x "$INSTALL_DIR/agent/install.sh"

# Create agent.py
cat > "$INSTALL_DIR/agent/agent.py" << 'AGENTPY'
#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import argparse
import requests
import psutil

VERSION = "2.0.0"

def get_metrics():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    load = os.getloadavg()
    net = psutil.net_io_counters()
    
    return {
        "cpu": cpu,
        "memory": mem.percent,
        "disk": disk.percent,
        "load_avg": list(load),
        "uptime": time.time() - psutil.boot_time(),
        "network": {"rx": net.bytes_recv, "tx": net.bytes_sent},
        "system_info": {
            "hostname": socket.gethostname(),
            "os": f"{os.uname().sysname} {os.uname().release}",
            "kernel": os.uname().release,
            "arch": os.uname().machine,
            "cpu_model": open('/proc/cpuinfo').read().split('model name')[1].split(':')[1].split('\n')[0].strip() if os.path.exists('/proc/cpuinfo') else "Unknown",
            "cpu_count": psutil.cpu_count()
        }
    }

def send_metrics(server_url, token):
    try:
        metrics = get_metrics()
        response = requests.post(
            f"{server_url}/api/agent/metrics",
            json=metrics,
            headers={
                "X-Agent-Token": token,
                "X-Agent-Version": VERSION,
                "Content-Type": "application/json"
            },
            timeout=30
        )
        data = response.json()
        if data.get("problems"):
            print(f"Problems detected: {len(data['problems'])}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    
    print(f"XMartGuard Agent v{VERSION}")
    print(f"Server: {args.server}")
    print(f"Interval: {args.interval}s")
    
    while True:
        send_metrics(args.server, args.token)
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
AGENTPY

chmod +x "$INSTALL_DIR/agent/agent.py"

echo -e "${GREEN}✓ Agent files created${NC}"

#===============================================================================
# Set ownership
#===============================================================================
echo -e "${YELLOW}Setting ownership...${NC}"

chown -R "$CPANEL_USER":"$CPANEL_USER" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"

echo -e "${GREEN}✓ Ownership set${NC}"

#===============================================================================
# Stop old PM2 process if running
#===============================================================================
echo -e "${YELLOW}Stopping old processes...${NC}"
pm2 delete xmartguard 2>/dev/null || true
systemctl stop xmartguard 2>/dev/null || true

echo -e "${GREEN}✓ Old processes stopped${NC}"

#===============================================================================
# DONE
#===============================================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Migration Complete! Now Setup in cPanel              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}App Location:${NC} $INSTALL_DIR"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  NEXT STEPS - Follow Carefully!${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Step 1: Login to cPanel${NC}"
echo "  → Go to: https://your-server:2083"
echo ""
echo -e "${CYAN}Step 2: Open 'Setup Node.js App'${NC}"
echo "  → Software section → Setup Node.js App"
echo ""
echo -e "${CYAN}Step 3: Click 'CREATE APPLICATION'${NC}"
echo ""
echo -e "${CYAN}Step 4: Fill these settings:${NC}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │ Node.js version    │ 18 or 20 (latest available)   │"
echo "  │ Application mode   │ Production                    │"
echo "  │ Application root   │ xmartguard                    │"
echo "  │ Application URL    │ app.xmartguard.com            │"
echo "  │ Application startup│ server.js                     │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
echo -e "${CYAN}Step 5: Click CREATE${NC}"
echo ""
echo -e "${CYAN}Step 6: Click 'Run NPM Install'${NC}"
echo "  → Wait for it to complete"
echo ""
echo -e "${CYAN}Step 7: Click 'RESTART'${NC}"
echo ""
echo -e "${GREEN}Step 8: Visit https://app.xmartguard.com${NC}"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Login Credentials:${NC}"
echo "  Email:    ${OLD_ADMIN_EMAIL:-admin@xmartguard.com}"
echo "  Password: $ADMIN_PASS"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Save these credentials now!${NC}"
echo ""
