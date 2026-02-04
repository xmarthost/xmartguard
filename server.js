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
