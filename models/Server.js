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
