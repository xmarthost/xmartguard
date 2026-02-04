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
