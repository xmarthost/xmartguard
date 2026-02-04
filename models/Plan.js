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
