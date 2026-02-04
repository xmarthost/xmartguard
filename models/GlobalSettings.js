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
