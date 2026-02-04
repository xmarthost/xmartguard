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
