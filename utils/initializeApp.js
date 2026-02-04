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
