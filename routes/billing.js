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
