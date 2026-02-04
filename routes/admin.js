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

// Get ALL payments (history)
router.get('/all-payments', protect, adminOnly, async (req, res) => {
  try {
    const invoices = await Invoice.find()
      .populate('user', 'name email')
      .sort('-createdAt')
      .limit(100);
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
