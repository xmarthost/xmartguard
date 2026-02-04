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
