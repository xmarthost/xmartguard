const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Server = require('../models/Server');
const User = require('../models/User');

router.get('/stats', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const [totalServers, onlineServers, offlineServers, serverData] = await Promise.all([
      Server.countDocuments({ owner: req.user._id }),
      Server.countDocuments({ owner: req.user._id, status: 'online' }),
      Server.countDocuments({ owner: req.user._id, status: { $in: ['offline', 'pending'] } }),
      Server.find({ owner: req.user._id }).select('problems')
    ]);
    
    let openIncidents = 0;
    serverData.forEach(s => { if (s.problems?.length) openIncidents += s.problems.length; });
    
    res.json({
      success: true,
      stats: {
        totalServers, onlineServers, offlineServers, openIncidents,
        serverLimit: user.subscription.serverLimit,
        serversRemaining: user.subscription.serverLimit - totalServers,
        plan: user.subscription.plan
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/server-status', protect, async (req, res) => {
  try {
    const servers = await Server.find({ owner: req.user._id })
      .select('name ipAddress status metrics problems lastSeen systemInfo')
      .sort('-lastSeen');
    res.json({ success: true, servers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/subscription', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const serverCount = await Server.countDocuments({ owner: req.user._id });
    const hasPendingUpgrade = user.pendingUpgrade?.status === 'pending';
    
    res.json({
      success: true,
      subscription: {
        plan: user.subscription.plan,
        status: user.subscription.status,
        serverLimit: user.subscription.serverLimit,
        serverCount,
        serversRemaining: user.subscription.serverLimit - serverCount,
        endDate: user.subscription.endDate,
        hasPendingUpgrade,
        pendingUpgrade: hasPendingUpgrade ? user.pendingUpgrade : null
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
