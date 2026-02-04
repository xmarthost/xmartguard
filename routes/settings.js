const express = require('express');
const router = express.Router();
const { protect, adminOnly } = require('../middleware/auth');
const GlobalSettings = require('../models/GlobalSettings');

router.get('/public', async (req, res) => {
  try {
    let settings = await GlobalSettings.findOne();
    if (!settings) settings = await GlobalSettings.create({});
    res.json({
      success: true,
      settings: {
        appName: settings.appName,
        appTagline: settings.appTagline,
        logo: settings.logo,
        favicon: settings.favicon,
        primaryColor: settings.primaryColor,
        secondaryColor: settings.secondaryColor
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/', protect, async (req, res) => {
  try {
    let settings = await GlobalSettings.findOne();
    if (!settings) settings = await GlobalSettings.create({});
    res.json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/', protect, adminOnly, async (req, res) => {
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
