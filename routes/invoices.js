const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Invoice = require('../models/Invoice');

router.get('/', protect, async (req, res) => {
  try {
    const invoices = await Invoice.find({ user: req.user._id }).sort('-createdAt');
    res.json({ success: true, invoices });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
