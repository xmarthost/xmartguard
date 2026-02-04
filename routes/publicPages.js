const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const PublicPage = require('../models/PublicPage');

router.get('/', protect, async (req, res) => {
  try {
    const pages = await PublicPage.find({ owner: req.user._id }).populate('servers', 'name status');
    res.json({ success: true, pages });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/', protect, async (req, res) => {
  try {
    const { name, slug, servers, isPublic, description } = req.body;
    const existing = await PublicPage.findOne({ slug });
    if (existing) return res.status(400).json({ success: false, message: 'Slug already taken' });
    
    const page = await PublicPage.create({
      owner: req.user._id,
      name,
      slug: slug.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
      servers,
      isPublic,
      description
    });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put('/:id', protect, async (req, res) => {
  try {
    const page = await PublicPage.findOneAndUpdate({ _id: req.params.id, owner: req.user._id }, req.body, { new: true });
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.delete('/:id', protect, async (req, res) => {
  try {
    await PublicPage.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/view/:slug', async (req, res) => {
  try {
    const page = await PublicPage.findOne({ slug: req.params.slug, isPublic: true }).populate('servers', 'name status metrics lastSeen');
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
