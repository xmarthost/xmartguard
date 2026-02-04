const express = require('express');
const router = express.Router();
const Server = require('../models/Server');

function detectProblems(metrics) {
  const problems = [];
  if (metrics.cpu > 80) {
    problems.push({
      problemType: 'cpu',
      severity: metrics.cpu > 90 ? 'critical' : 'warning',
      message: `High CPU usage: ${metrics.cpu}%`,
      suggestion: 'Check top processes: top -bn1 | head -20',
      detectedAt: new Date()
    });
  }
  if (metrics.memory > 85) {
    problems.push({
      problemType: 'memory',
      severity: metrics.memory > 95 ? 'critical' : 'warning',
      message: `High memory usage: ${metrics.memory}%`,
      suggestion: 'Free cache: sync && echo 3 > /proc/sys/vm/drop_caches',
      detectedAt: new Date()
    });
  }
  if (metrics.disk > 90) {
    problems.push({
      problemType: 'disk',
      severity: metrics.disk > 95 ? 'critical' : 'warning',
      message: `Low disk space: ${metrics.disk}% used`,
      suggestion: 'Find large files: du -h / | sort -rh | head -20',
      detectedAt: new Date()
    });
  }
  return problems;
}

router.post('/metrics', async (req, res) => {
  try {
    const token = req.headers['x-agent-token'];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });
    
    const server = await Server.findOne({ agentToken: token });
    if (!server) return res.status(404).json({ success: false, message: 'Invalid token' });
    
    const metrics = req.body;
    const problems = detectProblems(metrics);
    
    const updateData = {
      status: 'online',
      lastSeen: new Date(),
      'metrics.cpu': metrics.cpu || 0,
      'metrics.memory': metrics.memory || 0,
      'metrics.disk': metrics.disk || 0,
      'metrics.loadAvg': metrics.load_avg || [0, 0, 0],
      'metrics.uptime': metrics.uptime || 0,
      'metrics.network': metrics.network || { rx: 0, tx: 0 },
      problems,
      agentVersion: req.headers['x-agent-version'] || 'unknown'
    };
    
    if (metrics.system_info) {
      updateData['systemInfo.hostname'] = metrics.system_info.hostname;
      updateData['systemInfo.os'] = metrics.system_info.os;
      updateData['systemInfo.kernel'] = metrics.system_info.kernel;
      updateData['systemInfo.arch'] = metrics.system_info.arch;
      updateData['systemInfo.cpuModel'] = metrics.system_info.cpu_model;
      updateData['systemInfo.cpuCount'] = metrics.system_info.cpu_count;
    }
    
    await Server.findByIdAndUpdate(server._id, updateData);
    
    const io = req.app.get('io');
    if (io) {
      io.to(`server_${server._id}`).emit('metrics_update', { serverId: server._id, metrics, problems, status: 'online' });
    }
    
    res.json({ success: true, message: 'Metrics received', problems });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/info', async (req, res) => {
  try {
    const token = req.headers['x-agent-token'];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });
    
    const server = await Server.findOne({ agentToken: token });
    if (!server) return res.status(404).json({ success: false, message: 'Invalid token' });
    
    res.json({ success: true, server: { name: server.name, ipAddress: server.ipAddress, id: server._id } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
