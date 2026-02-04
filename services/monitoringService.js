const Server = require('../models/Server');

class MonitoringService {
  constructor() {
    this.interval = null;
    this.checkInterval = 30000; // 30 seconds
  }
  
  startMonitoring(io) {
    this.io = io;
    
    // Initial check
    this.checkServers();
    
    // Start interval
    this.interval = setInterval(() => {
      this.checkServers();
    }, this.checkInterval);
    
    console.log(`  ✓ Monitoring service started (checks every ${this.checkInterval/1000}s)`);
  }
  
  async checkServers() {
    try {
      const threshold = new Date(Date.now() - 2 * 60 * 1000); // 2 minutes
      
      // Find servers that haven't reported in 2 minutes
      const offlineServers = await Server.find({
        status: 'online',
        lastSeen: { $lt: threshold }
      });
      
      for (const server of offlineServers) {
        await Server.findByIdAndUpdate(server._id, { status: 'offline' });
        
        // Emit status change
        if (this.io) {
          this.io.to(`server_${server._id}`).emit('status_change', {
            serverId: server._id,
            status: 'offline',
            message: 'Server stopped responding'
          });
          
          // Notify user
          this.io.to(`user_${server.owner}`).emit('server_offline', {
            serverId: server._id,
            serverName: server.name,
            message: `Server ${server.name} is now offline`
          });
        }
      }
    } catch (err) {
      console.error('Monitoring check error:', err.message);
    }
  }
  
  stopMonitoring() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
      console.log('  ✓ Monitoring service stopped');
    }
  }
}

module.exports = new MonitoringService();
