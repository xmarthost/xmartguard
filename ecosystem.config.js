module.exports = {
  apps: [{
    name: 'xmartguard',
    script: '/opt/xmartguard/start.sh',
    cwd: '/opt/xmartguard',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '500M',
    env: {
      NODE_ENV: 'production'
    },
    error_file: '/opt/xmartguard/logs/error.log',
    out_file: '/opt/xmartguard/logs/output.log',
    time: true
  }]
};
