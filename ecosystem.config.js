module.exports = {
  apps: [
    {
      name: 'pulsewave-server',
      script: 'server.js',
      cwd: 'C:\\Users\\elias\\pulsewave-server',
      watch: false,
      autorestart: true,
      restart_delay: 3000,
      env: { PORT: 3333, NODE_ENV: 'production' }
    },
    {
      name: 'pulsewave-tunnel',
      script: 'tunnel.js',
      cwd: 'C:\\Users\\elias\\pulsewave-server',
      watch: false,
      autorestart: true,
      restart_delay: 1000
    }
  ]
};
