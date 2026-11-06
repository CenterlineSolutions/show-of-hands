// pm2 process file. Edit PUBLIC_URL and DB_PATH, then: pm2 start ecosystem.config.js
module.exports = {
  apps: [{
    name: 'show-of-hands',
    script: 'server.js',
    env: {
      PORT: 3000,
      PUBLIC_URL: 'https://poll.yourdomain.com',
      DB_PATH: '/home/youruser/polling-data/polling.db',
    },
  }],
};
