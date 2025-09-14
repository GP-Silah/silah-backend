module.exports = {
    apps: [
        {
            name: 'silah-backend', // The name that shows in pm2 list
            script: 'dist/src/main.js', // The entry point (after build)
            instances: 1, // Or "max" for all CPU cores
            autorestart: true, // Restart if it crashes
            watch: false, // Set true if you want auto-restart on code changes
            max_memory_restart: '500M', // Restart if memory exceeds this
            env: {
                NODE_ENV: 'development',
            },
            env_production: {
                NODE_ENV: 'production',
            },
        },
    ],
};
