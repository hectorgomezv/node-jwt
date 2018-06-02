module.exports = {
  apps: [
    {
      name: 'node-jwt',
      script: './bin/www',
      env: {
        NODE_ENV: 'development',
        MONGO_URL: 'mongodb://localhost:27017/node-jwt',
        SECRET: 'supersecret',
        TOKEN_EXPIRATION: '604800',
        MAILGUN_SANDBOX: 'yourMailgunSandBox',
        MAILGUN_PASS: 'yourMailgunPassword',
      },
    },
  ],
};
