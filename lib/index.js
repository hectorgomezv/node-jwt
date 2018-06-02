const Mailer = require('./mailer');
const Logger = require('./logger');
const Middleware = require('./middleware');

module.exports = {
  Mailer,
  Logger,
  ...Middleware,
};
