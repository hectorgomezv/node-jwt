const authErrors = require('./auth-errors');
const userErrors = require('./user-errors');

module.exports = {
  ...userErrors,
  ...authErrors,
};
