const jwt = require('jsonwebtoken');
const { ROLE_USER, ROLE_ADMIN } = require('../models/util/user-roles');

const { SECRET } = process.env;

const validateToken = (token) => {
  const { id, iat, exp } = jwt.verify(token, SECRET);
  return !!(id && iat && exp);
};

const isUser = (token) => {
  const { roles } = jwt.verify(token, SECRET);
  return (roles.indexOf(ROLE_USER) >= 0);
};

const isAdmin = (token) => {
  const { roles } = jwt.verify(token, SECRET);
  return (roles.indexOf(ROLE_ADMIN) >= 0);
};

module.exports = {
  validateToken,
  isUser,
  isAdmin,
};
