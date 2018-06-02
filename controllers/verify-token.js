const jwt = require('jsonwebtoken');
const _ = require('lodash');

const { SECRET } = process.env;
const {
  ERR_INVALID_TOKEN,
  ERR_TOKEN_REQUIRED,
} = require('../lib/errors');

const extractToken = (headers) => {
  const { authorization } = headers;
  if (!authorization || !_.isString) {
    throw new Error(ERR_TOKEN_REQUIRED);
  }
  return authorization;
};

const verifyToken = (req, res, next) => {
  try {
    const token = extractToken(req.headers);
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    req.userRoles = decoded.roles;
    next();
  } catch (err) {
    const responseError = (err.message === ERR_TOKEN_REQUIRED) ?
      err : new Error(ERR_INVALID_TOKEN);
    res.status(403).json({ error: responseError.message });
  }
};

module.exports = verifyToken;
