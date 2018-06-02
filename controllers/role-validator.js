const jwt = require('jsonwebtoken');
const _ = require('lodash');

const {
  ERR_INVALID_TOKEN,
  ERR_TOKEN_REQUIRED,
  ERR_OP_NOT_ALLOWED,
} = require('../lib/errors');
const { ROLE_ADMIN, ROLE_SA } = require('../models/util/user-roles');

const { SECRET } = process.env;

const extractToken = (headers) => {
  const { authorization } = headers;
  if (!authorization || !_.isString) {
    throw new Error(ERR_TOKEN_REQUIRED);
  }
  return authorization;
};

const decodeJwt = (req) => {
  const token = extractToken(req.headers);
  return jwt.verify(token, SECRET);
};

const isAdmin = (req) => {
  const decoded = decodeJwt(req);
  return (decoded.roles && decoded.roles.indexOf(ROLE_ADMIN) >= 0);
};

const isSuperadmin = (req) => {
  const decoded = decodeJwt(req);
  return (decoded.roles && decoded.roles.indexOf(ROLE_SA) >= 0);
};

const requireAdmin = (req, res, next) => {
  try {
    if (!isAdmin(req)) throw new Error(ERR_OP_NOT_ALLOWED);
    next();
  } catch (err) {
    let responseError;
    if (err.message === ERR_TOKEN_REQUIRED || err.message === ERR_OP_NOT_ALLOWED) {
      responseError = err;
    } else {
      responseError = new Error(ERR_INVALID_TOKEN);
    }
    res.status(403).json({ error: responseError.message });
  }
};

module.exports = { requireAdmin, isAdmin, isSuperadmin };
