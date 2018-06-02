const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const UserBusiness = require('../business/user-business');
const User = require('../models/user');
const verifyToken = require('./verify-token');
const { requireAdmin, isSuperadmin, isAdmin } = require('./role-validator');
const { verifyEmail } = require('../lib/middleware');
const { Mailer } = require('../lib');
const {
  ERR_INVALID_TOKEN,
  ERR_TOKEN_REQUIRED,
  ERR_INVALID_LOGIN,
  ERR_USER_NOT_FOUND,
  ERR_OP_NOT_ALLOWED,
} = require('../lib/errors');
const { ROLE_ADMIN } = require('../models/util/user-roles');

const router = express.Router();
const { SECRET, TOKEN_EXPIRATION } = process.env;

const validatePassword = async (user, password) => {
  const res = await bcrypt.compare(password, user.password);
  if (!res) throw new Error(ERR_INVALID_LOGIN);
};

const parseUser = user => _.pick(user, ['email', 'roles']);

const generateToken = user => jwt.sign(
  {
    id: user._id,
    roles: user.roles,
  },
  SECRET, { expiresIn: TOKEN_EXPIRATION },
);

router.post('/login', async (req, res) => {
  try {
    const { body: { email, password } } = req;
    const user = await User.findOne({ email });
    await validatePassword(user, password);
    const token = generateToken(user);
    res.status(200).send({ auth: true, token });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

router.get('/logout', verifyToken, (req, res) => {
  res.status(200).send({ auth: false, token: null });
});

router.get('/user', verifyToken, async (req, res, next) => {
  try {
    const user = await User.findOne({ _id: req.userId });
    const response = parseUser(user);
    res.status(200).json(response);
  } catch (err) {
    const response = (err.message === ERR_TOKEN_REQUIRED) ?
      err : new Error(ERR_INVALID_TOKEN);
    res.status(403).json({ error: response.message });
  }
});

router.post('/user', async (req, res) => {
  try {
    const { body } = req;
    let createAsAdmin = false;
    if (_.isArray(body.roles)
      && body.roles.indexOf(ROLE_ADMIN) >= 0
      && isSuperadmin(req)
    ) {
      createAsAdmin = true;
    }
    const user = await UserBusiness.createUser(body, createAsAdmin);
    const token = generateToken(user);
    res.status(200).send({ auth: true, token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/user', requireAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new Error(ERR_USER_NOT_FOUND);
    if (isSuperadmin(req) || (isAdmin(req) && user.roles.indexOf(ROLE_ADMIN) < 0)) {
      await User.deleteOne({ _id: user.id });
      res.status(200).send(user);
    } else {
      res.status(403).json({ error: ERR_OP_NOT_ALLOWED });
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/password-reset', verifyToken, verifyEmail, async (req, res) => {
  try {
    const { body: { email } } = req;
    const user = await User.findOne({ _id: req.userId });
    if (!user || !_.get(user, 'email') || _.get(user, 'email') !== email) {
      throw new Error(ERR_OP_NOT_ALLOWED);
    }
    const token = await UserBusiness.generateResetToken(email);
    const info = await Mailer.sendResetEmail(email, token);
    res.status(200).json({ sent: info });
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
});

router.post('/password-change', verifyEmail, async (req, res) => {
  try {
    const { body: { email, password, token } } = req;
    const user = await UserBusiness.resetPassword(email, password, token);
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch('/password-change', verifyToken, async (req, res) => {
  try {
    const { body: { email, oldPassword, newPassword } } = req;
    const user = await User.findOne({ email });
    await validatePassword(user, oldPassword);
    const modifiedUser = await UserBusiness.changePassword(email, newPassword);
    const token = jwt.sign({ id: modifiedUser._id }, SECRET, { expiresIn: TOKEN_EXPIRATION });
    res.status(200).send({ auth: true, token });
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
});

module.exports = router;
