const bcrypt = require('bcryptjs');
const User = require('../models/user');
const _ = require('lodash');
const bluebird = require('bluebird');
const crypto = require('crypto');

const randomBytes = bluebird.promisify(crypto.randomBytes);

const {
  ERR_DUPLICATED_USER,
  ERR_INVALID_PASSWORD,
  ERR_INVALID_EMAIL,
  ERR_INVALID_TOKEN,
} = require('../lib/errors');
const { passwordValidator } = require('./password-validator');
const { ROLE_USER, ROLE_ADMIN } = require('../models/util/user-roles');

const SALT_ROUNDS = 10;

const hashPassword = async password =>
  bcrypt.hash(password, SALT_ROUNDS);

const validatePassword = (password) => {
  if (!_.isString(password) || !passwordValidator.validate(password)) {
    throw new Error(ERR_INVALID_PASSWORD);
  }
};

const validateToken = (user, token) => {
  if (user.reset_pass_token !== token) {
    throw new Error(ERR_INVALID_TOKEN);
  }
};

class UserBusiness {
  static async createUser(user, isAdmin = false) {
    const { email, password } = user;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error(ERR_DUPLICATED_USER);
    } else {
      validatePassword(password);
      const hashedPass = await hashPassword(user.password);
      const roles = [ROLE_USER];
      if (isAdmin) roles.push(ROLE_ADMIN);
      return User.create({
        ...user,
        password: hashedPass,
        roles,
      });
    }
  }

  static async generateToken() {
    const token = await randomBytes(48);
    return token.toString('hex');
  }

  static async generateResetToken(email) {
    try {
      const token = await UserBusiness.generateToken();
      await User.findOneAndUpdate(
        { email },
        { reset_pass_token: token },
      ).exec();
      return token;
    } catch (err) {
      return Promise.reject(new Error(ERR_INVALID_EMAIL));
    }
  }

  static async resetPassword(email, password, token) {
    try {
      const user = await User.findOne({ email });
      validateToken(user, token);
      return user;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  static async changePassword(email, newPassword) {
    validatePassword(newPassword);
    const user = await User.findOne({ email });
    user.password = newPassword;
    await user.save();
    return user;
  }
}

module.exports = UserBusiness;
