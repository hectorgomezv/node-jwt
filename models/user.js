const mongoose = require('mongoose');
const {
  ERR_EMAIL_REQUIRED,
  ERR_INVALID_EMAIL,
  ERR_PASSWORD_REQUIRED,
} = require('../lib/errors');
const { ROLES } = require('./util/user-roles');

const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: [true, ERR_EMAIL_REQUIRED],
    validate: {
      validator: v => /^([\w-.]+@([\w-]+\.)+[\w-]{2,4})?$/.test(v),
      message: ERR_INVALID_EMAIL,
    },
  },
  password: {
    type: String,
    required: [true, ERR_PASSWORD_REQUIRED],
  },
  reset_pass_token: String,
  roles: [{
    type: String,
    enum: ROLES,
    required: true,
    default: 'user',
  }],
});

module.exports = mongoose.model('User', userSchema);
