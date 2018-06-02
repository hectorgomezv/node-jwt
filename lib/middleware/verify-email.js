const User = require('../../models/user');
const { ERR_INVALID_EMAIL } = require('../../lib/errors');

const sendError = res =>
  res.status(400).json({ error: ERR_INVALID_EMAIL });

const verifyEmail = async (req, res, next) => {
  const { body: { email } } = req;
  const user = await User.findOne({ email }).exec();
  if (!user) sendError(res);
  else next();
};

module.exports = verifyEmail;
