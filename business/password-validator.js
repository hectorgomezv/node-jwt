const Validator = require('password-validator');

const passwordValidator = new Validator();

passwordValidator
  .is().min(8)
  .is().max(100)
  .has()
  .uppercase()
  .has()
  .lowercase()
  .has()
  .digits()
  .has()
  .not()
  .spaces()
  .is()
  .not()
  .oneOf(['Passw0rd', 'Password123']);

module.exports = {
  passwordValidator,
};
