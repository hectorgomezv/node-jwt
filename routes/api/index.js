const router = require('express').Router();
const AuthController = require('../../controllers/auth-controller');
const PingController = require('../../controllers/ping-controller');

router.use('/', PingController);
router.use('/auth', AuthController);

module.exports = router;
