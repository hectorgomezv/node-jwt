/* eslint-disable prefer-destructuring */

const request = require('supertest');
const app = require('../../app');
const { assert } = require('chai');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sinon = require('sinon');
const UserBusiness = require('../../business/user-business');

const User = require('../../models/user');
const {
  ERR_INVALID_PASSWORD,
  ERR_INVALID_EMAIL,
  ERR_INVALID_LOGIN,
  ERR_INVALID_TOKEN,
  ERR_TOKEN_REQUIRED,
  ERR_OP_NOT_ALLOWED,
} = require('../../lib/errors');
const { validateToken, isUser, isAdmin } = require('../test-utils');

let userToken;
let adminToken;
let saToken;
const base = '/api/auth';
const USER_EMAIL = 'usermail@mail.com';
const USER_PASSWORD = 'c0rrectPa$$w04D';
const USER = {
  email: USER_EMAIL,
  password: USER_PASSWORD,
};
const ADMIN_EMAIL = 'testAdminMail@admins.com';
const RESET_TOKEN = 'testToken';
const BAD_NEW_PASSWORD = 'newPassword';
const NEW_GOOD_PASSWORD = 'neWG00DP4$$w04D';

describe('[integration] [/user]', () => {
  before(async () => {
    await User.remove({});
    const saPasswordHash = await bcrypt.hash(process.env.SA_PASSWORD, 10);
    await User.create({
      email: process.env.SA_EMAIL,
      password: saPasswordHash,
      roles: ['user', 'admin', 'sa'],
    });
  });
  after(() => User.remove({}));

  describe('register users', () => {
    it('{POST} OK [/user]', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then((res) => {
          const { body, status } = res;
          assert.equal(status, 200);
          assert.deepEqual(body.auth, true);
          userToken = body.token;
          assert.isTrue(validateToken(userToken));
          assert.isTrue(isUser(userToken));
          done();
        });
    });

    it('{POST} OK [/login] (login as superadmin)', (done) => {
      request(app)
        .post(`${base}/login`)
        .set('Content-Type', 'application/json')
        .send({
          email: process.env.SA_EMAIL,
          password: process.env.SA_PASSWORD,
        })
        .then((res) => {
          const { body, status } = res;
          assert.equal(status, 200);
          assert.deepEqual(body.auth, true);
          const decoded = jwt.verify(body.token, process.env.SECRET);
          assert.include(decoded.roles, 'sa');
          saToken = body.token;
          done();
        });
    });

    it('{POST} OK [/user] (superadmin registering admin)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', saToken)
        .send({
          email: ADMIN_EMAIL,
          password: '4DMinPa$$W0rD',
          roles: ['admin'],
        })
        .then((res) => {
          const { body, status } = res;
          assert.equal(status, 200);
          assert.deepEqual(body.auth, true);
          adminToken = body.token;
          assert.isTrue(validateToken(adminToken));
          assert.isTrue(isUser(adminToken));
          assert.isTrue(isAdmin(adminToken));
          done();
        });
    });

    it('{POST} KO [/user] (invalid password)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send({
          email: 'good@email.com',
          password: 'badpass',
        })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 400);
          assert.include(error, { error: ERR_INVALID_PASSWORD });
          done();
        });
    });

    it('{POST} KO [/user] (invalid email)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send({
          email: 'badmail@',
          password: USER_PASSWORD,
        })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 400);
          assert.match(error.error, new RegExp(ERR_INVALID_EMAIL));
          done();
        });
    });
  });

  describe('get user identity', () => {
    it('{GET} OK [/user]', (done) => {
      request(app)
        .get(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .then((res) => {
          const { body, status } = res;
          assert.equal(status, 200);
          assert.equal(body.email, USER_EMAIL);
          assert.notProperty(body, 'password');
          done();
        });
    });

    it('{GET} KO [/user] (no token provided)', (done) => {
      request(app)
        .get(`${base}/user`)
        .set('Content-Type', 'application/json')
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_TOKEN_REQUIRED));
          done();
        });
    });

    it('{GET} KO [/user] (invalid token)', (done) => {
      request(app)
        .get(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', 'invalidToken')
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_INVALID_TOKEN));
          done();
        });
    });
  });

  describe('user login and logout', () => {
    it('{GET} OK [/logout]', (done) => {
      request(app)
        .get(`${base}/logout`)
        .set('Authorization', userToken)
        .then((res) => {
          const { body } = res;
          assert.deepEqual(body.auth, false);
          assert.isNull(body.token);
          done();
        });
    });

    it('{POST} OK [/login]', (done) => {
      request(app)
        .post(`${base}/login`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then((res) => {
          const { body, status } = res;
          assert.equal(status, 200);
          assert.deepEqual(body.auth, true);
          assert.isDefined(body.token);
          userToken = body.token;
          done();
        });
    });

    it('{POST} KO [/login] (invalid login)', (done) => {
      request(app)
        .post(`${base}/login`)
        .set('Content-Type', 'application/json')
        .send({
          email: USER_EMAIL,
          password: 'badpass',
        })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 401);
          assert.match(error.error, new RegExp(ERR_INVALID_LOGIN));
          done();
        });
    });
  });

  describe('delete users', () => {
    it('{DELETE} KO [/user] (no token provided)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_TOKEN_REQUIRED));
          done();
        });
    });

    it('{DELETE} KO [/user] (bad token provided)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', 'thisIsABadToken')
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_INVALID_TOKEN));
          done();
        });
    });

    it('{DELETE} KO [/user] (not requested by an admin)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_OP_NOT_ALLOWED));
          done();
        });
    });

    it('{DELETE} OK [/user]', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', adminToken)
        .send({ email: USER_EMAIL })
        .then((res) => {
          assert.equal(res.status, 200);
          assert.property(res.body, 'email');
          done();
        });
    });

    it('{DELETE} KO [/user] (admin can\'t delete admins)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', adminToken)
        .send({ email: ADMIN_EMAIL })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_OP_NOT_ALLOWED));
          done();
        });
    });

    it('{DELETE} KO [/user] (admin can\'t delete superadmin)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', adminToken)
        .send({ email: process.env.SA_EMAIL })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_OP_NOT_ALLOWED));
          done();
        });
    });

    it('{DELETE} OK [/user] (superadmin can delete admins)', (done) => {
      request(app)
        .delete(`${base}/user`)
        .set('Content-Type', 'application/json')
        .set('Authorization', saToken)
        .send({ email: ADMIN_EMAIL })
        .then((res) => {
          assert.equal(res.status, 200);
          assert.property(res.body, 'email');
          done();
        });
    });
  });

  describe('password resets', () => {
    it.skip('{POST} OK [/password-reset]', (done) => {
      request(app)
        .post(`${base}/password-reset`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .send({ email: USER_EMAIL })
        .then((res) => {
          assert.equal(res.status, 200);
          done();
        });
    }).timeout(15000);

    it('{POST} KO [/password-reset] (invalid email)', (done) => {
      request(app)
        .post(`${base}/password-reset`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .send({ email: 'badmail@@' })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 400);
          assert.match(error.error, new RegExp(ERR_INVALID_EMAIL));
          done();
        });
    });

    it('{POST} KO [/password-reset] (non-existing email)', (done) => {
      request(app)
        .post(`${base}/password-reset`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .send({ email: 'nomail@existing.com' })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 400);
          assert.match(error.error, new RegExp(ERR_INVALID_EMAIL));
          done();
        });
    });

    it('{POST} KO [/password-reset] (no token)', (done) => {
      request(app)
        .post(`${base}/password-reset`)
        .set('Content-Type', 'application/json')
        .send({ email: USER_EMAIL })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_TOKEN_REQUIRED));
          done();
        });
    });

    it('{POST} KO [/password-reset] (token and email doesn\'t match)', (done) => {
      request(app)
        .post(`${base}/password-reset`)
        .set('Content-Type', 'application/json')
        .set('Authorization', userToken)
        .send({ email: process.env.SA_EMAIL })
        .then((res) => {
          const error = JSON.parse(res.error.text);
          assert.equal(res.status, 403);
          assert.match(error.error, new RegExp(ERR_OP_NOT_ALLOWED));
          done();
        });
    });

    it.skip('{POST} OK [/password-change]', (done) => {
      const generateTokenStub = sinon.stub(UserBusiness, 'generateToken');
      generateTokenStub.resolves(RESET_TOKEN);
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then(() => {
          request(app)
            .post(`${base}/password-reset`)
            .set('Content-Type', 'application/json')
            .send({ email: USER.email })
            .then(() => {
              request(app)
                .post(`${base}/password-change`)
                .set('Content-Type', 'application/json')
                .send({ email: USER_EMAIL, password: 'newPassword', token: RESET_TOKEN })
                .then((res) => {
                  assert.equal(res.status, 200);
                  assert.isTrue(bcrypt.compareSync(USER.password, res.body.user.password));
                  done();
                });
            });
        });
    });

    it('{POST} KO [/password-change] (bad token)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then(() => {
          request(app)
            .post(`${base}/password-change`)
            .set('Content-Type', 'application/json')
            .send({ email: USER_EMAIL, password: 'newPassword', token: 'badToken' })
            .then((res) => {
              const error = JSON.parse(res.error.text);
              assert.equal(res.status, 500);
              assert.match(error.error, new RegExp(ERR_INVALID_TOKEN));
              done();
            });
        });
    });
  });

  describe('password changes', () => {
    beforeEach(() => User.remove({}));

    it('{PATCH} OK [/password-change]', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then((registerResponse) => {
          const { email, password } = USER;
          request(app)
            .patch(`${base}/password-change`)
            .set('Content-Type', 'application/json')
            .set('Authorization', registerResponse.body.token)
            .send({ email, oldPassword: password, newPassword: NEW_GOOD_PASSWORD })
            .then((changePassResponse) => {
              const { body } = changePassResponse;
              assert.equal(changePassResponse.status, 200);
              assert.isTrue(body.auth);
              assert.isDefined(body.token);
              done();
            });
        });
    });

    it('{PATCH} KO [/password-change] (bad token)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then(() => {
          const { email, password } = USER;
          request(app)
            .patch(`${base}/password-change`)
            .set('Content-Type', 'application/json')
            .set('Authorization', 'badToken')
            .send({ email, oldPassword: password, newPassword: NEW_GOOD_PASSWORD })
            .then((res) => {
              const error = JSON.parse(res.error.text);
              assert.equal(res.status, 403);
              assert.match(error.error, new RegExp(ERR_INVALID_TOKEN));
              done();
            });
        });
    });

    it('{PATCH} KO [/password-change] (bad new password)', (done) => {
      request(app)
        .post(`${base}/user`)
        .set('Content-Type', 'application/json')
        .send(USER)
        .then((registerResponse) => {
          const { email, password } = USER;
          request(app)
            .patch(`${base}/password-change`)
            .set('Content-Type', 'application/json')
            .set('Authorization', registerResponse.body.token)
            .send({ email, oldPassword: password, newPassword: BAD_NEW_PASSWORD })
            .then((res) => {
              const error = JSON.parse(res.error.text);
              assert.equal(res.status, 403);
              assert.match(error.error, new RegExp(ERR_INVALID_PASSWORD));
              done();
            });
        });
    });
  });
});
