/* eslint-disable no-unused-expressions */

const mongoose = require('mongoose');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const bcrypt = require('bcryptjs');

const UserBusiness = require('../../business/user-business');
const User = require('../../models/user');
const {
  ERR_INVALID_EMAIL,
  ERR_INVALID_PASSWORD,
  ERR_DUPLICATED_USER,
  ERR_INVALID_TOKEN,
} = require('../../lib/errors');
const { ROLE_USER, ROLE_ADMIN } = require('../../models/util/user-roles');

chai.use(chaiAsPromised);

const { expect } = chai;
const GOOD_EMAIL = 'propermail@mail.com';
const GOOD_PASS = 'g00dPa$s';
const BAD_PASS = 'badPass';
const BAD_EMAIL = 'badmail@@@';
const NEW_GOOD_PASSWORD = 'neWG00DP4$$w04D';
const GOOD_USER = {
  email: GOOD_EMAIL,
  password: GOOD_PASS,
};

describe('[unit] [user-business]', () => {
  after(() => User.remove({}));

  describe('creating users', () => {
    beforeEach(() => User.remove({}));
    after(() => User.remove({}));

    it('should NOT create a user with a bad email', (done) => {
      const promise = UserBusiness.createUser({
        email: BAD_EMAIL,
        password: GOOD_PASS,
      });
      expect(promise).to.be.rejected
        .and.eventually.have.nested.property('errors.email.message', ERR_INVALID_EMAIL)
        .notify(done);
    });

    it('should NOT create a user with a bad password', (done) => {
      expect(UserBusiness.createUser({
        email: GOOD_EMAIL,
        password: BAD_PASS,
      }))
        .to.be.rejected
        .and.eventually.have.property('message', ERR_INVALID_PASSWORD)
        .notify(done);
    });

    it('should NOT create an existing user', async () => {
      try {
        await UserBusiness.createUser(GOOD_USER);
        const secondUser = await UserBusiness.createUser(GOOD_USER);
        expect(secondUser).to.be.undefined;
      } catch (err) {
        expect(err).to.have.property('message', ERR_DUPLICATED_USER);
      }
    });

    it('should create a proper user', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const user = createdUser.toObject();
      expect(user).to.have.property('email', GOOD_EMAIL);
      expect(user.roles).to.have.lengthOf(1).and.to.include(ROLE_USER);
      const compareResult = await bcrypt.compare(GOOD_PASS, user.password);
      expect(compareResult).to.be.true;
    });
  });

  describe('finding users', () => {
    beforeEach(() => User.remove({}));

    it('should find an existing user by id', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const user = await User.findOne({ _id: createdUser.id });
      expect(user).to.have.property('email', GOOD_EMAIL);
      const compareResult = await bcrypt.compare(GOOD_PASS, createdUser.password);
      expect(compareResult).to.be.true;
    });

    it('should NOT find a non-existing user by id', async () => {
      const user = await User.findOne({ _id: mongoose.Types.ObjectId() });
      expect(user).to.be.null;
    });

    it('should find an existing user by email', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const user = await User.findOne({ email: GOOD_EMAIL });
      expect(user).to.have.property('email', GOOD_EMAIL);
      const comparePromise = await bcrypt.compare(GOOD_PASS, createdUser.password);
      expect(comparePromise).to.be.true;
    });

    it('should NOT find a non-existing user by email', async () => {
      const user = await User.findOne({ email: 'non@existent.email' });
      expect(user).to.be.null;
    });
  });

  describe('deleting users', () => {
    beforeEach(() => User.remove({}));

    it('should NOT delete any user if a non-existent user is passed', async () => {
      await UserBusiness.createUser(GOOD_USER);
      expect(await User.count({})).to.be.equal(1);
      await User.deleteOne({ _id: mongoose.Types.ObjectId() });
      expect(await User.count({})).to.be.equal(1);
    });

    it('should delete the user', async () => {
      const created = await UserBusiness.createUser(GOOD_USER);
      expect(await User.count({})).to.be.equal(1);
      await User.deleteOne({ _id: created.id });
      expect(await User.count({})).to.be.equal(0);
    });
  });

  describe('creating admins', () => {
    beforeEach(() => User.remove({}));

    it('should create a proper admin', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER, true);
      const user = createdUser.toObject();
      expect(user).to.have.property('email', GOOD_EMAIL);
      expect(user.roles).to.have.lengthOf(2)
        .and.to.include(ROLE_USER)
        .and.to.include(ROLE_ADMIN);
      const compareResult = await bcrypt.compare(GOOD_PASS, user.password);
      expect(compareResult).to.be.true;
    });
  });

  describe('reset password tokens generation and checking', () => {
    beforeEach(() => User.remove({}));

    it('should generate and store a reset password token', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const token = await UserBusiness.generateResetToken(createdUser.email);
      const user = await User.findOne({ email: GOOD_USER.email });
      expect(token).to.be.equal(user.reset_pass_token);
    });

    it('should update a reset password token', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const token = await UserBusiness.generateResetToken(createdUser.email);
      const user = await User.findOne({ email: GOOD_USER.email });
      expect(token).to.be.equal(user.reset_pass_token);
      const newToken = await UserBusiness.generateResetToken(createdUser.email);
      const newUser = await User.findOne({ email: GOOD_USER.email });
      expect(newToken).to.be.equal(newUser.reset_pass_token);
    });

    it('should change pass if token is valid', (done) => {
      UserBusiness.createUser(GOOD_USER)
        .then((createdUser) => {
          UserBusiness.generateResetToken(createdUser.email)
            .then((token) => {
              const promise = UserBusiness.resetPassword(createdUser.email, 'newPas$W0rD', token);
              expect(promise).to.be.fulfilled
                .and.eventually.have.property('email', GOOD_USER.email)
                .notify(done);
            });
        });
    });

    it('should NOT change pass if token is invalid', (done) => {
      UserBusiness.createUser(GOOD_USER)
        .then((createdUser) => {
          const promise = UserBusiness.resetPassword(createdUser.email, 'newPas$W0rD', 'invalidToken');
          expect(promise).to.be.rejected
            .and.eventually.have.property('message', ERR_INVALID_TOKEN)
            .notify(done);
        });
    });
  });

  describe('change passwords', () => {
    beforeEach(() => User.remove({}));

    it('should change user password if it meet the requirements', async () => {
      const createdUser = await UserBusiness.createUser(GOOD_USER);
      const updatedUser = await UserBusiness.changePassword(createdUser.email, NEW_GOOD_PASSWORD);
      expect(updatedUser.password).to.be.equal(NEW_GOOD_PASSWORD);
    });

    it('should NOT change user password if it DOES NOT meet the requirements', async () => {
      try {
        const createdUser = await UserBusiness.createUser(GOOD_USER);
        await UserBusiness.changePassword(createdUser.email, BAD_PASS);
        expect(false).to.be.true;
      } catch (err) {
        expect(err).to.have.property('message', ERR_INVALID_PASSWORD);
      }
    });
  });
});
