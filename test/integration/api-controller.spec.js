const request = require('supertest');
const { assert } = require('chai');
const app = require('../../app');

describe('[integration][/api]', () => {
  it('should return ping-pong', (done) => {
    setTimeout(() => {
      request(app)
        .get('/api')
        .expect(200)
        .end((err, res) => {
          assert.isNull(err);
          assert.deepEqual(JSON.parse(res.text), ({ ping: 'pong' }));
          done();
        });
    }, 200);
  });
});
