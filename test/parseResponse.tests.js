var samlpLogout = require('../');
var expect = require('chai').expect;

describe('samlp logout signature', function () {
  var example_reponse = '7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ/ff/z9cZmQBbPbOStrJniGAqsgfP358Hz8iHjfZolw9el5dVOv2Vd6sqmWTp2dPP/vo988PHmTn2cOD7Qc7+XR7f7K7u32Qn8+2p9P79z89uD95cO/BvY/Sn8zrpqiWn320N975KD1rmnV+tmzabNnSRzu7+9s7D7Z3Pn2z+/DR7oNHu5+O793f+amP0qd50xbLrOU35227ah7dvVtWF8VyZ7y4ztbtfGc8rRb4iPD6KD0BWgC5rpePqqwpmkfLbJE3j9rpo9fHXzx/RL0/mkqjR+tls8qnxXmRzwijpRnVm4oGtXPwYHeSPfj0QX7/0/39vXvT6afU6N2iXDaPmBSbu1jVVVtNq/Kjo8c81Fpe3fxS1jR5jaF+dGSG2tL4t7PZeTO2Y318VyAe6ZS8brN23YR/nVSzPP3JrFznm3tsuPWj1+vpNG+aj9K7R4/vhlD1z3Dej/4f';
  var parsed;

  before(function (done) {
    samlpLogout.parseResponse(example_reponse, function (err, response) {
      if (err) return done(err);
      parsed = response;
      done();
    });
  });

  it('should return the status', function () {
    expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
  });
});