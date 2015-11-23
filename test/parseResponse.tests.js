var expect      = require('chai').expect;
var samlpLogout = require('../');

describe('parse response', function () {
  describe('SAMLResponse with only StatusCode element', function () {
    var example_response = '7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ/ff/z9cZmQBbPbOStrJniGAqsgfP358Hz8iHjfZolw9el5dVOv2Vd6sqmWTp2dPP/vo988PHmTn2cOD7Qc7+XR7f7K7u32Qn8+2p9P79z89uD95cO/BvY/Sn8zrpqiWn320N975KD1rmnV+tmzabNnSRzu7+9s7D7Z3Pn2z+/DR7oNHu5+O793f+amP0qd50xbLrOU35227ah7dvVtWF8VyZ7y4ztbtfGc8rRb4iPD6KD0BWgC5rpePqqwpmkfLbJE3j9rpo9fHXzx/RL0/mkqjR+tls8qnxXmRzwijpRnVm4oGtXPwYHeSPfj0QX7/0/39vXvT6afU6N2iXDaPmBSbu1jVVVtNq/Kjo8c81Fpe3fxS1jR5jaF+dGSG2tL4t7PZeTO2Y318VyAe6ZS8brN23YR/nVSzPP3JrFznm3tsuPWj1+vpNG+aj9K7R4/vhlD1z3Dej/4f';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(1);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
    });
  });

  describe('SAMLResponse with StatusCode and StatusMessage elements', function () {
    var example_response = 'fZFPb9swDMXvA/YdBN3jf3GSWotTDAsGBFgva9ZDL4MmE7Y2m3REOev66afYzRBkaK+P5CN/j+vbp64VR3BsCUuZRokUgIYqi3Upv+0/z27k7eb9uzXrrs169RW4J2QQYQxZTWopB4eKNFtWqDtg5Y26/3j3RWVRonpHngy1UmyBvUXtx1WN9z2rODaEnpgiPfgmiQx1cUs1DV6K3baUu23aoH5edodfZIdDkSU/8blaLf8UqyY/HptatxX+NrVJLXPRNTUYCpN4vnNPpfy+TFbJIs+rVT43C50n8x9ZHpqYB9ghe42+lFmSLmZpOsvm+3Sh5rnKiigpikcpHs7hBBgZohBCTGmo0cFdRvF2EpoZ3Ilebq7pT9yjQ9yB15X2eh1fLrnc26t7r/3Ak/af/IkqEA+6HeDta3jsDh89DOEv4KSIX3G8A2Zdw+bkxrZGa7RX4By5ifpkFloCmEJCeLLBDv0HsW9AvBREZSuB5MVYfWG79p8Y42vIf8r5qZu/';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(2);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
      expect(parsed.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
    });
  });

  describe('SAMLResponse with StatusCode and StatusDetail elements', function () {
    var example_response = 'fZFNi9swEIbvhf4HoXss2XGStYizlA0LgfbSTffQS5nKQlZrS45nlG3211d1miVs6d7Ey3w8emZ9+6vv2NGM6IKveZ5JzozXoXHe1vzL/n52w28379+tEfquGNRng0PwaFhq86jOac3j6FUAdKg89AYVafXw4dNHVWRSDWOgoEPH2dYgOQ80rWqJBlRCUDujlGcmZhCplZkOveiCDZE4221rvtvmrYfnZX/4GVw8VIX84Z+b1fJUrdryeGwtdI1/0lbnDrHqW2t0SJ3+groPNf+2lCu5KMtmVc71Ako5/16UqQgxmp1HAk81L2S+mOX5rJjv84Wal6qoMllVXzl7vPhJ/+HJBmPsLERNE8ZrG2/LAEQz/hHANxcBw2iSoiZDZ73TQJMAC2Se4CRoPFnbgkfI0IhpgegNQQMEa3HNcI01qAcCinjO/onvQmPYI3TRvA2LU3W6+SGmC5mRi/8M3CYi120w9IY10/sv26uCM6J4zfiSXE62+Q0=';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(2);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
      expect(parsed.detail).to.equal('some detail');
    });
  });

  describe('SAMLResponse with StatusCode, StatusMessage and StatusDetail elements', function () {
    var example_response = 'fZJPj9MwEMXvSHwHy/fmX9N2Y5quEBVSJfbClj1wQUMySgyJnXom3e1+etykQVVBe7OeZ57n/cbr+5e2EUd0pK3JZRxEUqApbKlNlctv+8+zO3m/ef9uTdA2Sae+InXWEArfZkiNai57Z5QF0qQMtEiKC/X48eGLSoJIdc6yLWwjxRaJtQEenqqZO1JhyPWMvR5gH0DPdRQUtg0bW9mepdhtc7nbxrWB12V7+G11f8iS6Jd5LVfLU7aq0+OxrqApzXNRFbEmytq6wsL6TjONure5/LGMVtEiTctVOi8WkEbzn0nqi4h63BliMJzLJIoXszieJfN9vFDzVCVZEGXZdymeJj4+j/Q0hBAjEDU4uGsab8MAInRnAHIzAegcekRlQLoyugAeAFTA+AynkN2pqmowBAFhODwQtshQAsM6vJ7heqxOPTJwT6P2j/zJliieoOnx7WFpqPY7P/R+Q+hkePUTRqsHJIIKN2ebKYBC56wbaZxdfIkPrIw1+KK9j+EPYl+juFyIUpfCWBbD7SXUrf//g2w9Cd1syLYoyuF8034pGNGEt2z+KtNX2fwB';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(3);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
      expect(parsed.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
      expect(parsed.detail).to.equal('some detail');
    });
  });

  describe('SAMLResponse with StatusCode, sub-StatusCode and StatusMessage elements', function () {
    var example_response = 'rZJBj9MwEIXvSPwHy/cmTpq2xDRdISqkSuyFLXvggowzSgzJTJpxyrK/HjehS9UVe+I6nnlv3jde3zy0jThCz46wkEmkpAC0VDqsCvl5/2H2Rt5sXr9as2mbtNOfgDtCBhHGkPVULeTQoybDjjWaFlh7q+/e3X7UaaR015MnS40UW2Dv0PjRqva+Yx3HltATU2QGX6vIUhs3VNHgpdhtC7nbJjWax2V7+EFuOOSp+o6P5Wr5K1/V2fFYV6Yp8aetbOKY87auwFKYxPOeeyrk16VaqUWWlatsbhcmU/NvaRaamAfYIXuDvpCpShazJJml832y0PNMp3mk8vyLFPdnOCGMDCiEEBMNPSr0lyheJmGYoT+ll5vr9Kfco0Lcgjel8WYdX5pc+nb6zhs/8FR7Vn5PJYh70wzw8jY8doeLHoZwF+jlk95/ktwCOiiliP8uGj+T/UeIW2A2FWxObuwqdNZ4DX1P/QT6ZBZaAkuNhPDgQgL0b8W+BvHnQZSuFEhejK9X1mf9CWt8zfWpcv5Hm98=';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(3);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
      expect(parsed.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
      expect(parsed.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
    });
  });

  describe('SAMLResponse with StatusCode, sub-StatusCode, StatusMessage and StatusDetail elements', function () {
    var example_response = 'rZJPb9swDMXvA/YdBN3jf3GSWYtdDAsGBFgva9bDLoVmEbY2m3JEOW366afYdRekXU+7GRTJ9/h7Xl89tA07gCVtMOdxEHEGWBqlscr5992X2Qd+Vbx/tybZNkknvgF1BgmYH0MSYzXnvUVhJGkSKFsg4Upx8+n6q0iCSHTWOFOahrMNkNMo3SBVO9eRCENXz5yvB9AHsnd1FJSmDRtTmd5xtt3kfLuJa5SPy3b/2+h+nyXRL3xUq+UxW9Xp4VBXslF4X1ZlrImytq6gNH4SJ6s7k/O7ZbSKFmmqVum8XMg0mv9MUt9E1MMWyUl0OU+ieDGL41ky38ULMU9FkgVRlv3g7Hbi4+/hngZjbAQihg32nMbbMCQR2BMAXkwAOgsekQpIV6hL6QYAlXRwL4+hs8eqqiWSDAjCQSBswUklnVyH5x7ObXXixknX01h7Uf5sFLBb2fTwtlkaun3m+94nBJY/7/tPKzeAGhRn4V+j4Yu1/zjiGohkBcVJbUInwFpjxxxOYr7FoxZoEB60vwDdR7argT09MKUVQ+PY8HohPe1/XX3jM9BNQaYFpobvi/GnhjGU8DKV58r0kxZ/AA==';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(4);
      expect(parsed.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
      expect(parsed.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
      expect(parsed.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
      expect(parsed.detail).to.equal('some detail');
    });
  });

  describe('SAMLResponse without Status element', function () {
    var example_response = 'fdFNT8MwDAbgOxL/Icq9bfqxlUbrJqQJaRJcYHDggkwapYU26Wp3Y/x6QqdJEweuVmy/ebxYfXUt2+sBG2dLHoeCM22VqxprSv68vQtu+Gp5fbVA6Nqkl48ae2dRM99mUZ6qJR8HKx1gg9JCp1GSkk+3D/cyCYXsB0dOuZaztUZqLNC0qibqUUYR1QH5eqjHEEaqRahcF7XOuJE426xLvlnHtYXvebf7dM24KxLxYb+rfH4s8jrb72sDbWUPyqi4QSy62mjlfKc9R926kr/NRS5mWVblWapmkIn0Pcn8I8RRbywSWCp5IuJZEMdBkm7jmUwzmRShKIpXzl7OPv4/3Gswxk4gcpowXGr8jwGIevgF4MszQD9oT1SF2BjbKKAJwADpAxwjGo7G1GARQtTRtCDqNEEFBIvoMsMplr9U9OdUyx8=';
    var parsed;

    before(function (done) {
      samlpLogout.parseResponse(example_response, function (err, response) {
        if (err) return done(err);
        parsed = response;
        done();
      });
    });

    it('should return parsed response', function () {
      expect(parsed).to.be.ok;
      expect(Object.keys(parsed)).to.have.length(0);
    });
  });
});
