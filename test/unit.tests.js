const expect      = require('chai').expect;
const url         = require('url');
const DOMParser   = require('xmldom').DOMParser;
const fs          = require('fs');
const path        = require('path');
const zlib        = require('zlib');
const samlpLogout = require('..');

const credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('samlpLogout', function () {
  describe('with a malformed key', function () {
    var parsedUrl;
    it('should invoke the callback with an error', function (done) {
      const logout = samlpLogout({
        issuer: 'http://example.org',
        identityProviderUrl: 'http://myadfs.com/ls',
        cert: credentials.cert,
        key:  'badly-formatted-key',
        relayState: 'foo=bar',
        deflate: true,
        identityProviderSigningCert: credentials.cert // only for testing purposes
      });

      logout({
        samlNameID: '112233',
        samlSessionIndex: '554433',
        query: {},
        body: {}
      }, {
        redirect: function (location) {
          parsedUrl = url.parse(location, true);

          expect(parsedUrl.protocol).to.equal('http:');
          expect(parsedUrl.hostname).to.equal('myadfs.com');
          expect(parsedUrl.pathname).to.equal('/ls');

          zlib.inflateRaw(new Buffer(parsedUrl.query.SAMLRequest, 'base64'), function (err, buffer) {
            if (err) return done(err);

            SAMLRequestWithDeflate = parsedUrl.query.SAMLRequest;
            SAMLRequest = new DOMParser().parseFromString(buffer.toString());
            RelayState = parsedUrl.query.RelayState;
            SigAlg = parsedUrl.query.SigAlg;
            Signature = parsedUrl.query.Signature;
          });
        }
      }, (err) => {
        expect(err.message).to.equal('error:0909006C:PEM routines:get_name:no start line')
        done();
      });
    });
  });
});
