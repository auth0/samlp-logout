var expect      = require('chai').expect;
var samlpLogout = require('../');
var DOMParser   = require('xmldom').DOMParser;
var cheerio     = require('cheerio');
var fs          = require('fs');
var path        = require('path');

var select = require('xml-crypto').xpath;
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('HTTP POST Binding', function () {
  describe('samlp logout signature', function () {
    var SAMLRequest, SAMLRequestBase64;

    before(function (done) {
      var logout = samlpLogout({
        protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        issuer: 'http://example.org',
        identityProviderUrl: 'http://myadfs.com',
        cert: credentials.cert,
        key:  credentials.key
      });

      logout({
        samlNameID: '112233',
        samlSessionIndex: '554433'
      }, {
        send: function (html) {
          var $ = cheerio.load(html);

          var samlRequestInput = $('form input[name="SAMLRequest"]').val();
          SAMLRequestBase64 = new Buffer(samlRequestInput, 'base64').toString();
          SAMLRequest = new DOMParser().parseFromString(SAMLRequestBase64);
          done();
        },
        set: function (key, value) {
          expect(key).to.equal('Content-Type');
          expect(value).to.equal('text/html');
        }
      });
    });

    it('should be valid', function () {
      var signature = select(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
      var sig = new SignedXml();

      sig.keyInfoProvider = new FileKeyInfo(path.join(__dirname, 'fixture', 'samlp.test-cert.pem'));
      sig.loadSignature(signature.toString());
      sig.checkSignature(SAMLRequestBase64);

      expect(sig.validationErrors).to.be.empty;
    });
  });
});
