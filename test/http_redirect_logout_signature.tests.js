var expect      = require('chai').expect;
var url         = require('url');
var DOMParser   = require('xmldom').DOMParser;
var fs          = require('fs');
var path        = require('path');
var samlpLogout = require('../');

var select = require('xml-crypto').xpath;
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('HTTP Redirect Binding', function () {
  describe('samlp logout signature', function () {
    var parsedUrl, xml, SAMLRequest;

    before(function (done) {
      var logout = samlpLogout({
        issuer: 'http://example.org',
        identityProviderUrl: 'http://myadfs.com',
        cert: credentials.cert,
        key:  credentials.key
      });

      logout({
        samlNameID: '112233',
        samlSessionIndex: '554433'
      }, {
        redirect: function (location) {
          parsedUrl = url.parse(location, true);
          xml = new Buffer(parsedUrl.query.SAMLRequest, 'base64').toString();
          SAMLRequest = new DOMParser().parseFromString(xml);
          done();
        }
      });
    });

    it('should be valid', function () {
      var signature = select(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
      var sig = new SignedXml();

      sig.keyInfoProvider = new FileKeyInfo(path.join(__dirname, 'fixture', 'samlp.test-cert.pem'));
      sig.loadSignature(signature.toString());
      sig.checkSignature(xml);

      expect(sig.validationErrors).to.be.empty;
    });
  });
});
