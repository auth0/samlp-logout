var expect      = require('chai').expect;
var url         = require('url');
var DOMParser   = require('xmldom').DOMParser;
var fs          = require('fs');
var path        = require('path');
var xmlCrypto   = require('xml-crypto');
var zlib        = require('zlib');
var crypto      = require('crypto');
var qs          = require('querystring');
var samlpLogout = require('../');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('SAMLRequest - HTTP Redirect Binding', function () {
  describe('with signing request', function () {
    describe('with deflate', function () {
      var parsedUrl, SAMLRequestWithDeflate, SAMLRequest, RelayState, SigAlg, Signature;

      before(function (done) {
        var logout = samlpLogout({
          issuer: 'http://example.org',
          identityProviderUrl: 'http://myadfs.com/ls',
          cert: credentials.cert,
          key:  credentials.key,
          relayState: 'foo=bar',
          deflate: true
        });

        logout({
          samlNameID: '112233',
          samlSessionIndex: '554433'
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
              done();
            });
          }
        });
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo=bar');
      });

      it('should include SigAlg', function () {
        expect(SigAlg)
          .to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
      });

      it('should include a valid Signature', function () {
        var verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(qs.stringify({
          SAMLRequest: SAMLRequestWithDeflate,
          RelayState: RelayState,
          SigAlg: SigAlg
        }));
        
        expect(Signature).to.be.ok;
        expect(verifier.verify(credentials.cert, Signature, 'base64')).to.be.true;
      });

      it('should be a samlp:LogoutRequest doc', function () {
        expect(SAMLRequest.firstChild.nodeName)
          .to.equal('samlp:LogoutRequest');
      });

      it('should contain an ID attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('ID'))
          .to.be.ok;
      });

      it('should contain an IssueInstant attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('IssueInstant'))
          .to.be.ok;
      });

      it('should not contain signature embedded', function () {
        var signature = xmlCrypto.xpath(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
        expect(signature).to.be.undefined;
      });

      it('should contain the issuer element', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
        expect(el.childNodes[0].textContent).to.equal('http://example.org');
      });

      it('should contain the nameid', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID')[0];
        expect(el.childNodes[0].textContent).to.equal('112233');
      });


      it('should contain the sessionindex', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'SessionIndex')[0];
        expect(el.childNodes[0].textContent).to.equal('554433');
      });
    });

    describe('without deflate', function () {
      var parsedUrl, SAMLRequest, RelayState;

      before(function (done) {
        var logout = samlpLogout({
          issuer: 'http://example.org',
          identityProviderUrl: 'http://myadfs.com/ls',
          cert: credentials.cert,
          key:  credentials.key,
          relayState: 'foo=bar'
        });

        logout({
          samlNameID: '112233',
          samlSessionIndex: '554433'
        }, {
          redirect: function (location) {
            parsedUrl = url.parse(location, true);

            expect(parsedUrl.protocol).to.equal('http:');
            expect(parsedUrl.hostname).to.equal('myadfs.com');
            expect(parsedUrl.pathname).to.equal('/ls');

            var xml = new Buffer(parsedUrl.query.SAMLRequest, 'base64').toString();
            SAMLRequest = new DOMParser().parseFromString(xml);
            RelayState = parsedUrl.query.RelayState;
            done();
          }
        });
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo=bar');
      });

      it('should be a samlp:LogoutRequest doc', function () {
        expect(SAMLRequest.firstChild.nodeName)
          .to.equal('samlp:LogoutRequest');
      });

      it('should contain an ID attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('ID'))
          .to.be.ok;
      });

      it('should contain an IssueInstant attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('IssueInstant'))
          .to.be.ok;
      });

      it('should contain signature embedded', function () {
        var signature = xmlCrypto.xpath(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
        var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
        sig.keyInfoProvider = {
          getKeyInfo: function () {
            return "<X509Data></X509Data>";
          },
          getKey: function () {
            return credentials.cert;
          }
        };

        sig.loadSignature(signature.toString());
        expect(sig.checkSignature(SAMLRequest.toString())).to.be.true;
        expect(sig.validationErrors).to.be.empty;
        
        expect(SAMLRequest.documentElement
              .getElementsByTagName('SignatureMethod')[0]
              .getAttribute('Algorithm')).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

        expect(SAMLRequest.documentElement
              .getElementsByTagName('DigestMethod')[0]
              .getAttribute('Algorithm')).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
      });

      it('should contain the issuer element', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
        expect(el.childNodes[0].textContent).to.equal('http://example.org');
      });

      it('should contain the nameid', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID')[0];
        expect(el.childNodes[0].textContent).to.equal('112233');
      });


      it('should contain the sessionindex', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'SessionIndex')[0];
        expect(el.childNodes[0].textContent).to.equal('554433');
      });
    });
  });

  describe('without signing request', function () {
    describe('with deflate', function () {
      var parsedUrl, SAMLRequest, RelayState;

      before(function (done) {
        var logout = samlpLogout({
          issuer: 'http://example.org',
          identityProviderUrl: 'http://myadfs.com/ls',
          relayState: 'foo=bar',
          deflate: true
        });

        logout({
          samlNameID: '112233',
          samlSessionIndex: '554433'
        }, {
          redirect: function (location) {
            parsedUrl = url.parse(location, true);

            expect(parsedUrl.protocol).to.equal('http:');
            expect(parsedUrl.hostname).to.equal('myadfs.com');
            expect(parsedUrl.pathname).to.equal('/ls');

            zlib.inflateRaw(new Buffer(parsedUrl.query.SAMLRequest, 'base64'), function (err, buffer) {
              if (err) return done(err);

              SAMLRequest = new DOMParser().parseFromString(buffer.toString());
              RelayState = parsedUrl.query.RelayState;
              done();
            });
          }
        });
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo=bar');
      });

      it('should be a samlp:LogoutRequest doc', function () {
        expect(SAMLRequest.firstChild.nodeName)
          .to.equal('samlp:LogoutRequest');
      });

      it('should contain an ID attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('ID'))
          .to.be.ok;
      });

      it('should contain an IssueInstant attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('IssueInstant'))
          .to.be.ok;
      });

      it('should not contain signature embedded', function () {
        var signature = xmlCrypto.xpath(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
        expect(signature).to.be.undefined;
      });

      it('should contain the issuer element', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
        expect(el.childNodes[0].textContent).to.equal('http://example.org');
      });

      it('should contain the nameid', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID')[0];
        expect(el.childNodes[0].textContent).to.equal('112233');
      });


      it('should contain the sessionindex', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'SessionIndex')[0];
        expect(el.childNodes[0].textContent).to.equal('554433');
      });
    });

    describe('without deflate', function () {
      var parsedUrl, SAMLRequest, RelayState;

      before(function (done) {
        var logout = samlpLogout({
          issuer: 'http://example.org',
          identityProviderUrl: 'http://myadfs.com/ls',
          relayState: 'foo=bar'
        });

        logout({
          samlNameID: '112233',
          samlSessionIndex: '554433'
        }, {
          redirect: function (location) {
            parsedUrl = url.parse(location, true);

            expect(parsedUrl.protocol).to.equal('http:');
            expect(parsedUrl.hostname).to.equal('myadfs.com');
            expect(parsedUrl.pathname).to.equal('/ls');

            var xml = new Buffer(parsedUrl.query.SAMLRequest, 'base64').toString();
            SAMLRequest = new DOMParser().parseFromString(xml);
            RelayState = parsedUrl.query.RelayState;
            done();
          }
        });
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo=bar');
      });

      it('should be a samlp:LogoutRequest doc', function () {
        expect(SAMLRequest.firstChild.nodeName)
          .to.equal('samlp:LogoutRequest');
      });

      it('should contain an ID attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('ID'))
          .to.be.ok;
      });

      it('should contain an IssueInstant attribute', function () {
        expect(SAMLRequest.firstChild.hasAttribute('IssueInstant'))
          .to.be.ok;
      });

      it('should not contain signature embedded', function () {
        var signature = xmlCrypto.xpath(SAMLRequest, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
        expect(signature).to.be.undefined;
      });

      it('should contain the issuer element', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
        expect(el.childNodes[0].textContent).to.equal('http://example.org');
      });

      it('should contain the nameid', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID')[0];
        expect(el.childNodes[0].textContent).to.equal('112233');
      });


      it('should contain the sessionindex', function () {
        var el = SAMLRequest.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'SessionIndex')[0];
        expect(el.childNodes[0].textContent).to.equal('554433');
      });
    });
  });
});
