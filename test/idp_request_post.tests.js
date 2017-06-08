var expect      = require('chai').expect;
var fs          = require('fs');
var path        = require('path');
var util        = require('util');
var DOMParser   = require('xmldom').DOMParser;
var cheerio     = require('cheerio');
var xmlCrypto   = require('xml-crypto');
var signers     = require('../lib/signers');
var samlpLogout = require('../');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

var credentials2 = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert2.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert2.key')),
};

const template = '<urn:LogoutRequest xmlns:urn="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="111" IssueInstant="2016-05-17T20:27:16.833Z" NotOnOrAfter="%s" Destination="https://acme.auth0.com/v2/logout?returnTo=https://www.acme.com"><urn1:Issuer xmlns:urn1="urn:oasis:names:tc:SAML:2.0:assertion">https://saml_provider.com</urn1:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">%s</saml:NameID><urn:SessionIndex>%s</urn:SessionIndex></urn:LogoutRequest>';

describe('IdP Initiated - SAMLRequest - HTTP POST Binding', function () {
  describe('signed request', function () {
    var signAndBase64 = function (SAMLResponse, customCreds) {
      var signedXml = signers.signXml({
        cert: customCreds ? customCreds.cert : credentials.cert,
        key: customCreds ? customCreds.key : credentials.key,
        reference: "//*[local-name(.)='LogoutRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']"
      }, SAMLResponse);

      return new Buffer(signedXml).toString('base64');
    };

    var base64 = function (SAMLResponse) {
      return new Buffer(SAMLResponse).toString('base64');
    };

    var logout = samlpLogout({
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      issuer: 'http://example.org',
      identityProviderUrl: 'http://myadfs.com?a=b',
      cert: credentials.cert,
      key: credentials.key,
      identityProviderSigningCert: credentials.cert, // only for testing purposes
      validSessionIndex: function (logoutRequest) {
        return logoutRequest.sessionIndex === 'abc' && logoutRequest.nameId === 'john@acme.com';
      }
    });

    describe('when request is invalid', function () {
      it('should return error if request has expired', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(template, '1983-05-17T20:32:16.835Z', 'john@acme.com', 'abc'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('LogoutRequest has expired');
          done();
        });
      });

      it('should return error if request has invalid signature', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(template, new Date().toISOString(), 'john@acme.com', 'abc'), credentials2)
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.match(/^invalid signature: the signature value .+ is incorrect$/);
          done();
        });
      });

      it('should return error if request is not signed', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: base64(util.format(template, new Date().toISOString(), 'john@acme.com', 'abc'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('LogoutRequest message MUST be signed when using an asynchronous binding (POST or Redirect)');
          done();
        });
      });

      it('should return error if SessionIndex is missing', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(template, new Date().toISOString(), 'john@acme.com', ''))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing SessionIndex');
          done();
        });
      });

      it('should return error if NameID is missing', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(template, new Date().toISOString(), '', 'abc'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing NameID');
          done();
        });
      });

      it('should return error if SessionIndex is invalid', function (done) {
        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(template, new Date().toISOString(), 'john@acme.com', 'invalid'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Invalid SessionIndex/NameID');
          done();
        });
      });

      it('should return missing SessionIndex if element was not found', function (done) {
        const temp = '<urn:LogoutRequest xmlns:urn="urn:oasis:names:tc:SAML:2.0:protocol"><urn1:Issuer xmlns:urn1="urn:oasis:names:tc:SAML:2.0:assertion">https://saml_provider.com</urn1:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">%s</saml:NameID></urn:LogoutRequest>';

        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(temp, new Date().toISOString(), 'john@acme.com'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing SessionIndex');
          done();
        });
      });

      it('should return missing NameID if element was not found', function (done) {
        const temp = '<urn:LogoutRequest xmlns:urn="urn:oasis:names:tc:SAML:2.0:protocol"><urn1:Issuer xmlns:urn1="urn:oasis:names:tc:SAML:2.0:assertion">https://saml_provider.com</urn1:Issuer><urn:SessionIndex>session</urn:SessionIndex></urn:LogoutRequest>';

        var req = {
          query: {},
          body: {
            SAMLRequest: signAndBase64(util.format(temp, new Date().toISOString(), 'john@acme.com'))
          }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing NameID');
          done();
        });
      });
    });

    describe('when request is valid', function () {
      var callback, RelayState, SAMLResponse, contentType;

      before(function (done) {
        var req = {
          query: {},
          body: {
            RelayState: 'foo',
            SAMLRequest: signAndBase64(util.format(template, new Date().toISOString(), 'john@acme.com', 'abc'))
          }
        };

        var res = {
          send: function (html) {
            var $ = cheerio.load(html);
            var samlResponseInput = $('form input[name="SAMLResponse"]').val();
            var samlResponseStr = new Buffer(samlResponseInput, 'base64').toString();

            SAMLResponse = new DOMParser().parseFromString(samlResponseStr);
            RelayState = $('form input[name="RelayState"]').val();
            callback = $('form').attr('action');
            done();
          },
          set: function (key, value) {
            if (key === 'Content-Type') {
              contentType = value;
            }
          }
        };

        logout(req, res);
      });

      it('should set Content-Type', function () {
        expect(contentType)
          .to.equal('text/html');
      });

      it('should include callback', function () {
        expect(callback)
          .to.equal('http://myadfs.com?a=b');
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo');
      });

      it('should be a samlp:LogoutResponse doc', function () {
        expect(SAMLResponse.firstChild.nodeName)
          .to.equal('samlp:LogoutResponse');
      });

      it('should contain an ID attribute', function () {
        expect(SAMLResponse.firstChild.hasAttribute('ID'))
          .to.be.ok;
      });

      it('should contain an IssueInstant attribute', function () {
        expect(SAMLResponse.firstChild.hasAttribute('IssueInstant'))
          .to.be.ok;
      });

      it('should contain a Destination attribute', function () {
        expect(SAMLResponse.firstChild.getAttribute('Destination'))
          .to.be.equal('http://myadfs.com?a=b');
      });

      it('should contain an InResponseTo attribute', function () {
        expect(SAMLResponse.firstChild.getAttribute('InResponseTo'))
          .to.be.equal('111'); // SAMLRequest's ID
      });

      it('should contain a valid signature embedded', function () {
        var signature = xmlCrypto.xpath(SAMLResponse, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
        var sig = new xmlCrypto.SignedXml();
        sig.keyInfoProvider = {
          getKeyInfo: function () {
            return '<X509Data></X509Data>';
          },
          getKey: function () {
            return credentials.cert;
          }
        };

        sig.loadSignature(signature.toString());
        expect(sig.checkSignature(SAMLResponse.toString())).to.be.true;
        expect(sig.validationErrors).to.be.empty;

        expect(SAMLResponse.documentElement
              .getElementsByTagName('SignatureMethod')[0]
              .getAttribute('Algorithm')).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

        expect(SAMLResponse.documentElement
              .getElementsByTagName('DigestMethod')[0]
              .getAttribute('Algorithm')).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
      });

      it('should contain the issuer element', function () {
        var el = SAMLResponse.childNodes[0]
                            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
        expect(el.childNodes[0].textContent).to.equal('http://example.org');
      });

      it('should contain the status code', function () {
        expect(SAMLResponse.documentElement
          .getElementsByTagName('samlp:Status')[0]
          .getElementsByTagName('samlp:StatusCode')[0]
          .getAttribute('Value')).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
      });
    });
  });
});
