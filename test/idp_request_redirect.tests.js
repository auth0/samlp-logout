var expect      = require('chai').expect;
var fs          = require('fs');
var path        = require('path');
var util        = require('util');
var DOMParser   = require('xmldom').DOMParser;
var qs          = require('querystring');
var zlib        = require('zlib');
var url         = require('url');
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

describe('IdP Initiated - SAMLRequest - HTTP Redirect Binding', function () {
  describe('signed request', function () {
    var deflateAndBase64AndSign = function (params, customCreds) {
      if (!params.RelayState) {
        delete params.RelayState;
      }

      params.SigAlg = params.SigAlg || 'http://www.w3.org/2000/09/xmldsig#rsa-sha256';
      params.SAMLRequest = zlib.deflateRawSync(new Buffer(params.SAMLRequest)).toString('base64');

      var query = {
        SAMLRequest: params.SAMLRequest,
        SigAlg: params.SigAlg,
        Signature: signers.sign({
          key: customCreds ? customCreds.key : credentials.key,
          signatureAlgorithm: 'RSA-SHA256'
        }, qs.stringify(params))
      };

      if (params.RelayState) {
        query.RelayState = params.RelayState;
      }

      return query;
    };

    var logout = samlpLogout({
      issuer: 'http://example.org',
      identityProviderUrl: 'http://myadfs.com?a=b',
      cert: credentials.cert,
      key: credentials.key,
      identityProviderSigningCert: credentials.cert, // only for testing purposes
      deflate: true,
      validSessionIndex: function (logoutRequest) {
        return logoutRequest.sessionIndex === 'abc' && logoutRequest.nameId === 'john@acme.com';
      }
    });

    describe('when request is invalid', function () {
      it('should return error if request has expired', function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, '1983-05-17T20:32:16.835Z', 'john@acme.com', 'abc')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('LogoutRequest has expired');
          done();
        });
      });

      it('should return error if request has invalid signature', function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', 'abc')
          }, credentials2)
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.match(/^invalid signature: the signature value .+ is incorrect$/);
          done();
        });
      });

      it('should return error if SessionIndex is missing', function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', '')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing SessionIndex');
          done();
        });
      });

      it('should return error if NameID is missing', function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, new Date().toISOString(), '', 'abc')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing NameID');
          done();
        });
      });

      it('should return error if SessionIndex is invalid', function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', 'invalid')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Invalid SessionIndex/NameID');
          done();
        });
      });
    });

    describe('when request is valid', function () {
      var redirect, RelayState, SAMLResponse, SAMLResponseOriginal, SigAlg, Signature;

      before(function (done) {
        var req = {
          query: deflateAndBase64AndSign({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', 'abc'),
            RelayState: 'foo'
          })
        };

        var res = {
          redirect: function (redirectUrl) {
            var parsedUrl = url.parse(redirectUrl, true);
            redirect = parsedUrl.protocol + '//' + parsedUrl.host + parsedUrl.pathname;

            SAMLResponseOriginal = parsedUrl.query.SAMLResponse;
            SAMLResponse = new DOMParser().parseFromString(zlib.inflateRawSync(new Buffer(SAMLResponseOriginal, 'base64')).toString());
            RelayState = parsedUrl.query.RelayState;
            SigAlg = parsedUrl.query.SigAlg;
            Signature = parsedUrl.query.Signature;
            done();
          }
        };

        logout(req, res);
      });

      it('should redirect to idp endpoint', function () {
        expect(redirect)
          .to.equal('http://myadfs.com/');
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo');
      });

      it('should include SigAlg', function () {
        expect(SigAlg)
          .to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
      });

      it('should include Signature', function () {
        expect(Signature)
          .to.be.ok;
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

      it('should contain a valid signature', function () {
        var signedContent = {
          SAMLResponse: SAMLResponseOriginal,
          RelayState: RelayState,
          SigAlg: SigAlg
        };

        expect(signers.isValidContentAndSignature(qs.stringify(signedContent), Signature, {
          identityProviderSigningCert: credentials.cert,
          signatureAlgorithm: SigAlg
        })).to.be.true;
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

  describe('unsigned request', function () {
    var deflateAndBase64 = function (params) {
      params.SAMLRequest = zlib.deflateRawSync(new Buffer(params.SAMLRequest)).toString('base64');
      return params;
    };

    var logout = samlpLogout({
      issuer: 'http://example.org',
      identityProviderUrl: 'http://myadfs.com?a=b',
      cert: credentials.cert,
      key: credentials.key,
      identityProviderSigningCert: credentials.cert, // only for testing purposes
      deflate: true,
      validSessionIndex: function (logoutRequest) {
        return logoutRequest.sessionIndex === 'abc' && logoutRequest.nameId === 'john@acme.com';
      }
    });

    describe('when request is invalid', function () {
      it('should return error if request has expired', function (done) {
        var req = {
          query: deflateAndBase64({
            SAMLRequest: util.format(template, '1983-05-17T20:32:16.835Z', 'john@acme.com', 'abc')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('LogoutRequest has expired');
          done();
        });
      });

      it('should return error if SessionIndex is missing', function (done) {
        var req = {
          query: deflateAndBase64({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', '')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing SessionIndex');
          done();
        });
      });

      it('should return error if NameID is missing', function (done) {
        var req = {
          query: deflateAndBase64({
            SAMLRequest: util.format(template, new Date().toISOString(), '', 'abc')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Missing NameID');
          done();
        });
      });

      it('should return error if SessionIndex is invalid', function (done) {
        var req = {
          query: deflateAndBase64({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', 'invalid')
          })
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('Invalid SessionIndex/NameID');
          done();
        });
      });
    });

    describe('when request is valid', function () {
      var redirect, RelayState, SAMLResponse, SAMLResponseOriginal, SigAlg, Signature;

      before(function (done) {
        var req = {
          query: deflateAndBase64({
            SAMLRequest: util.format(template, new Date().toISOString(), 'john@acme.com', 'abc'),
            RelayState: 'foo'
          })
        };

        var res = {
          redirect: function (redirectUrl) {
            var parsedUrl = url.parse(redirectUrl, true);
            redirect = parsedUrl.protocol + '//' + parsedUrl.host + parsedUrl.pathname;

            SAMLResponseOriginal = parsedUrl.query.SAMLResponse;
            SAMLResponse = new DOMParser().parseFromString(zlib.inflateRawSync(new Buffer(SAMLResponseOriginal, 'base64')).toString());
            RelayState = parsedUrl.query.RelayState;
            SigAlg = parsedUrl.query.SigAlg;
            Signature = parsedUrl.query.Signature;
            done();
          }
        };

        logout(req, res);
      });

      it('should redirect to idp endpoint', function () {
        expect(redirect)
          .to.equal('http://myadfs.com/');
      });

      it('should include RelayState', function () {
        expect(RelayState)
          .to.equal('foo');
      });

      it('should include SigAlg', function () {
        expect(SigAlg)
          .to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
      });

      it('should include Signature', function () {
        expect(Signature)
          .to.be.ok;
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

      it('should contain a valid signature', function () {
        var signedContent = {
          SAMLResponse: SAMLResponseOriginal,
          RelayState: RelayState,
          SigAlg: SigAlg
        };

        expect(signers.isValidContentAndSignature(qs.stringify(signedContent), Signature, {
          identityProviderSigningCert: credentials.cert,
          signatureAlgorithm: SigAlg
        })).to.be.true;
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
