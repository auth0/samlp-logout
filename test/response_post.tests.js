var expect      = require('chai').expect;
var fs          = require('fs');
var path        = require('path');
var util        = require('util');
var signers     = require('../lib/signers');
var samlpLogout = require('../');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

var template = '<samlp:LogoutResponse ID="_e87afa98-70ec-4b11-8efd-cc55685b7373" Version="2.0" IssueInstant="2014-07-06T19:17:16.350Z" Destination="https://login0.myauth0.com/logout" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_0871ba767e564423cc6d" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://test-adfs.auth0.com</Issuer>%s</samlp:LogoutResponse>';

describe('SAMLResponse - HTTP POST Binding', function () {
  describe('signed response', function () {
    var signAndBase64 = function (SAMLResponse) {
      var signedXml = signers.signXml({
        cert: credentials.cert,
        key: credentials.key,
        reference: "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']"
      }, SAMLResponse);

      return new Buffer(signedXml).toString('base64');
    };
    
    var logout = samlpLogout({
      cert: credentials.cert,
      key: credentials.key,
      identityProviderSigningCert: credentials.cert, // only for testing purposes
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    });

    describe('when status is valid', function () {
      it('should call next and set parsed SAMLResponse', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.undefined;
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
          done();
        });
      });

      it('should call next and set parsed SAMLResponse for a PartialLogout response', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout" /></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.undefined;
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:PartialLogout');
          done();
        });
      });
    });

    describe('when status is invalid', function () {
      it('should call next with error and set parsed SAMLResponse with only StatusCode element', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('unexpected SAMLP Logout response (urn:oasis:names:tc:SAML:2.0:status:Requester)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode and StatusMessage elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(2);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('some detail');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(2);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, StatusMessage and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist (some detail)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(3);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, sub-StatusCode and StatusMessage elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(3);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, sub-StatusCode, StatusMessage and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist (some detail)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(4);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse without Status element', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: signAndBase64(util.format(template, '')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('unexpected SAMLP Logout response (undefined)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(0);
          done();
        });
      });
    });
  });

  describe('unsigned response', function () {
    var base64 = function (SAMLResponse) {
      return new Buffer(SAMLResponse).toString('base64');
    };
    
    var logout = samlpLogout({
      cert: credentials.cert,
      key: credentials.key,
      identityProviderSigningCert: credentials.cert, // only for testing purposes
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    });

    describe('when status is valid', function () {
      it('should call next and set parsed SAMLResponse', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.undefined;
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
          done();
        });
      });

      it('should call next and set parsed SAMLResponse for a PartialLogout response', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout" /></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.undefined;
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:PartialLogout');
          done();
        });
      });
    });

    describe('when status is invalid', function () {
      it('should call next with error and set parsed SAMLResponse with only StatusCode element', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('unexpected SAMLP Logout response (urn:oasis:names:tc:SAML:2.0:status:Requester)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(1);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode and StatusMessage elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(2);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('some detail');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(2);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, StatusMessage and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist (some detail)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(3);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, sub-StatusCode and StatusMessage elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(3);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse with StatusCode, sub-StatusCode, StatusMessage and StatusDetail elements', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode><samlp:StatusMessage>urn:signicat:error:saml2.0:session:nonexistent; The session did not exist</samlp:StatusMessage><samlp:StatusDetail>some detail</samlp:StatusDetail></samlp:Status>')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist (some detail)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(4);
          expect(req.parsedSAMLResponse.status).to.equal('urn:oasis:names:tc:SAML:2.0:status:Requester');
          expect(req.parsedSAMLResponse.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
          expect(req.parsedSAMLResponse.message).to.equal('urn:signicat:error:saml2.0:session:nonexistent; The session did not exist');
          expect(req.parsedSAMLResponse.detail).to.equal('some detail');
          done();
        });
      });

      it('should call next with error and set parsed SAMLResponse without Status element', function (done) {
        var req = {
          query: {},
          body: { SAMLResponse: base64(util.format(template, '')) }
        };

        logout(req, {}, function (err) {
          expect(err).to.be.ok;
          expect(err.message).to.equal('unexpected SAMLP Logout response (undefined)');
          expect(req.parsedSAMLResponse).to.be.ok;
          expect(Object.keys(req.parsedSAMLResponse)).to.have.length(0);
          done();
        });
      });
    });
  });
});
