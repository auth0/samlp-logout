var expect      = require('chai').expect;
var fs          = require('fs');
var path        = require('path');
var DOMParser   = require('xmldom').DOMParser;
var cheerio     = require('cheerio');
var xmlCrypto   = require('xml-crypto');
var samlpLogout = require('../');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('SAMLRequest - HTTP POST Binding', function () {
  describe('with signing request', function () {
    var callback, RelayState, SAMLRequest, contentType;

    before(function (done) {
      var logout = samlpLogout({
        protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        issuer: 'http://example.org',
        identityProviderUrl: 'http://myadfs.com?a=b',
        cert: credentials.cert,
        key: credentials.key,
        relayState: 'foo=bar'
      });

      logout({
        samlNameID: '112233',
        samlSessionIndex: '554433'
      }, {
        send: function (html) {
          var $ = cheerio.load(html);

          callback = $('form').attr('action');
          RelayState = $('form input[name="RelayState"]').val();
          var samlRequestInput = $('form input[name="SAMLRequest"]').val();
          
          var SAMLRequestBase64 = new Buffer(samlRequestInput, 'base64').toString();
          SAMLRequest = new DOMParser().parseFromString(SAMLRequestBase64);
          done();
        },
        set: function (key, value) {
          if (key === 'Content-Type') {
            contentType = value;
          }
        }
      });
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

  describe('without signing request', function () {
    var callback, RelayState, SAMLRequest, contentType;

    before(function (done) {
      var logout = samlpLogout({
        protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        issuer: 'http://example.org',
        identityProviderUrl: 'http://myadfs.com?a=b',
        relayState: 'foo=bar'
      });

      logout({
        samlNameID: '112233',
        samlSessionIndex: '554433'
      }, {
        send: function (html) {
          var $ = cheerio.load(html);

          callback = $('form').attr('action');
          RelayState = $('form input[name="RelayState"]').val();
          var samlRequestInput = $('form input[name="SAMLRequest"]').val();
          
          var SAMLRequestBase64 = new Buffer(samlRequestInput, 'base64').toString();
          SAMLRequest = new DOMParser().parseFromString(SAMLRequestBase64);
          done();
        },
        set: function (key, value) {
          if (key === 'Content-Type') {
            contentType = value;
          }
        }
      });
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
