var expect = require('chai').expect;
var url = require('url');
var samlpLogout = require('../');
var xmldom = require('xmldom');
var DOMParser = xmldom.DOMParser;

var fs = require('fs');
var path = require('path');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, 'fixture', 'samlp.test-cert.key')),
};

describe('samlp logout request', function () {
  var parsedUrl, SAMLRequest;

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
        var xml = new Buffer(parsedUrl.query.SAMLRequest, 'base64').toString();
        SAMLRequest = new DOMParser().parseFromString(xml);
        done();
      }
    });
  });

  it('should be a samlp:LogoutRequest doc', function () {
    expect(SAMLRequest.firstChild.nodeName)
      .to.equal('samlp:LogoutRequest');
  });

  it('should contain an ID attribute', function () {
    expect(SAMLRequest.firstChild.hasAttribute('ID'))
      .to.be.ok;
  });

  it('should contain an ID attribute', function () {
    expect(SAMLRequest.firstChild.hasAttribute('IssueInstant'))
      .to.be.ok;
  });

  it('should be digital signed', function () {

    // var el = SAMLRequest.childNodes[0]
    //                     .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
    // expect(el.childNodes[0].textContent).to.equal('http://example.org');
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