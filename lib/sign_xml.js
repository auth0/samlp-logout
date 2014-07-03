var SignedXml = require('xml-crypto').SignedXml;
var encoders = require('./encoders');

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

module.exports = function (options, xml) {
  var signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  var digestAlgorithm = options.digestAlgorithm || 'sha256';

  var sig = new SignedXml(null, {
    signatureAlgorithm: algorithms.signature[signatureAlgorithm],
    idAttribute: 'ID'
  });

  sig.addReference("//*[local-name(.)='LogoutRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
                  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                   "http://www.w3.org/2001/10/xml-exc-c14n#"],
                  algorithms.digest[digestAlgorithm]);

  sig.signingKey = options.key;

  var pem = encoders.removeHeaders(options.cert);
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data><X509Certificate>" + pem + "</X509Certificate></X509Data>";
    }
  };

  sig.computeSignature(xml, "//*[local-name(.)='Issuer']");
  return sig.getSignedXml();
};