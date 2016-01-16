var SignedXml = require('xml-crypto').SignedXml;
var crypto    = require('crypto');
var encoders  = require('./encoders');

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

var DEFAULT_SIG_ALG = 'rsa-sha256';
var DEFAULT_DIGEST_ALG = 'sha256';

module.exports.getSigAlg = function (options) {
  return algorithms.signature[options.signatureAlgorithm || DEFAULT_SIG_ALG];
};

module.exports.signXml = function (options, xml) {
  var signatureAlgorithm = options.signatureAlgorithm || DEFAULT_SIG_ALG;
  var digestAlgorithm = options.digestAlgorithm || DEFAULT_DIGEST_ALG;

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

module.exports.sign = function (options, content) {
  var signatureAlgorithm = options.signatureAlgorithm || DEFAULT_SIG_ALG;
  var signer = crypto.createSign(signatureAlgorithm.toUpperCase());
  signer.update(content);
  return signer.sign(options.key, 'base64');
};
