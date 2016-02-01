var zlib      = require('zlib');
var url       = require('url');
var xmldom    = require('xmldom');
var xpath     = require('xpath');
var qs        = require('querystring');
var xtend     = require('xtend');
var util      = require('util');
var qs        = require('querystring');
var templates = require('./templates');
var trim_xml  = require('./lib/trim_xml');
var signers   = require('./lib/signers');
var DOMParser = xmldom.DOMParser;

var BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

var RESPONSE_EMBEDDED_SIGNATURE_PATH = "//*[local-name(.)='LogoutResponse']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

function generateUniqueID() {
  var chars = 'abcdef0123456789';
  var uniqueID = '';
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }

  return uniqueID;
}

//http://msdn.microsoft.com/en-us/library/az4se3k1.aspx#Roundtrip
function getRoundTripDateFormat() {
  var date = new Date();
  return date.getUTCFullYear() + '-' +
        ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' +
        ('0' + date.getUTCDate()).slice(-2) + 'T' +
        ('0' + date.getUTCHours()).slice(-2) + ":" +
        ('0' + date.getUTCMinutes()).slice(-2) + ":" +
        ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

function appendQueryString(initialUrl, query) {
  var parsed = url.parse(initialUrl, true);
  parsed.query = xtend(parsed.query, query);
  delete parsed.search;
  return url.format(parsed);
}

module.exports = function (options) {
  options = options || {};

  var parseResponse = function (req, res, next) {
    var SAMLResponse = req.query.SAMLResponse || req.body.SAMLResponse;

    var parseAndValidate = function (err, buffer) {
      if (err) return next(err);

      var xml = new DOMParser().parseFromString(buffer.toString());
      var parsedResponse = {};

      // status code
      var statusCodes = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusCode');
      var statusCodeXml = statusCodes[0];
      if (statusCodeXml) {
        parsedResponse.status = statusCodeXml.getAttribute('Value');

        // status sub code
        var statusSubCodeXml = statusCodes[1];
        if (statusSubCodeXml) {
          parsedResponse.subCode = statusSubCodeXml.getAttribute('Value');
        }
      }

      // status message
      var samlStatusMsgXml = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusMessage')[0];
      if (samlStatusMsgXml) {
        parsedResponse.message = samlStatusMsgXml.textContent;
      }

      // status detail
      var samlStatusDetailXml = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusDetail')[0];
      if (samlStatusDetailXml) {
        parsedResponse.detail = samlStatusDetailXml.textContent;
      }

      req.parsedSAMLResponse = parsedResponse;

      var isResponseSigned = req.body.SAMLResponse ?
        xpath.select(RESPONSE_EMBEDDED_SIGNATURE_PATH, xml).length > 0 : !!req.query.SigAlg;

      if (isResponseSigned) {
        // validate signature
        try {
          if (req.body.SAMLResponse || !options.deflate) {
            // HTTP-POST or HTTP-Redirect without deflate encoding
            var validationErrors = signers.validateXmlEmbeddedSignature(xml, options);
            if (validationErrors && validationErrors.length > 0) {
              return next(new Error(validationErrors.join('; ')));
            }
          }
          else {
            // HTTP-Redirect with deflate encoding
            var signedContent = {
              SAMLResponse: req.query.SAMLResponse,
              RelayState: req.query.RelayState,
              SigAlg: req.query.SigAlg
            };

            if (!signedContent.RelayState) {
              delete signedContent.RelayState;
            }

            if (!signedContent.SigAlg) {
              return next(new Error('SigAlg parameter is mandatory'));
            }

            signers.isValidContentAndSignature(qs.stringify(signedContent), req.query.Signature, {
              identityProviderSigningCert: options.identityProviderSigningCert,
              signatureAlgorithm: req.query.SigAlg
            });
          }
        } catch (e) {
          return next(e);
        }
      }

      // validate status
      if (parsedResponse.status !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        var err_message = parsedResponse.message && parsedResponse.detail ?
          util.format('%s (%s)', parsedResponse.message, parsedResponse.detail) :
          parsedResponse.message ||
          parsedResponse.detail ||
          util.format('unexpected SAMLP Logout response (%s)', parsedResponse.status);

        return next(new Error(err_message));
      }

      next();
    };

    if (req.body.SAMLResponse || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      return parseAndValidate(null, new Buffer(SAMLResponse, 'base64'));
    }

    // Default: HTTP-Redirect with deflate encoding
    zlib.inflateRaw(new Buffer(SAMLResponse, 'base64'), parseAndValidate);
  };

  var sendRequest = function (req, res, next, params) {
    if (options.protocolBinding === BINDINGS.HTTP_POST) {
      // HTTP-POST
      res.set('Content-Type', 'text/html');
      return res.send(templates.Form({
        callback:     options.identityProviderUrl,
        RelayState:   params.RelayState,
        SAMLRequest:  params.SAMLRequest
      }));
    }

    // HTTP-Redirect
    var samlRequestUrl = appendQueryString(options.identityProviderUrl, params);
    res.redirect(samlRequestUrl);
  };

  return function (req, res, next) {
    req.body = req.body || {};
    req.query = req.query || {};

    // validations
    if (!options.cert || !options.key) {
      return next(new Error('signing key is mandatory (options.cert and options.key)'));
    }

    if (!options.identityProviderSigningCert) {
      return next(new Error('options.identityProviderSigningCert is mandatory'));
    }

    if (req.query.SAMLResponse || req.body.SAMLResponse) {
      // parse SAMLResponse (Logout Response)
      return parseResponse(req, res, next);
    }

    // initialize a Logout Request
    var logoutRequest = templates.LogoutRequest({
      ID: generateUniqueID(),
      IssueInstant: getRoundTripDateFormat(),
      Issuer: options.issuer,
      NameID: typeof req.samlNameID === 'string' ? { value: req.samlNameID } : req.samlNameID,
      SessionIndex: req.samlSessionIndex,
      Destination: options.identityProviderUrl
    });

    var params = {
      SAMLRequest: null,
      RelayState: options.relayState || ''
    };

    // canonical request
    logoutRequest = trim_xml(logoutRequest);

    if (options.protocolBinding === BINDINGS.HTTP_POST || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      try {
        logoutRequest = signers.signXml(options, logoutRequest);
      } catch (err) {
        return next(err);
      }

      params.SAMLRequest = new Buffer(logoutRequest).toString('base64');
      return sendRequest(req, res, next, params);
    }

    // Default: HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
    zlib.deflateRaw(new Buffer(logoutRequest), function (err, buffer) {
      if (err) return next(err);

      params.SAMLRequest = buffer.toString('base64');

      // construct the Signature: a string consisting of the concatenation of the SAMLRequest,
      // RelayState (if present) and SigAlg query string parameters (each one URLencoded)
      if (params.RelayState === '') {
        // if there is no RelayState value, the parameter should be omitted from the signature computation
        delete params.RelayState;
      }
      
      params.SigAlg = signers.getSigAlg(options);
      params.Signature = signers.sign(options, qs.stringify(params));

      sendRequest(req, res, next, params);
    });
  };
};
