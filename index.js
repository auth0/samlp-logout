var zlib      = require('zlib');
var DOMParser = require('xmldom').DOMParser;
var xpath     = require('xpath');
var qs        = require('querystring');
var util      = require('util');
var qs        = require('querystring');
var templates = require('./templates');
var trim_xml  = require('./lib/trim_xml');
var signers   = require('./lib/signers');
var utils     = require('./lib/utils');

var BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

var RESPONSE_EMBEDDED_SIGNATURE_PATH = "//*[local-name(.)='LogoutResponse']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
var REQUEST_EMBEDDED_SIGNATURE_PATH = "//*[local-name(.)='LogoutRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

function prepareAndSendToken (req, res, type, token, options, cb) {
  var send = function (params) {
    if (options.protocolBinding === BINDINGS.HTTP_POST) {
      // HTTP-POST
      res.set('Content-Type', 'text/html');
      return res.send(templates.Form({
        type:         type,
        callback:     options.identityProviderUrl,
        RelayState:   params.RelayState,
        token:        params[type]
      }));
    }

    // HTTP-Redirect
    var samlResponseUrl = utils.appendQueryString(options.identityProviderUrl, params);
    res.redirect(samlResponseUrl);
  };

  var params = {};
  params[type] = null;
  params.RelayState = req.body.RelayState || req.query.RelayState || options.relayState || '';

  // canonical request
  token = trim_xml(token);

  if (options.protocolBinding === BINDINGS.HTTP_POST || !options.deflate) {
    // HTTP-POST or HTTP-Redirect without deflate encoding
    try {
      token = signers.signXml(options, token);
    } catch (err) {
      return cb(err);
    }

    params[type] = new Buffer(token).toString('base64');
    return send(params);
  }

  // Default: HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
  zlib.deflateRaw(new Buffer(token), function (err, buffer) {
    if (err) return cb(err);

    params[type] = buffer.toString('base64');

    // construct the Signature: a string consisting of the concatenation of the SAMLResponse,
    // RelayState (if present) and SigAlg query string parameters (each one URLencoded)
    if (params.RelayState === '') {
      // if there is no RelayState value, the parameter should be omitted from the signature computation
      delete params.RelayState;
    }

    params.SigAlg = signers.getSigAlg(options);
    params.Signature = signers.sign(options, qs.stringify(params));

    send(params);
  });
}

function isTokenExpired (logoutNode) {
  var notOnOrAfterText = logoutNode.getAttribute('NotOnOrAfter');
  if (notOnOrAfterText) {
    var notOnOrAfter = new Date(notOnOrAfterText);
    notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew
    var now = new Date();
    return now > notOnOrAfter;
  }

  return false;
}

function validateSignature (req, type, xml, options) {
  var isRequestSigned = req.body[type] ?
    xpath.select(REQUEST_EMBEDDED_SIGNATURE_PATH, xml).length > 0 : !!req.query.SigAlg;

  if (isRequestSigned) {
    if (req.body[type] || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      var validationErrors = signers.validateXmlEmbeddedSignature(xml, options);
      if (validationErrors && validationErrors.length > 0) {
        throw new Error(validationErrors.join('; '));
      }
    }
    else {
      // HTTP-Redirect with deflate encoding
      var signedContent = {};
      signedContent[type] = req.query[type];
      signedContent.RelayState = req.query.RelayState;
      signedContent.SigAlg = req.query.SigAlg;

      if (!signedContent.RelayState) {
        delete signedContent.RelayState;
      }

      if (!signedContent.SigAlg) {
        throw new Error('SigAlg parameter is mandatory');
      }

      var valid = signers.isValidContentAndSignature(qs.stringify(signedContent), req.query.Signature, {
        identityProviderSigningCert: options.identityProviderSigningCert,
        signatureAlgorithm: req.query.SigAlg
      });
      
      if (!valid) {
        throw new Error('invalid signature: the signature value ' + req.query.Signature + ' is incorrect');
      }
    }
  } else if (type === 'SAMLRequest') {
    throw new Error('LogoutRequest message MUST be signed when using an asynchronous binding (POST or Redirect)');
  }
}

module.exports = function (options) {
  options = options || {};

  // Scenario #2: IdP Single Logout - SLO
  var idpSingleLogOut = function (req, res, next) {
    var SAMLRequest = req.query.SAMLRequest || req.body.SAMLRequest;

    var validateAndRespond = function (err, buffer) {
      if (err) return next(err);

      var xml = new DOMParser().parseFromString(buffer.toString());
      var logoutRequestNode = xpath.select("//*[local-name(.)='LogoutRequest']", xml)[0];

      // validate expiration
      if (isTokenExpired(logoutRequestNode)) {
        return next(new Error('LogoutRequest has expired'));
      }

      // validate signature
      try {
        validateSignature(req, 'SAMLRequest', xml, options);
      } catch (e) {
        return next(e);
      }

      // get ID, Issuer, NameID and SessionIndex
      var parsedRequest = {};
      parsedRequest.id = logoutRequestNode && logoutRequestNode.getAttribute('ID');

      var issuerNode = xpath.select("//*[local-name(.)='Issuer']", xml);
      parsedRequest.issuer = issuerNode && issuerNode[0] && issuerNode[0].textContent;

      var nameIdNode = xpath.select("//*[local-name(.)='NameID']", xml);
      parsedRequest.nameId = nameIdNode && nameIdNode[0] && nameIdNode[0].textContent;

      var sessionIndexNode = xpath.select("//*[local-name(.)='SessionIndex']", xml);
      parsedRequest.sessionIndex = sessionIndexNode && sessionIndexNode[0] && sessionIndexNode[0].textContent;

      // validate parameters (NameID and SessionIndex)
      if (!parsedRequest.sessionIndex) { return next(new Error('Missing SessionIndex')); }
      if (!parsedRequest.nameId) { return next(new Error('Missing NameID')); }

      var checkSessionIndex = typeof options.validSessionIndex === 'function';
      var isValidSessionIndex = checkSessionIndex && options.validSessionIndex(parsedRequest);
      if (checkSessionIndex && !isValidSessionIndex) {
        return next(new Error('Invalid SessionIndex/NameID'));
      }

      // prepare and send response
      var logoutResponse = templates.LogoutResponse({
        ID: utils.generateUniqueID(),
        IssueInstant: utils.getRoundTripDateFormat(),
        Destination: options.identityProviderUrl,
        InResponseTo: parsedRequest.id,
        Issuer: options.issuer,
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success' // TODO: support all status codes
      });

      options.reference = "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']";
      
      prepareAndSendToken(req, res, 'SAMLResponse', logoutResponse, options, next);
    };

    if (req.body.SAMLRequest || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      return validateAndRespond(null, new Buffer(SAMLRequest, 'base64'));
    }

    // Default: HTTP-Redirect with deflate encoding
    zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), validateAndRespond);
  };

  // Scenario #1.2: parse and validate SAMLResponse (Logout Response)
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

      // validate signature
      try {
        validateSignature(req, 'SAMLResponse', xml, options);
      } catch (e) {
        return next(e);
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

    if (req.query.SAMLRequest || req.body.SAMLRequest) {
      // Scenario #2 (IdP-Initiated SLO): parse and validate SAMLRequest and return a SAMLResponse
      return idpSingleLogOut(req, res, next);
    }

    if (req.query.SAMLResponse || req.body.SAMLResponse) {
      // Scenario #1.2: parse and validate the Logout Response
      return parseResponse(req, res, next);
    }

    // Scenario #1.1: initialize a Logout Request
    var logoutRequest = templates.LogoutRequest({
      ID: utils.generateUniqueID(),
      IssueInstant: utils.getRoundTripDateFormat(),
      Issuer: options.issuer,
      NameID: typeof req.samlNameID === 'string' ? { value: req.samlNameID } : req.samlNameID,
      SessionIndex: req.samlSessionIndex,
      Destination: options.identityProviderUrl
    });

    prepareAndSendToken(req, res, 'SAMLRequest', logoutRequest, options, next);
  };
};
