var zlib      = require('zlib');
var url       = require('url');
var xmldom    = require('xmldom');
var qs        = require('querystring');
var xtend     = require('xtend');
var templates = require('./templates');
var trim_xml  = require('./lib/trim_xml');
var signers   = require('./lib/signers');
var DOMParser = xmldom.DOMParser;

var BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
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

  function sendRequest(req, res, next, params) {
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
  }

  return function (req, res, next) {
    var signRequest = !!(options.cert && options.key);
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
      if (signRequest) {
        try {
          logoutRequest = signers.signXml(options, logoutRequest);
        } catch (err) {
          return next(err);
        }
      }

      params.SAMLRequest = new Buffer(logoutRequest).toString('base64');
      return sendRequest(req, res, next, params);
    }

    // HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
    zlib.deflateRaw(new Buffer(logoutRequest), function (err, buffer) {
      if (err) return next(err);

      params.SAMLRequest = buffer.toString('base64');

      if (signRequest) {
        // construct the Signature: a string consisting of the concatenation of the SAMLRequest,
        // RelayState (if present) and SigAlg query string parameters (each one URLencoded)
        if (params.RelayState === '') {
          // if there is no RelayState value, the parameter should be omitted from the signature computation
          delete params.RelayState;
        }
        
        params.SigAlg = signers.getSigAlg(options);
        params.Signature = signers.sign(options, qs.stringify(params));
      }

      sendRequest(req, res, next, params);
    });
  };
};

module.exports.parseResponse = function (samlResponse, callback) {
  zlib.inflateRaw(new Buffer(samlResponse, 'base64'), function (err, buffer) {
    if (err) return callback(err);
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

    callback(null, parsedResponse);
  });
};