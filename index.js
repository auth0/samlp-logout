var zlib      = require('zlib');
var url       = require('url');
var xmldom    = require('xmldom');
var templates = require('./templates');
var trim_xml  = require('./lib/trim_xml');
var sign_xml  = require('./lib/sign_xml');
var DOMParser = xmldom.DOMParser;

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

function buildUrl(identityProviderUrl, buffer, relayState) {
  var parsed = url.parse(identityProviderUrl, true);
  delete parsed.search;
  parsed.query.SAMLRequest = buffer.toString('base64');
  
  if (relayState) {
    parsed.query.RelayState = relayState;
  }
  
  return url.format(parsed);
}

module.exports = function (options) {

  function sendRequest(req, res, next, samlrequest) {
    if (options.protocolBinding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
      res.set('Content-Type', 'text/html');
      return res.send(templates.Form({
        callback:     options.identityProviderUrl,
        RelayState:   options.relayState || '',
        SAMLRequest:  samlrequest.toString('base64')
      }));
    }

    // HTTP-Redirect
    res.redirect(buildUrl(options.identityProviderUrl, samlrequest, options.relayState));
  }

  return function (req, res, next) {
    var logoutRequest = templates.LogoutRequest({
      ID: generateUniqueID(),
      IssueInstant: getRoundTripDateFormat(),
      Issuer: options.issuer,
      NameID: typeof req.samlNameID === 'string' ? { value: req.samlNameID } : req.samlNameID,
      SessionIndex: req.samlSessionIndex,
      Destination: options.identityProviderUrl
    });

    // canonical request
    logoutRequest = trim_xml(logoutRequest);

    if (options.cert && options.key) {
      try {
        // signed request
        logoutRequest = sign_xml(options, logoutRequest);
      } catch (err) {
        return next(err);
      }
    }

    if (options.deflate) {
      // we compress with deflate
      zlib.deflateRaw(logoutRequest, function (err, buffer) {
        if (err) return next(err);
        sendRequest(req, res, next, buffer);
      });
    } else {
      sendRequest(req, res, next, new Buffer(logoutRequest));
    }
  };
};

module.exports.parseResponse = function (samlResponse, callback) {
  zlib.inflateRaw(new Buffer(samlResponse, 'base64'), function (err, buffer) {
    if (err) return callback(err);
    var xml = new DOMParser().parseFromString(buffer.toString());
    var status = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusCode')[0]
                    .getAttribute('Value');

    callback(null, { status: status });
  });
};