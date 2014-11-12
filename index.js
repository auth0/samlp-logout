var templates = require('./templates');
var zlib = require('zlib');
var url = require('url');
var trim_xml = require('./lib/trim_xml');
var sign_xml = require('./lib/sign_xml');

var xmldom = require('xmldom');
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

  function redirect(req, res, next, samlrequest) {
    if (!options.deflate) {
      return res.redirect(buildUrl(options.identityProviderUrl,
                                   new Buffer(samlrequest),
                                   options.relayState));
    }

    //we compress with deflate
    zlib.deflateRaw(samlrequest, function(err, buffer) {
      if (err) return next(err);
      res.redirect(buildUrl(options.identityProviderUrl, buffer, options.relayState));
    });
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

    var canonicalRequest = trim_xml(logoutRequest);

    if (options.cert && options.key) {
      var signedRequest;

      try {
        signedRequest = sign_xml(options, canonicalRequest);
      } catch (err) {
        return next(err);
      }

      redirect(req, res, next, signedRequest);
    } else {
      redirect(req, res, next, canonicalRequest);
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