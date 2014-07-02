var templates = require('./templates');
var zlib = require('zlib');
var url = require('url');

function trimXML (xml) {
  return xml.replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
}

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
  return function (req, res, next) {

    var logoutRequest = templates.LogoutRequest({
      ID: generateUniqueID(),
      IssueInstant: getRoundTripDateFormat(),
      Issuer: options.issuer,
      NameID: req.samlNameID,
      SessionIndex: req.samlSessionIndex,
      Destination: options.identityProviderUrl
    });

    console.log(logoutRequest);

    var logoutRequestBuffer = new Buffer(trimXML(logoutRequest));

    if (!options.deflate) {
      return res.redirect(buildUrl(options.identityProviderUrl, logoutRequestBuffer, options.relayState));
    }

    zlib.deflateRaw(logoutRequestBuffer, function(err, buffer) {
      if (err) return next(err);
      res.redirect(buildUrl(options.identityProviderUrl, buffer, options.relayState));
    });
  };
};