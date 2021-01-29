const url = require('url');
const xtend = require('xtend');

const IdGenerator = require('auth0-id-generator');
const generator = new IdGenerator({len: 20, alphabet: "abcdef0123456789"});

/**
 * Generates a random alphanumeric ID.
 * > IDs are 20 characters long and use the hexadecimal alphabet
 * @returns {string}
 */
exports.generateUniqueID = function () {
  return generator.get();
};

exports.getRoundTripDateFormat = function() {
  //http://msdn.microsoft.com/en-us/library/az4se3k1.aspx#Roundtrip
  const date = new Date();
  return date.getUTCFullYear() + '-' +
        ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' +
        ('0' + date.getUTCDate()).slice(-2) + 'T' +
        ('0' + date.getUTCHours()).slice(-2) + ":" +
        ('0' + date.getUTCMinutes()).slice(-2) + ":" +
        ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

exports.appendQueryString = function(initialUrl, query) {
  const parsed = url.parse(initialUrl, true);
  parsed.query = xtend(parsed.query, query);
  delete parsed.search;
  return url.format(parsed);
};
