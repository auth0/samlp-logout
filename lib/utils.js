var url = require('url');
var xtend = require('xtend');

exports.generateUniqueID = function(){
  var chars = 'abcdef0123456789';
  var uniqueID = '';
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }

  return uniqueID;
};

exports.getRoundTripDateFormat = function() {
  //http://msdn.microsoft.com/en-us/library/az4se3k1.aspx#Roundtrip
  var date = new Date();
  return date.getUTCFullYear() + '-' +
        ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' +
        ('0' + date.getUTCDate()).slice(-2) + 'T' +
        ('0' + date.getUTCHours()).slice(-2) + ":" +
        ('0' + date.getUTCMinutes()).slice(-2) + ":" +
        ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

exports.appendQueryString = function(initialUrl, query) {
  var parsed = url.parse(initialUrl, true);
  parsed.query = xtend(parsed.query, query);
  delete parsed.search;
  return url.format(parsed);
};
