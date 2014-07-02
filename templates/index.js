var ejs = require('ejs');
var fs = require('fs');
var path = require('path');

var templates = fs.readdirSync(__dirname);

templates.forEach(function (tmplFile) {
  if (tmplFile.substr(-3) !== 'ejs') return;
  var content = fs.readFileSync(path.join(__dirname, tmplFile));
  var template = ejs.compile(content.toString());
  exports[tmplFile.slice(0, -4)] = template;
});