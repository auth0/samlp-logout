Federated single sign-out for SAMLP providers from express.js applications.

## Installation

```
npm i samlp-logout --save
```

## Usage

```javascript
var SamlpLogout = require('samlp-logout');

var logout = SamlpLogout({
  issuer: 'urn:foobar',
  identityProviderUrl: 'http://xx.b'
});

//assuming we have req.samlNameID
app.get('/logout', function (req, res, next) {
  req.samlNameID = {
    value: 'xyz',
    Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  };
  next();
}, logout);
```

## License

MIT - 2014 - AUTH0 INC.