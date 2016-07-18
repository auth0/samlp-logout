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
  identityProviderUrl: 'http://xx.b',
  identityProviderSigningCert: fs.readFileSync('idpSigningKey.pem'), // validate LogoutRequest signature
  key: fs.readFileSync('signingKey.key'), // sign LogoutResponse
  cert: fs.readFileSync('signingKey.pem')
});

// assuming we have req.samlSessionIndex and req.samlNameID
app.get('/logout', function (req, res, next) {
  req.samlSessionIndex = 'abc';
  req.samlNameID = {
    value: 'xyz',
    Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  };
  next();
}, logout);
```

## License

MIT - 2014 - AUTH0 INC.
