const express = require('express');
const app = express();
const port = 3000;

const OktaJwtVerifier = require('@okta/jwt-verifier');
const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: 'https://trial-5793640.okta.com/oauth2/default'
});
const audience = 'api://default';

//Authenitcation middleware
const authenticationRequired = async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/Bearer (.+)/);
  if (!match) {
    return res.status(401).send();
  }

  try {
    const accessToken = match[1];
    if (!accessToken) {
      return res.status(401, 'Not authorized').send();
    }
    req.jwt = await oktaJwtVerifier.verifyAccessToken(accessToken, audience);
    next();
  } catch (err) {
    return res.status(401).send(err.message);
  }
};


// Api routes
app.get('/', (req, res) => {
  res.send('Home!')
})

app.get('/api/hello', (req, res) => {
    res.send('Hello world!');
});


app.get('/api/whoami', authenticationRequired, (req, res) => {
    const user = req.jwt.claims.sub;
    const scopes = req.jwt.claims.scp || [];
    if (scopes.includes('admin')) {
      res.send(`Hello ${user}, you are an admin!`);
    } else {
      res.send(`Hello ${user}, you have basic access.`);
    }
  });


app
  .listen(port, () => console.log('API Magic happening on port ' + port));
