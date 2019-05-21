## laravel-passport-express

Express middleware to authenticate against a Laravel Passport server.

### Installation

```
npm install --save git+https://github.com/Waavi/laravel-passport-express.git#master
```

### Usage

```js
const express = require('express');
const bodyParser = require('body-parser');
const passportClient = require('laravel-passport-express');

const passport = passportClient({
    url: 'https://my-passport-server.com',
    clientId: 'client-id',
    clientSecret: 'client-secret'
});

const requireAuth = passport.authToken();

const optionalAuth = passport.authToken({
    requireAuth: false,
    userEndpoint: '/user'
});

const app = express();

app.use(bodyParser.json());

app.post('/oauth/token', passport.requestToken);

app.get('/user', requireAuth, (req, res) => {
    res.send('You are authenticated');
});

app.get('/user-maybe', optionalAuth, (req, res) => {
    res.json(req.user || 'No user');
});

app.listen(8080);
```
