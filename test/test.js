require('mocha');
const express = require('express');
const bodyParser = require('body-parser');
const { assert, request } = require('chai').use(require('chai-http'));
const PassportServerMock = require('./PassportServerMock');

const PASSPORT_CONFIG = {
    url: 'https://passport.example.com',
    clientId: 'client-id',
    clientSecret: 'client-secret'
};

describe('Authentication', () => {
    const app = express();

    before(() => {
        const passportClient = require('../')(PASSPORT_CONFIG);
        app.use(bodyParser.json());
        app.post('/oauth/token', passportClient.auth);
        app.get('/auth-required',
            passportClient.jwtValidator(),
            (req, res) => res.send('Hello World')
        );
        app.get('/auth-optional',
            passportClient.jwtValidator({ requireAuth: false }),
            (req, res) => res.json(req.user)
        );
        app.get('/invalid-user-endpoint',
            passportClient.jwtValidator({ userEndpoint: '/unknown' }),
            (req, res) => res.json(req.user)
        );
        app.listen(55723 /* port */);

        const passportServer = new PassportServerMock({
            ...PASSPORT_CONFIG,
            userEndpoint: '/user'
        });
        passportServer.addPasswordUser({ username: 'user@mail.com', password: 'secret' });
        passportServer.addSocialUser({ network: 'google', accessToken: 'google-token' });
        passportServer.setup();
    });

    describe('POST /oauth/token grant_type=password', () => {
        it('Invalid user cannot request token', async () => {
            const res = await request(app).post('/oauth/token').send({
                grant_type: 'password', username: 'unknown', password: 'unknown'
            });
            assert.equal(res.statusCode, 401);
            assert.deepEqual(res.body, {
                error: 'invalid_credentials',
                message: 'The user credentials were incorrect.'
            });
        });

        it('Valid user can request token', async () => {
            const res = await request(app).post('/oauth/token').send({
                grant_type: 'password', username: 'user@mail.com', password: 'secret'
            });
            assert.equal(res.statusCode, 200);
            assert.hasAllKeys(res.body, ['access_token', 'expires_in', 'refresh_token', 'token_type']);
        });
    });

    describe('POST /oauth/token grant_type=social', () => {
        it('Invalid user cannot request token', async () => {
            const res = await request(app).post('/oauth/token').send({
                grant_type: 'social', network: 'google', access_token: 'invalid-token'
            });
            assert.equal(res.statusCode, 401);
            assert.deepEqual(res.body, {
                error: 'invalid_credentials',
                message: 'The user credentials were incorrect.'
            });
        });

        it('Valid user can request token', async () => {
            const res = await request(app).post('/oauth/token').send({
                grant_type: 'social', network: 'google', access_token: 'google-token'
            });
            assert.equal(res.statusCode, 200);
            assert.hasAllKeys(res.body, ['access_token', 'expires_in', 'refresh_token', 'token_type']);
        });
    });

    describe('Validator middleware with requireAuth=true', () => {
        it('User without authentication cannot call endpoint', async () => {
            const res = await request(app).get('/auth-required');
            assert.equal(res.statusCode, 401);
        });

        it('User with authentication can call endpoint', async () => {
            const { body } = await request(app).post('/oauth/token').send({
                grant_type: 'password', username: 'user@mail.com', password: 'secret'
            });
            const res = await request(app).get('/auth-required')
                .set('Authorization', `bearer ${body.access_token}`);
            assert.equal(res.statusCode, 200);
        });
    });

    describe('Validator middleware with requireAuth=false', () => {
        it('User without authentication has empty req.user', async () => {
            const res = await request(app).get('/auth-optional');
            assert.equal(res.statusCode, 200);
            assert.deepEqual(res.body, null);
        });

        it('User with authentication has filled req.user', async () => {
            const { body } = await request(app).post('/oauth/token').send({
                grant_type: 'password', username: 'user@mail.com', password: 'secret'
            });
            const res = await request(app).get('/auth-optional')
                .set('Authorization', `bearer ${body.access_token}`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual(res.body, { username: 'user@mail.com', password: 'secret' });
        });
    });

    describe('Validator middleware against an invalid userEndpoint', () => {
        it('User without authentication cannot call endpoint', async () => {
            const res = await request(app).get('/invalid-user-endpoint');
            assert.equal(res.statusCode, 401);
        });

        it('User with authentication cannot call endpoint either', async () => {
            const { body } = await request(app).post('/oauth/token').send({
                grant_type: 'password', username: 'user@mail.com', password: 'secret'
            });
            const res = await request(app).get('/invalid-user-endpoint')
                .set('Authorization', `bearer ${body.access_token}`);
            assert.equal(res.statusCode, 401);
        });
    });
});
