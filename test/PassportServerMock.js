const nock = require('nock');
const uuid = require('uuid/v4');

class PassportServerMock {
    constructor({ url, clientId, clientSecret, userEndpoint }) {
        this.url = url;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.userEndpoint = userEndpoint;

        this.usersByHash = {};
        this.userHashByToken = {};
    }

    setup() {
        const self = this;

        nock(this.url).persist()
            .post(uri => uri === '/oauth/token')
            .reply((uri, body) => {
                const json = JSON.parse(body);

                const userHash = (json.grant_type === 'password')
                    ? `${json.username}:${json.password}`
                    : `${json.network}:${json.access_token}`;

                if (!this.usersByHash[userHash]) {
                    return [401, {
                        error: 'invalid_credentials',
                        message: 'The user credentials were incorrect.'
                    }];
                }

                const tokenData = this._createAccessTokenForUser(userHash);
                return [200, tokenData];
            })
            .get(uri => uri === this.userEndpoint)
            .reply(function() {
                const accessToken = this.req.headers.authorization;
                const user = self._getUserByAccessToken(accessToken);
                return [200, user];
            })
            .get(() => true)
            .reply(function() {
                return [404, { message: 'Invalid route' }];
            });
    }

    async addPasswordUser(user) {
        this.usersByHash[`${user.username}:${user.password}`] = user;
    }

    async addSocialUser(user) {
        this.usersByHash[`${user.network}:${user.accessToken}`] = user;
    }

    _createAccessTokenForUser(userHash) {
        const accessTokenData = {
            token_type: 'Bearer',
            expires_in: 31536000,
            access_token: uuid(),
            refresh_token: uuid(),
        };

        this.userHashByToken[accessTokenData.access_token] = userHash;

        return accessTokenData;
    }

    _getUserByAccessToken(accessToken) {
        // Remove leading 'Bearer ', if set
        accessToken = this._cleanupBearerKeyword(accessToken || '');

        const userHash = this.userHashByToken[accessToken];

        return this.usersByHash[userHash];
    }

    _cleanupBearerKeyword(bearerToken) {
        if (bearerToken.toLowerCase().indexOf('bearer ') === 0) {
            return bearerToken.substring('bearer '.length);
        }

        return bearerToken;
    }
}

module.exports = PassportServerMock;
