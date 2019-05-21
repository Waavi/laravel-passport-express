const axios = require('axios');

class PassportClient {
    constructor({ url, clientId, clientSecret }) {
        this.client = axios.create({ baseURL: url });
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    async _captureResponse(request) {
        try {
            return await request;
        } catch (e) {
            if (e.response) {
                return e.response;
            }
            throw e;
        }
    }

    async requestAccessToken(params) {
        const body = {
            // 'grant_type=password', 'username', 'password' or
            // 'grant_type=social', 'network', 'access_token'
            ...params,
            client_id: this.clientId,
            client_secret: this.clientSecret
        };

        return await this._captureResponse(
            this.client.post('/oauth/token', body)
        );
    }

    // Extract the access token from the authorization header
    // string, if it has the format `Bearer ACCESS_TOKEN`.
    extractAccessToken(bearerToken) {
        if (bearerToken.toLowerCase().indexOf('bearer ') === 0) {
            return bearerToken.substring('bearer '.length);
        }

        return bearerToken;
    }

    // Perform a request authenticating with the given access token.
    async requestWithToken(accessToken, endpoint) {
        // Remove leading 'Bearer ', if set
        accessToken = this.extractAccessToken(accessToken || '');

        const headers = { Authorization: `Bearer ${accessToken}` };

        return await this._captureResponse(
            this.client.get(endpoint, { headers })
        );
    }
}

module.exports = PassportClient;
