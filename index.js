const PassportClient = require('./src/PassportClient');
const jwtValidatorMiddleware = require('./src/jwtValidatorMiddleware');

const DEFAULT_JWT_CACHE_TIME = 5 * 60 * 1000; // 5 min

module.exports = ({ url, clientId, clientSecret }) => {
    const client = new PassportClient({ url, clientId, clientSecret });

    return {
        // Expose possport client instance to the user,
        // in case its useful to use it directly.
        client,

        // Request an access token with a grant_type
        // supported by the Passport server.
        //
        // The client will add the configured clientId and
        // clientSecret to the request, and forward it to
        // the Passport server.
        async requestToken(req, res) {
            const tokenResp = await client.requestAccessToken(req.body);
            res.status(tokenResp.status).json(tokenResp.data);
        },

        // Builds a middleware to validate the bearer token of an
        // authorized user against the given endpoint.
        //
        // This endpoint should return data about the user which
        // the passport server wants to make available to the
        // application.
        //
        // If successful, the user's data is published in `req.user`.
        authToken({
            userEndpoint = '/user',
            requireAuth = true,
            cacheTime = DEFAULT_JWT_CACHE_TIME
        } = {}) {
            return jwtValidatorMiddleware({ client, userEndpoint, requireAuth, cacheTime });
        }
    };
};
