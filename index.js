const PassportClient = require('./src/PassportClient');
const jwtValidatorMiddleware = require('./src/jwtValidatorMiddleware');

const DEFAULT_JWT_CACHE_TIME = 5 * 60 * 1000; // 5 min

module.exports = ({ url, clientId, clientSecret }) => {
    const client = new PassportClient({ url, clientId, clientSecret });

    const _auth = async (body, res) => {
        const clientRes = await client.requestAccessToken(body);
        res.status(clientRes.status).json(clientRes.data);
    };

    return {
        // Allow auth with any grant type
        async auth(req, res) {
            return await _auth(req.body, res);
        },

        // Attempt authentication only with password grant
        async passwordAuth(req, res) {
            const { username, password } = req.body;
            return await _auth({ grant_type: 'password', username, password }, res);
        },

        // Attempt authentication only with social grant
        async socialAuth(req, res) {
            const { network, access_token } = req.body;
            return await _auth({ grant_type: 'social', network, access_token }, res);
        },

        // Builds a middleware to validate the bearer token of an
        // authorized user against the given endpoint.
        //
        // This endpoint should return data about the user which
        // the passport server wants to make available to the
        // application.
        //
        // If successful, the user's data is published in `req.user`.
        jwtValidator({
            userEndpoint = '/user',
            requireAuth = true,
            cacheTime = DEFAULT_JWT_CACHE_TIME
        } = {}) {
            return jwtValidatorMiddleware({ client, userEndpoint, requireAuth, cacheTime });
        }
    };
};
