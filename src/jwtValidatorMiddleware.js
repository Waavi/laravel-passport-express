const PassportClient = require('./PassportClient');
const { Cache } = require('memory-cache');

const unauthorized = res => {
    res.status(401).json({
        error: 'unauthorized',
        message: 'You must authenticate to perform this action',
    });
};

module.exports = ({ client, userEndpoint, requireAuth, cacheTime }) => {
    const cache = new Cache();

    return async(req, res, next) => {
        const accessToken = req.headers.authorization;
        let user = null;

        // Attempt to find a cached user for the token,
        // or request it to the Passport server.
        // If the endpoint returns a valid response but
        // no data, assume its a valid user, and just set
        // `req.user` to true.
        if (accessToken) {
            user = cache.get(accessToken);

            if (!user) {
                const resp = await client.requestWithToken(accessToken, userEndpoint);

                if (resp.status === 200) {
                    user = resp.data || true;
                }
            }
        }

        // No user found in an endpoint with required auth,
        // return unauthorized error.
        if (!user && requireAuth) {
            return unauthorized(res);
        }

        // No user found, continue.
        if (!user) {
            req.user = null;
            return next();
        }

        // Cache the found token's user temporarily and
        // make it available in 'req.user'
        cache.put(accessToken, user, cacheTime);
        req.user = user;

        next();
    };
}