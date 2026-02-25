'use strict';

const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const config = require('../config');
const logger = require('../services/logger');

const jwksClient = jwksRsa({
    jwksUri: `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/certs`,
    cache: true,
    cacheMaxAge: 600_000,
});

function getKey(header, callback) {
    jwksClient.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);
        callback(null, key.publicKey || key.rsaPublicKey);
    });
}

function verifyToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(
            token,
            getKey,
            {
                algorithms: ['RS256'],
                issuer: [
                    `${config.keycloak.url}/realms/${config.keycloak.realm}`,
                    `http://localhost:8080/realms/${config.keycloak.realm}`,
                ],
            },
            (err, decoded) => (err ? reject(err) : resolve(decoded))
        );
    });
}

/**
 * Express middleware: validates Bearer JWT and attaches req.user.
 * Returns 401 on missing or invalid token.
 */
async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required', requestId: req.requestId });
    }

    try {
        const decoded = await verifyToken(authHeader.substring(7));
        req.user = {
            id: decoded.sub,
            email: decoded.email,
            roles: decoded.realm_access?.roles || [],
            groups: decoded.groups || [],
            name: decoded.name,
            clearance_level:
                decoded.realm_access?.roles?.includes('admin') ? 3 :
                    decoded.realm_access?.roles?.includes('developer') ? 2 : 1,
        };
        next();
    } catch (error) {
        logger.warn('Auth failed', { error: error.message, requestId: req.requestId });
        return res.status(401).json({ error: 'Invalid token', requestId: req.requestId });
    }
}

module.exports = { authenticate };
