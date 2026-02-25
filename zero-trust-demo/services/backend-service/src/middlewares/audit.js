'use strict';

const logger = require('../services/logger');

/**
 * Express middleware factory: structured audit log for sensitive operations.
 * Only logs if req.requiresAudit was set by the authorization middleware.
 * @param {string} action - Human-readable action name (e.g. 'list_users')
 */
function auditLog(action) {
    return (req, _res, next) => {
        if (req.requiresAudit) {
            logger.info('AUDIT', {
                action,
                user: req.user.id,
                resource: req.path,
                method: req.method,
                ip: req.ip,
                requestId: req.requestId,
                timestamp: new Date().toISOString(),
            });
        }
        next();
    };
}

module.exports = { auditLog };
