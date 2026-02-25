'use strict';

const axios = require('axios');
const config = require('../config');
const logger = require('../services/logger');
const { policyDecisions } = require('./metrics');

/**
 * Call OPA for a policy decision.
 * Timeout is 500ms — authz runs on every request.
 * In production, run OPA as a sidecar to make this a localhost call (<1ms).
 * Fails closed on any error (timeout, unreachable, parse failure).
 *
 * @param {string} policy - OPA policy path segment (e.g. 'authz/decision')
 * @param {object} input  - Input document sent to OPA
 * @returns {Promise<{allow: boolean, audit?: boolean, reasons?: string[]}>}
 */
async function checkPolicy(policy, input) {
    try {
        const response = await axios.post(
            `${config.opa.url}/v1/data/zerotrust/${policy}`,
            { input },
            { timeout: 500 }
        );
        const result = response.data.result;
        policyDecisions.labels(result?.allow ? 'allow' : 'deny', policy).inc();
        return result;
    } catch (error) {
        logger.error('Policy check error', { policy, error: error.message });
        policyDecisions.labels('error', policy).inc();
        // Fail closed: deny on any OPA error.
        return { allow: false };
    }
}

/**
 * Express middleware factory: enforces OPA authorization.
 * @param {string} resourceType - Resource type passed to OPA (e.g. 'api')
 */
function authorize(resourceType = 'api') {
    return async (req, res, next) => {
        const policyResult = await checkPolicy('authz/decision', {
            user: req.user,
            resource: { type: resourceType, path: req.path, method: req.method },
            context: {
                ip: req.ip,
                user_agent: req.headers['user-agent'],
                timestamp: new Date().toISOString(),
                request_id: req.requestId,
            },
        });

        if (!policyResult.allow) {
            logger.warn('Access denied', {
                user: req.user.id,
                path: req.path,
                reasons: policyResult.reasons,
                requestId: req.requestId,
            });
            return res.status(403).json({
                error: 'Access denied',
                reasons: policyResult.reasons,
                requestId: req.requestId,
            });
        }

        req.requiresAudit = policyResult.audit;
        next();
    };
}

/**
 * Express middleware factory: OPA data-classification check.
 * @param {string} dataType       - e.g. 'pii', 'business'
 * @param {string} classification - e.g. 'confidential', 'internal'
 */
function dataAccessControl(dataType, classification) {
    return async (req, res, next) => {
        const policyResult = await checkPolicy('data/decision', {
            user: { ...req.user, department: 'engineering' },
            data: {
                type: dataType,
                classification,
                owner_department: 'engineering',
                fields: req.body?.fields || ['id', 'name', 'email'],
            },
            action: req.method === 'GET' ? 'read' : 'write',
            purpose: req.headers['x-access-purpose'] || 'system_maintenance',
        });

        if (!policyResult.allow) {
            return res.status(403).json({ error: 'Data access denied', requestId: req.requestId });
        }

        req.maskedFields = policyResult.masked_fields || [];
        req.requiresAudit = policyResult.requires_audit;
        next();
    };
}

module.exports = { authorize, dataAccessControl };
