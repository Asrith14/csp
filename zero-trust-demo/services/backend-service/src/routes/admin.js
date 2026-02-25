'use strict';

const { Router } = require('express');
const { authenticate } = require('../middlewares/auth');
const { authorize } = require('../middlewares/authorize');
const { auditLog } = require('../middlewares/audit');
const { getSecret } = require('../services/vault');

const router = Router();

// GET /api/v1/config (admin only)
router.get('/config',
    authenticate,
    authorize('api'),
    async (req, res) => {
        if (!req.user.roles.includes('admin')) {
            return res.status(403).json({ error: 'Admin access required', requestId: req.requestId });
        }
        try {
            const secrets = await getSecret('apps/api-keys');
            res.json({
                config: {
                    feature_flags: { dark_mode: true, beta_features: false },
                    api_version: 'v1',
                    secrets_loaded: Object.keys(secrets).length > 0,
                },
                requestId: req.requestId,
            });
        } catch {
            res.status(500).json({ error: 'Config error', requestId: req.requestId });
        }
    }
);

// GET /api/v1/audit (admin only)
router.get('/audit',
    authenticate,
    authorize('api'),
    auditLog('view_audit'),
    (req, res) => {
        if (!req.user.roles.includes('admin')) {
            return res.status(403).json({ error: 'Admin access required', requestId: req.requestId });
        }
        res.json({
            audit: {
                total_requests_today: 1250,
                failed_auth_attempts: 12,
                policy_denials: 5,
                sensitive_data_access: 45,
            },
            requestId: req.requestId,
        });
    }
);

module.exports = router;
