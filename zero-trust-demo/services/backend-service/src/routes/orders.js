'use strict';

const { Router } = require('express');
const { authenticate } = require('../middlewares/auth');
const { authorize, dataAccessControl } = require('../middlewares/authorize');
const { auditLog } = require('../middlewares/audit');

const router = Router();

// GET /api/v1/orders
router.get('/',
    authenticate,
    authorize('api'),
    dataAccessControl('business', 'confidential'),
    auditLog('list_orders'),
    (_req, res) => {
        res.json({
            orders: [
                { id: 'ORD-001', customer: 'Customer A', total: 299.99, status: 'completed' },
                { id: 'ORD-002', customer: 'Customer B', total: 149.99, status: 'pending' },
            ],
        });
    }
);

module.exports = router;
