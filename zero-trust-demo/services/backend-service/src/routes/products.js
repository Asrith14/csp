'use strict';

const { Router } = require('express');
const { authenticate } = require('../middlewares/auth');
const { authorize, dataAccessControl } = require('../middlewares/authorize');

const router = Router();

// GET /api/v1/products
router.get('/',
    authenticate,
    authorize('api'),
    dataAccessControl('business', 'internal'),
    (_req, res) => {
        res.json({
            products: [
                { id: 1, name: 'Product A', price: 99.99, stock: 100 },
                { id: 2, name: 'Product B', price: 149.99, stock: 50 },
                { id: 3, name: 'Product C', price: 199.99, stock: 25 },
            ],
        });
    }
);

module.exports = router;
