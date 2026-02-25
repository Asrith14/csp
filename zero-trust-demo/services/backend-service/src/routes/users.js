'use strict';

const { Router } = require('express');
const { body, validationResult } = require('express-validator');
const { authenticate } = require('../middlewares/auth');
const { authorize, dataAccessControl } = require('../middlewares/authorize');
const { auditLog } = require('../middlewares/audit');
const { dbQueryDuration } = require('../middlewares/metrics');
const pool = require('../services/database');
const logger = require('../services/logger');

const router = Router();

// GET /api/v1/users — list all users (admin / developer)
router.get('/',
    authenticate,
    authorize('api'),
    dataAccessControl('pii', 'confidential'),
    auditLog('list_users'),
    async (req, res) => {
        const start = Date.now();
        try {
            const result = await pool.query(
                'SELECT id, name, email, role, created_at FROM users LIMIT 100'
            );
            dbQueryDuration.labels('select').observe((Date.now() - start) / 1000);

            const maskedFields = req.maskedFields || [];
            const users = result.rows.map(user => {
                const masked = { ...user };
                maskedFields.forEach(field => {
                    if (masked[field] !== undefined) masked[field] = '***MASKED***';
                });
                return masked;
            });

            res.json({ users, requestId: req.requestId });
        } catch (error) {
            logger.error('Database error', { error: error.message, requestId: req.requestId });
            res.status(500).json({ error: 'Database error', requestId: req.requestId });
        }
    }
);

// GET /api/v1/users/:id — single user
router.get('/:id',
    authenticate,
    authorize('api'),
    dataAccessControl('pii', 'confidential'),
    auditLog('get_user'),
    async (req, res) => {
        try {
            const result = await pool.query(
                'SELECT id, name, email, role, created_at FROM users WHERE id = $1',
                [req.params.id]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'User not found', requestId: req.requestId });
            }
            res.json({ user: result.rows[0], requestId: req.requestId });
        } catch (error) {
            logger.error('Database error', { error: error.message, requestId: req.requestId });
            res.status(500).json({ error: 'Database error', requestId: req.requestId });
        }
    }
);

// POST /api/v1/users — create user (admin only)
router.post('/',
    authenticate,
    authorize('api'),
    body('name').isString().trim().isLength({ min: 2, max: 100 }),
    body('email').isEmail().normalizeEmail(),
    body('role').isIn(['admin', 'developer', 'viewer']),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array(), requestId: req.requestId });
        }
        if (!req.user.roles.includes('admin')) {
            return res.status(403).json({ error: 'Admin access required', requestId: req.requestId });
        }

        try {
            const { name, email, role } = req.body;
            const result = await pool.query(
                'INSERT INTO users (name, email, role) VALUES ($1, $2, $3) RETURNING id, name, email, role, created_at',
                [name, email, role]
            );
            logger.info('User created', {
                createdBy: req.user.id,
                newUser: result.rows[0].id,
                requestId: req.requestId,
            });
            res.status(201).json({ user: result.rows[0], requestId: req.requestId });
        } catch (error) {
            if (error.code === '23505') {
                return res.status(409).json({ error: 'Email already exists', requestId: req.requestId });
            }
            res.status(500).json({ error: 'Database error', requestId: req.requestId });
        }
    }
);

module.exports = router;
