'use strict';

/**
 * Zero-Trust Backend Service — Entry Point
 *
 * Responsibilities of this file:
 *   1. Bootstrap Express with security and observability middleware
 *   2. Mount route modules
 *   3. Initialise the database schema
 *   4. Start listening
 *
 * Business logic lives in routes/; auth in middlewares/; infrastructure in services/.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

// Config (includes startup guards — will exit(1) if secrets missing)
const config = require('./config');

// Services
const pool = require('./services/database');
const logger = require('./services/logger');

// Middlewares
const { register, metricsMiddleware } = require('./middlewares/metrics');

// Routes
const usersRouter = require('./routes/users');
const productsRouter = require('./routes/products');
const ordersRouter = require('./routes/orders');
const adminRouter = require('./routes/admin');

// ── App setup ──────────────────────────────────────────────────────────────

const app = express();

app.use(helmet());
app.use(cors({ origin: ['http://localhost:3000', 'http://localhost:8000'], credentials: true }));
app.use(express.json({ limit: '10kb' }));

// Attach a unique request ID to every incoming request
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));
app.use(metricsMiddleware);

// ── Unprotected endpoints ──────────────────────────────────────────────────

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', service: config.serviceName });
  } catch {
    res.status(503).json({ status: 'unhealthy', error: 'Database connection failed' });
  }
});

app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// ── Protected API routes ───────────────────────────────────────────────────

app.use('/api/v1/users', usersRouter);
app.use('/api/v1/products', productsRouter);
app.use('/api/v1/orders', ordersRouter);
app.use('/api/v1', adminRouter);       // mounts /config and /audit

// ── Global error handler ───────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, requestId: req.requestId });
  res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

// ── Database init + server start ───────────────────────────────────────────

async function init() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id         SERIAL PRIMARY KEY,
        name       VARCHAR(100) NOT NULL,
        email      VARCHAR(255) UNIQUE NOT NULL,
        role       VARCHAR(50)  NOT NULL DEFAULT 'viewer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      INSERT INTO users (name, email, role) VALUES
        ('Admin User',     'admin@zerotrust.local',   'admin'),
        ('Developer User', 'dev@zerotrust.local',     'developer'),
        ('Viewer User',    'viewer@zerotrust.local',  'viewer')
      ON CONFLICT (email) DO NOTHING
    `);
    logger.info('Database initialised');
  } catch (error) {
    logger.error('Database init error', { error: error.message });
    // Non-fatal: service still starts; health check will surface DB issues.
  }

  app.listen(config.port, () => {
    logger.info('Backend service started', { port: config.port });
  });
}

init();

module.exports = app;
