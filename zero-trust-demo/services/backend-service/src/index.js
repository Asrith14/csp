'use strict';

/**
 * Zero-Trust Backend Service — Entry Point
 *
 * Boot sequence (mirrors auth-service bootstrap pattern):
 *   1. Validate VAULT_TOKEN is present (fail fast — done in config/index.js).
 *   2. bootstrap(): fetch DB password from Vault, build connection string in
 *      memory, initialise the pg Pool via initDb().
 *   3. Start listening ONLY after the pool is ready.
 *
 * DATABASE_URL is NOT injected as an environment variable into this container.
 * The password never appears in docker inspect, crash dumps, or /proc/self/environ.
 *
 * Business logic lives in routes/; auth in middlewares/; infrastructure in services/.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

// Config (includes VAULT_TOKEN startup guard — will exit(1) if missing)
const config = require('./config');

// Services — initDb() called in bootstrap(), not here.
const { initDb } = require('./services/database');
const { getSecret } = require('./services/vault');
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
    // getPool() throws if boot hasn't completed — surface as 503.
    const { getPool } = require('./services/database');
    await getPool().query('SELECT 1');
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
app.use('/api/v1', adminRouter);  // mounts /config and /audit

// ── Global error handler ───────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, requestId: req.requestId });
  res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

// ── Bootstrap: fetch secrets → init DB → start server ─────────────────────

/**
 * Fetch the database password from Vault, construct the connection string
 * in memory, initialise the pg Pool, then start listening.
 *
 * The application never starts if Vault is unreachable or the secret is
 * absent — this is the intended "fail fast" behaviour.
 */
async function bootstrap() {
  logger.info('Fetching secrets from Vault...');

  let secrets;
  try {
    secrets = await getSecret('apps/backend-service');
  } catch (error) {
    logger.error('FATAL: Could not load secrets from Vault', { error: error.message });
    process.exit(1);
  }

  const dbPassword = secrets?.db_password;
  if (!dbPassword) {
    logger.error('FATAL: db_password not found in Vault at apps/backend-service');
    process.exit(1);
  }

  // Build the connection string purely in memory — never in an env var.
  const connectionString =
    `postgresql://${config.database.user}:${dbPassword}` +
    `@${config.database.host}:${config.database.port}/${config.database.name}`;

  logger.info('Initialising database pool...');
  initDb(connectionString);
  logger.info('Database pool ready.');

  // Schema is managed by Knex migrations (db-migrate init container).
  // Never run DDL here.

  app.listen(config.port, () => {
    logger.info('Backend service started', { port: config.port });
  });
}

bootstrap();

module.exports = app;
