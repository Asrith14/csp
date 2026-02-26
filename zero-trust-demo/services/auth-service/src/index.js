'use strict';

/**
 * Zero-Trust Auth Service
 *
 * Boot sequence:
 *   1. Validate required environment variables — crash-loop if missing (fail fast).
 *   2. Fetch KEYCLOAK_CLIENT_SECRET from HashiCorp Vault.
 *   3. Start listening only after secrets are in memory.
 *
 * This ensures the process never silently starts with a hardcoded fallback.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const promClient = require('prom-client');
const winston = require('winston');

// ── Fail-fast guards ───────────────────────────────────────────────────────
// No fallback secrets. If a variable is missing, crash immediately.
const REQUIRED_ENV = ['VAULT_TOKEN', 'VAULT_ADDR', 'KEYCLOAK_URL'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`FATAL: Required environment variable ${key} is not set. Exiting.`);
    process.exit(1);
  }
}

// ── Static config (non-secret) ─────────────────────────────────────────────
const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  keycloak: {
    url: process.env.KEYCLOAK_URL,
    realm: 'zero-trust',
    clientId: 'auth-service',
    // clientSecret is populated by Vault at startup — see bootstrap() below.
    clientSecret: null,
  },
  vault: {
    addr: process.env.VAULT_ADDR,
    token: process.env.VAULT_TOKEN,
  },
  opa: {
    // OPA runs as a sidecar — localhost call, sub-millisecond authz.
    url: process.env.OPA_URL || 'http://localhost:8181',
  },
  serviceName: process.env.SERVICE_NAME || 'auth-service',
};

// ── Logger ─────────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: config.serviceName },
  transports: [new winston.transports.Console()],
});

// ── Prometheus metrics ─────────────────────────────────────────────────────
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

const authAttempts = new promClient.Counter({
  name: 'auth_attempts_total',
  help: 'Total authentication attempts',
  labelNames: ['status', 'type'],
  registers: [register],
});

const policyDecisions = new promClient.Counter({
  name: 'policy_decisions_total',
  help: 'Total policy decisions',
  labelNames: ['result', 'policy'],
  registers: [register],
});

// ── JWKS client ────────────────────────────────────────────────────────────
const jwksClient = jwksRsa({
  jwksUri: `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 600_000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

// ── Express app ────────────────────────────────────────────────────────────
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(cors({ origin: ['http://localhost:3000'], credentials: true }));
app.use(express.json({ limit: '10kb' }));

// Attach unique request ID
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// Prometheus HTTP duration
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    httpRequestDuration
      .labels(req.method, req.route?.path || req.path, res.statusCode)
      .observe((Date.now() - start) / 1000);
  });
  next();
});

// ── Helper functions ───────────────────────────────────────────────────────

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
 * Fetch a secret from HashiCorp Vault KV v2.
 * Called during bootstrap — not during request handling.
 * @param {string} path — e.g. 'apps/auth-service'
 */
async function getSecret(path) {
  try {
    const response = await axios.get(
      `${config.vault.addr}/v1/secret/data/${path}`,
      { headers: { 'X-Vault-Token': config.vault.token } }
    );
    return response.data.data.data;
  } catch (error) {
    logger.error('Vault error', { path, error: error.message });
    throw error;
  }
}

/**
 * OPA authorization check.
 * Timeout is 500ms — fail closed on any degradation.
 * OPA runs as a sidecar (localhost), so network latency is negligible.
 */
async function checkAuthorization(input) {
  try {
    const response = await axios.post(
      `${config.opa.url}/v1/data/zerotrust/authz/allow`,
      { input },
      { timeout: 500 }  // 500ms max — authz on the critical path must be fast
    );
    policyDecisions.labels(response.data.result ? 'allow' : 'deny', 'authz').inc();
    return response.data.result;
  } catch (error) {
    logger.error('OPA error', { error: error.message });
    policyDecisions.labels('error', 'authz').inc();
    return false; // Fail closed
  }
}

// ── Auth middleware ────────────────────────────────────────────────────────

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    authAttempts.labels('failed', 'missing_token').inc();
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
    };
    authAttempts.labels('success', 'jwt').inc();
    next();
  } catch (error) {
    logger.warn('Token verification failed', { error: error.message, requestId: req.requestId });
    authAttempts.labels('failed', 'invalid_token').inc();
    return res.status(401).json({ error: 'Invalid token', requestId: req.requestId });
  }
}

function authorize(requiredRoles = []) {
  return async (req, res, next) => {
    const input = {
      user: req.user,
      resource: { type: 'api', path: req.path, method: req.method },
      context: {
        ip: req.ip, user_agent: req.headers['user-agent'],
        timestamp: new Date().toISOString(), request_id: req.requestId
      },
    };

    const allowed = await checkAuthorization(input);

    if (!allowed) {
      logger.warn('Authorization denied', { user: req.user.id, path: req.path, requestId: req.requestId });
      return res.status(403).json({ error: 'Access denied', requestId: req.requestId });
    }

    if (requiredRoles.length > 0 && !requiredRoles.some(r => req.user.roles.includes(r))) {
      return res.status(403).json({ error: 'Insufficient permissions', requestId: req.requestId });
    }

    next();
  };
}

// ── Routes ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: config.serviceName, timestamp: new Date().toISOString() });
});

app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// POST /auth/login — exchange credentials for tokens
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    authAttempts.labels('failed', 'missing_credentials').inc();
    return res.status(400).json({ error: 'Username and password required', requestId: req.requestId });
  }

  try {
    const tokenResponse = await axios.post(
      `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'password',
        client_id: config.keycloak.clientId,
        client_secret: config.keycloak.clientSecret,   // fetched from Vault at boot
        username,
        password,
        scope: 'openid profile email roles',
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    logger.info('Login successful', { username, requestId: req.requestId });
    authAttempts.labels('success', 'login').inc();

    res.json({
      access_token: tokenResponse.data.access_token,
      refresh_token: tokenResponse.data.refresh_token,
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in,
    });
  } catch (error) {
    logger.warn('Login failed', { username, error: error.response?.data?.error_description || error.message, requestId: req.requestId });
    authAttempts.labels('failed', 'login').inc();
    res.status(401).json({ error: 'Invalid credentials', requestId: req.requestId });
  }
});

// POST /auth/refresh
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'Refresh token required', requestId: req.requestId });
  }

  try {
    const tokenResponse = await axios.post(
      `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: config.keycloak.clientId,
        client_secret: config.keycloak.clientSecret,   // fetched from Vault at boot
        refresh_token,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    authAttempts.labels('success', 'refresh').inc();
    res.json({
      access_token: tokenResponse.data.access_token,
      refresh_token: tokenResponse.data.refresh_token,
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in,
    });
  } catch (error) {
    logger.warn('Token refresh failed', { error: error.response?.data?.error_description || error.message, requestId: req.requestId });
    authAttempts.labels('failed', 'refresh').inc();
    res.status(401).json({ error: 'Invalid refresh token', requestId: req.requestId });
  }
});

// POST /auth/validate
app.post('/auth/validate', authenticate, (req, res) => {
  res.json({ valid: true, user: req.user, requestId: req.requestId });
});

// GET /auth/profile
app.get('/auth/profile', authenticate, authorize(), (req, res) => {
  res.json({ user: req.user, requestId: req.requestId });
});

// POST /auth/logout
app.post('/auth/logout', authenticate, async (req, res) => {
  const { refresh_token } = req.body;

  try {
    if (refresh_token) {
      await axios.post(
        `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/logout`,
        new URLSearchParams({
          client_id: config.keycloak.clientId,
          client_secret: config.keycloak.clientSecret,
          refresh_token,
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
    }

    logger.info('Logout successful', { user: req.user.id, requestId: req.requestId });
    res.json({ message: 'Logged out successfully', requestId: req.requestId });
  } catch (error) {
    logger.error('Logout error', { error: error.message, requestId: req.requestId });
    res.status(500).json({ error: 'Logout failed', requestId: req.requestId });
  }
});

// POST /auth/policy/check
app.post('/auth/policy/check', authenticate, authorize(['admin', 'service-account']), async (req, res) => {
  const { policy, input } = req.body;

  try {
    const response = await axios.post(
      `${config.opa.url}/v1/data/zerotrust/${policy}`,
      { input },
      { timeout: 500 }  // same 500ms limit as all OPA calls
    );
    res.json({ result: response.data.result, requestId: req.requestId });
  } catch (error) {
    logger.error('Policy check failed', { policy, error: error.message, requestId: req.requestId });
    res.status(500).json({ error: 'Policy check failed', requestId: req.requestId });
  }
});

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, requestId: req.requestId });
  res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

// ── Bootstrap: fetch secrets, then start ──────────────────────────────────
/**
 * Fetch the Keycloak client secret from Vault before the server starts
 * accepting traffic. If Vault is unreachable the process crashes (fail fast).
 */
async function bootstrap() {
  logger.info('Fetching secrets from Vault...');

  try {
    const secrets = await getSecret('apps/auth-service');
    config.keycloak.clientSecret = secrets.keycloak_client_secret;

    if (!config.keycloak.clientSecret) {
      logger.error('FATAL: keycloak_client_secret not found in Vault at apps/auth-service');
      process.exit(1);
    }

    logger.info('Secrets loaded from Vault successfully');
  } catch (error) {
    logger.error('FATAL: Could not load secrets from Vault', { error: error.message });
    process.exit(1);
  }

  // Only start listening after all secrets are in memory.
  app.listen(config.port, () => {
    logger.info('Auth service started', { port: config.port });
  });
}

bootstrap();

module.exports = app;
