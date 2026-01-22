/**
 * Zero-Trust Auth Service
 * Handles authentication, token validation, and policy decisions
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

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  keycloak: {
    url: process.env.KEYCLOAK_URL || 'http://keycloak:8080',
    realm: 'zero-trust',
    clientId: 'auth-service',
    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET || 'auth-service-secret-2024'
  },
  vault: {
    addr: process.env.VAULT_ADDR || 'http://vault:8200',
    token: process.env.VAULT_TOKEN || 'root-token-zero-trust'
  },
  opa: {
    url: process.env.OPA_URL || 'http://opa:8181'
  },
  serviceName: process.env.SERVICE_NAME || 'auth-service'
};

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: config.serviceName },
  transports: [
    new winston.transports.Console()
  ]
});

// Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const authAttempts = new promClient.Counter({
  name: 'auth_attempts_total',
  help: 'Total authentication attempts',
  labelNames: ['status', 'type'],
  registers: [register]
});

const policyDecisions = new promClient.Counter({
  name: 'policy_decisions_total',
  help: 'Total policy decisions',
  labelNames: ['result', 'policy'],
  registers: [register]
});

// JWKS client for Keycloak token validation
const jwksClient = jwksRsa({
  jwksUri: `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 600000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10
});

// Middleware
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
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}));

app.use(cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

// Request ID middleware
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

// Logging middleware
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    httpRequestDuration.labels(req.method, req.route?.path || req.path, res.statusCode).observe(duration);
  });
  next();
});

// ============================================
// Helper Functions
// ============================================

// Get signing key from JWKS
function getKey(header, callback) {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Verify JWT token
async function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      algorithms: ['RS256'],
      // Accept both internal Docker hostname and localhost issuer
      issuer: [
        `${config.keycloak.url}/realms/${config.keycloak.realm}`,
        `http://localhost:8080/realms/${config.keycloak.realm}`
      ]
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

// Get secrets from Vault
async function getSecret(path) {
  try {
    const response = await axios.get(
      `${config.vault.addr}/v1/secret/data/${path}`,
      {
        headers: { 'X-Vault-Token': config.vault.token }
      }
    );
    return response.data.data.data;
  } catch (error) {
    logger.error('Vault error', { path, error: error.message });
    throw error;
  }
}

// Check authorization with OPA
async function checkAuthorization(input) {
  try {
    const response = await axios.post(
      `${config.opa.url}/v1/data/zerotrust/authz/allow`,
      { input },
      { timeout: 5000 }
    );
    policyDecisions.labels(response.data.result ? 'allow' : 'deny', 'authz').inc();
    return response.data.result;
  } catch (error) {
    logger.error('OPA error', { error: error.message });
    policyDecisions.labels('error', 'authz').inc();
    return false; // Fail closed
  }
}

// Authentication middleware
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    authAttempts.labels('failed', 'missing_token').inc();
    return res.status(401).json({
      error: 'Authentication required',
      requestId: req.requestId
    });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = await verifyToken(token);
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.realm_access?.roles || [],
      groups: decoded.groups || [],
      name: decoded.name
    };
    authAttempts.labels('success', 'jwt').inc();
    next();
  } catch (error) {
    logger.warn('Token verification failed', {
      error: error.message,
      requestId: req.requestId
    });
    authAttempts.labels('failed', 'invalid_token').inc();
    return res.status(401).json({
      error: 'Invalid token',
      requestId: req.requestId
    });
  }
}

// Authorization middleware
function authorize(requiredRoles = []) {
  return async (req, res, next) => {
    const input = {
      user: req.user,
      resource: {
        type: 'api',
        path: req.path,
        method: req.method
      },
      context: {
        ip: req.ip,
        user_agent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
        request_id: req.requestId
      }
    };

    const allowed = await checkAuthorization(input);

    if (!allowed) {
      logger.warn('Authorization denied', {
        user: req.user.id,
        path: req.path,
        requestId: req.requestId
      });
      return res.status(403).json({
        error: 'Access denied',
        requestId: req.requestId
      });
    }

    // Additional role check if specified
    if (requiredRoles.length > 0) {
      const hasRole = requiredRoles.some(role => req.user.roles.includes(role));
      if (!hasRole) {
        return res.status(403).json({
          error: 'Insufficient permissions',
          requestId: req.requestId
        });
      }
    }

    next();
  };
}

// ============================================
// Routes
// ============================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: config.serviceName,
    timestamp: new Date().toISOString()
  });
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// Login - Exchange credentials for tokens
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    authAttempts.labels('failed', 'missing_credentials').inc();
    return res.status(400).json({
      error: 'Username and password required',
      requestId: req.requestId
    });
  }

  try {
    const tokenResponse = await axios.post(
      `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'password',
        client_id: config.keycloak.clientId,
        client_secret: config.keycloak.clientSecret,
        username,
        password,
        scope: 'openid profile email roles'
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    logger.info('Login successful', { username, requestId: req.requestId });
    authAttempts.labels('success', 'login').inc();

    res.json({
      access_token: tokenResponse.data.access_token,
      refresh_token: tokenResponse.data.refresh_token,
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in
    });
  } catch (error) {
    logger.warn('Login failed', {
      username,
      error: error.response?.data?.error_description || error.message,
      requestId: req.requestId
    });
    authAttempts.labels('failed', 'login').inc();

    res.status(401).json({
      error: 'Invalid credentials',
      requestId: req.requestId
    });
  }
});

// Refresh token
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: 'Refresh token required',
      requestId: req.requestId
    });
  }

  try {
    const tokenResponse = await axios.post(
      `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: config.keycloak.clientId,
        client_secret: config.keycloak.clientSecret,
        refresh_token
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    authAttempts.labels('success', 'refresh').inc();
    res.json({
      access_token: tokenResponse.data.access_token,
      refresh_token: tokenResponse.data.refresh_token,
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in
    });
  } catch (error) {
    logger.warn('Token refresh failed', {
      error: error.response?.data?.error_description || error.message,
      requestId: req.requestId
    });
    authAttempts.labels('failed', 'refresh').inc();

    res.status(401).json({
      error: 'Invalid refresh token',
      requestId: req.requestId
    });
  }
});

// Validate token
app.post('/auth/validate', authenticate, (req, res) => {
  res.json({
    valid: true,
    user: req.user,
    requestId: req.requestId
  });
});

// Get user profile (protected)
app.get('/auth/profile', authenticate, authorize(), (req, res) => {
  res.json({
    user: req.user,
    requestId: req.requestId
  });
});

// Logout
app.post('/auth/logout', authenticate, async (req, res) => {
  const { refresh_token } = req.body;

  try {
    if (refresh_token) {
      await axios.post(
        `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/logout`,
        new URLSearchParams({
          client_id: config.keycloak.clientId,
          client_secret: config.keycloak.clientSecret,
          refresh_token
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }
      );
    }

    logger.info('Logout successful', { user: req.user.id, requestId: req.requestId });
    res.json({
      message: 'Logged out successfully',
      requestId: req.requestId
    });
  } catch (error) {
    logger.error('Logout error', {
      error: error.message,
      requestId: req.requestId
    });
    res.status(500).json({
      error: 'Logout failed',
      requestId: req.requestId
    });
  }
});

// Policy check endpoint (for other services)
app.post('/auth/policy/check', authenticate, authorize(['admin', 'service-account']), async (req, res) => {
  const { policy, input } = req.body;

  try {
    const response = await axios.post(
      `${config.opa.url}/v1/data/zerotrust/${policy}`,
      { input },
      { timeout: 5000 }
    );

    res.json({
      result: response.data.result,
      requestId: req.requestId
    });
  } catch (error) {
    logger.error('Policy check failed', {
      policy,
      error: error.message,
      requestId: req.requestId
    });
    res.status(500).json({
      error: 'Policy check failed',
      requestId: req.requestId
    });
  }
});

// Error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    requestId: req.requestId
  });

  res.status(500).json({
    error: 'Internal server error',
    requestId: req.requestId
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Auth service started`, { port: PORT });
});

module.exports = app;
