/**
 * Zero-Trust Backend Service
 * Demonstrates secure API with policy enforcement and data protection
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
const { body, validationResult } = require('express-validator');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;

// Configuration
const config = {
  keycloak: {
    url: process.env.KEYCLOAK_URL || 'http://keycloak:8080',
    realm: 'zero-trust'
  },
  vault: {
    addr: process.env.VAULT_ADDR || 'http://vault:8200',
    // Never fall back to a hardcoded token — fail loudly if not set.
    token: process.env.VAULT_TOKEN
  },
  opa: {
    url: process.env.OPA_URL || 'http://opa:8181'
  },
  database: {
    // Never fall back to hardcoded credentials — fail loudly if not set.
    url: process.env.DATABASE_URL
  },
  serviceName: process.env.SERVICE_NAME || 'backend-service'
};

// Guard: refuse to start if critical secrets are missing.
if (!config.vault.token) {
  console.error('FATAL: VAULT_TOKEN environment variable is not set.');
  process.exit(1);
}
if (!config.database.url) {
  console.error('FATAL: DATABASE_URL environment variable is not set.');
  process.exit(1);
}

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: config.serviceName },
  transports: [new winston.transports.Console()]
});

// Database connection
const pool = new Pool({
  connectionString: config.database.url,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const dbQueryDuration = new promClient.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of database queries',
  labelNames: ['query_type'],
  registers: [register]
});

const policyDecisions = new promClient.Counter({
  name: 'policy_decisions_total',
  help: 'Policy decisions',
  labelNames: ['result', 'policy'],
  registers: [register]
});

// JWKS client
const jwksClient = jwksRsa({
  jwksUri: `${config.keycloak.url}/realms/${config.keycloak.realm}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 600000
});

// Middleware
app.use(helmet());
app.use(cors({ origin: ['http://localhost:3000', 'http://localhost:8000'], credentials: true }));
app.use(express.json({ limit: '10kb' }));

// Request ID
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    httpRequestDuration.labels(req.method, req.route?.path || req.path, res.statusCode)
      .observe((Date.now() - start) / 1000);
  });
  next();
});

// ============================================
// Helper Functions
// ============================================

function getKey(header, callback) {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.publicKey || key.rsaPublicKey);
  });
}

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

async function checkPolicy(policy, input) {
  try {
    const response = await axios.post(
      `${config.opa.url}/v1/data/zerotrust/${policy}`,
      { input },
      {
        // 500ms max — authorization runs on every request.
        // A 5-second timeout will saturate the event loop under any real load.
        // In production, deploy OPA as a sidecar to eliminate the network hop entirely.
        timeout: 500
      }
    );
    const result = response.data.result;
    policyDecisions.labels(result?.allow ? 'allow' : 'deny', policy).inc();
    return result;
  } catch (error) {
    logger.error('Policy check error', { policy, error: error.message });
    policyDecisions.labels('error', policy).inc();
    // Fail closed: deny on any OPA error (timeout, unreachable, etc.)
    return { allow: false };
  }
}

async function getSecretFromVault(path) {
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

// Authentication middleware
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
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
      clearance_level: decoded.realm_access?.roles?.includes('admin') ? 3 :
        decoded.realm_access?.roles?.includes('developer') ? 2 : 1
    };
    next();
  } catch (error) {
    logger.warn('Auth failed', { error: error.message, requestId: req.requestId });
    return res.status(401).json({ error: 'Invalid token', requestId: req.requestId });
  }
}

// Authorization middleware with OPA
function authorize(resourceType = 'api') {
  return async (req, res, next) => {
    const policyResult = await checkPolicy('authz/decision', {
      user: req.user,
      resource: {
        type: resourceType,
        path: req.path,
        method: req.method
      },
      context: {
        ip: req.ip,
        user_agent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
        request_id: req.requestId
      }
    });

    if (!policyResult.allow) {
      logger.warn('Access denied', {
        user: req.user.id,
        path: req.path,
        reasons: policyResult.reasons,
        requestId: req.requestId
      });
      return res.status(403).json({
        error: 'Access denied',
        reasons: policyResult.reasons,
        requestId: req.requestId
      });
    }

    // Attach audit requirement to request
    req.requiresAudit = policyResult.audit;
    next();
  };
}

// Data access control middleware
function dataAccessControl(dataType, classification) {
  return async (req, res, next) => {
    const policyResult = await checkPolicy('data/decision', {
      user: {
        ...req.user,
        department: 'engineering' // Would come from user profile
      },
      data: {
        type: dataType,
        classification: classification,
        owner_department: 'engineering',
        fields: req.body?.fields || ['id', 'name', 'email']
      },
      action: req.method === 'GET' ? 'read' : 'write',
      purpose: req.headers['x-access-purpose'] || 'system_maintenance'
    });

    if (!policyResult.allow) {
      return res.status(403).json({
        error: 'Data access denied',
        requestId: req.requestId
      });
    }

    req.maskedFields = policyResult.masked_fields || [];
    req.requiresAudit = policyResult.requires_audit;
    next();
  };
}

// Audit logging
function auditLog(action) {
  return (req, res, next) => {
    if (req.requiresAudit) {
      logger.info('AUDIT', {
        action,
        user: req.user.id,
        resource: req.path,
        method: req.method,
        ip: req.ip,
        requestId: req.requestId,
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
}

// ============================================
// Routes
// ============================================

// Health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', service: config.serviceName });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: 'Database connection failed' });
  }
});

// Metrics
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// ============================================
// API v1 Routes (Protected)
// ============================================

// Get all users (admin/developer only)
app.get('/api/v1/users',
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

      // Apply field masking based on policy
      const maskedFields = req.maskedFields || [];
      const users = result.rows.map(user => {
        const masked = { ...user };
        if (Array.isArray(maskedFields)) {
          maskedFields.forEach(field => {
            if (masked[field]) masked[field] = '***MASKED***';
          });
        }
        return masked;
      });

      res.json({ users, requestId: req.requestId });
    } catch (error) {
      logger.error('Database error', { error: error.message, requestId: req.requestId });
      res.status(500).json({ error: 'Database error', requestId: req.requestId });
    }
  }
);

// Get single user
app.get('/api/v1/users/:id',
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
      res.status(500).json({ error: 'Database error', requestId: req.requestId });
    }
  }
);

// Create user (admin only)
app.post('/api/v1/users',
  authenticate,
  authorize('api'),
  [
    body('name').isString().trim().isLength({ min: 2, max: 100 }),
    body('email').isEmail().normalizeEmail(),
    body('role').isIn(['admin', 'developer', 'viewer'])
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array(), requestId: req.requestId });
    }

    // Check if user has admin role
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
        requestId: req.requestId
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

// Products endpoint (example business data)
app.get('/api/v1/products',
  authenticate,
  authorize('api'),
  dataAccessControl('business', 'internal'),
  async (req, res) => {
    // Simulated products data
    const products = [
      { id: 1, name: 'Product A', price: 99.99, stock: 100 },
      { id: 2, name: 'Product B', price: 149.99, stock: 50 },
      { id: 3, name: 'Product C', price: 199.99, stock: 25 }
    ];

    res.json({ products, requestId: req.requestId });
  }
);

// Orders endpoint
app.get('/api/v1/orders',
  authenticate,
  authorize('api'),
  dataAccessControl('business', 'confidential'),
  auditLog('list_orders'),
  async (req, res) => {
    // Simulated orders data
    const orders = [
      { id: 'ORD-001', customer: 'Customer A', total: 299.99, status: 'completed' },
      { id: 'ORD-002', customer: 'Customer B', total: 149.99, status: 'pending' }
    ];

    res.json({ orders, requestId: req.requestId });
  }
);

// Admin-only configuration endpoint
app.get('/api/v1/config',
  authenticate,
  authorize('api'),
  async (req, res) => {
    if (!req.user.roles.includes('admin')) {
      return res.status(403).json({ error: 'Admin access required', requestId: req.requestId });
    }

    try {
      // Get config from Vault
      const secrets = await getSecretFromVault('apps/api-keys');
      res.json({
        config: {
          feature_flags: { dark_mode: true, beta_features: false },
          api_version: 'v1',
          // Don't expose actual secrets, just confirmation they exist
          secrets_loaded: Object.keys(secrets).length > 0
        },
        requestId: req.requestId
      });
    } catch (error) {
      res.status(500).json({ error: 'Config error', requestId: req.requestId });
    }
  }
);

// Audit logs (admin only)
app.get('/api/v1/audit',
  authenticate,
  authorize('api'),
  async (req, res) => {
    if (!req.user.roles.includes('admin')) {
      return res.status(403).json({ error: 'Admin access required', requestId: req.requestId });
    }

    // Return audit summary (actual logs would come from SIEM)
    res.json({
      audit: {
        total_requests_today: 1250,
        failed_auth_attempts: 12,
        policy_denials: 5,
        sensitive_data_access: 45
      },
      requestId: req.requestId
    });
  }
);

// Error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, requestId: req.requestId });
  res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

// Initialize database and start server
async function init() {
  try {
    // Create tables if not exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'viewer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert sample data
    await pool.query(`
      INSERT INTO users (name, email, role) VALUES
        ('Admin User', 'admin@zerotrust.local', 'admin'),
        ('Developer User', 'dev@zerotrust.local', 'developer'),
        ('Viewer User', 'viewer@zerotrust.local', 'viewer')
      ON CONFLICT (email) DO NOTHING
    `);

    logger.info('Database initialized');
  } catch (error) {
    logger.error('Database init error', { error: error.message });
  }

  app.listen(PORT, () => {
    logger.info(`Backend service started`, { port: PORT });
  });
}

init();

module.exports = app;
