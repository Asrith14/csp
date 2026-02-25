'use strict';

const promClient = require('prom-client');

const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestDuration = new promClient.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code'],
    registers: [register],
});

const dbQueryDuration = new promClient.Histogram({
    name: 'db_query_duration_seconds',
    help: 'Duration of database queries in seconds',
    labelNames: ['query_type'],
    registers: [register],
});

const policyDecisions = new promClient.Counter({
    name: 'policy_decisions_total',
    help: 'Total policy decisions',
    labelNames: ['result', 'policy'],
    registers: [register],
});

/**
 * Express middleware that records per-request HTTP duration.
 */
function metricsMiddleware(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        httpRequestDuration
            .labels(req.method, req.route?.path || req.path, res.statusCode)
            .observe((Date.now() - start) / 1000);
    });
    next();
}

module.exports = { register, metricsMiddleware, dbQueryDuration, policyDecisions };
