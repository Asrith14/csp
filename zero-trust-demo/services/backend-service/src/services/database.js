'use strict';

const { Pool } = require('pg');

/**
 * Module-level pool reference, populated by initDb().
 * Routes import this module and call pool() to get the active instance.
 * Accessing it before bootstrap completes will throw — intentional fail-fast.
 */
let _pool = null;

/**
 * Initialize the database connection pool.
 * Must be called once in bootstrap() BEFORE app.listen().
 *
 * @param {string} connectionString - Built in memory from Vault secrets.
 *   Never sourced from an environment variable in the long-running process.
 * @returns {import('pg').Pool}
 */
function initDb(connectionString) {
    _pool = new Pool({
        connectionString,
        max: 10,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 2_000,
    });
    return _pool;
}

/**
 * Returns the active Pool. Throws if initDb() has not been called yet.
 */
function getPool() {
    if (!_pool) {
        throw new Error('Database pool not initialized. Call initDb() in bootstrap() first.');
    }
    return _pool;
}

module.exports = { initDb, getPool };
