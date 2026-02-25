'use strict';

const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool({
    connectionString: config.database.url,
    ...config.database.pool,
});

module.exports = pool;
