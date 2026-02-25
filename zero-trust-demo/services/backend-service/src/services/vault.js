'use strict';

const axios = require('axios');
const config = require('../config');
const logger = require('./logger');

/**
 * Retrieve a secret from HashiCorp Vault KV v2.
 * @param {string} path - The secret path (e.g. 'apps/api-keys')
 * @returns {Promise<Record<string, string>>}
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

module.exports = { getSecret };
