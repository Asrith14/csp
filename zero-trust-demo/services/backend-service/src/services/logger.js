'use strict';

const winston = require('winston');
const config = require('../config');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: config.serviceName },
    transports: [new winston.transports.Console()],
});

module.exports = logger;
