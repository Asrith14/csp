// @ts-check
/** @type {import('knex').Knex.Config} */
module.exports = {
    client: 'pg',
    connection: process.env.DATABASE_URL,
    migrations: {
        directory: './db/migrations',
        tableName: 'knex_migrations',
    },
    seeds: {
        directory: './db/seeds',
    },
};
