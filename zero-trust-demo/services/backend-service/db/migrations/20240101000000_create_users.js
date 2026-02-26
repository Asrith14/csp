/**
 * Migration: 001 — Create users table
 *
 * Run via:  npx knex migrate:latest
 * Rollback: npx knex migrate:rollback
 */

/** @param {import('knex').Knex} knex */
exports.up = async function (knex) {
    await knex.schema.createTableIfNotExists('users', (table) => {
        table.increments('id').primary();
        table.string('name', 100).notNullable();
        table.string('email', 255).notNullable().unique();
        table.enu('role', ['admin', 'developer', 'viewer']).notNullable().defaultTo('viewer');
        table.timestamp('created_at').defaultTo(knex.fn.now());
    });
};

/** @param {import('knex').Knex} knex */
exports.down = async function (knex) {
    await knex.schema.dropTableIfExists('users');
};
