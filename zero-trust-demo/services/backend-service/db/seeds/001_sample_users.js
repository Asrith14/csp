/**
 * Seed: 001 — Bootstrap sample users for development
 * Production seeds should never be auto-applied.
 * Run via: npx knex seed:run
 */

/** @param {import('knex').Knex} knex */
exports.seed = async function (knex) {
    await knex('users').insert([
        { name: 'Admin User', email: 'admin@zerotrust.local', role: 'admin' },
        { name: 'Developer User', email: 'dev@zerotrust.local', role: 'developer' },
        { name: 'Viewer User', email: 'viewer@zerotrust.local', role: 'viewer' },
    ]).onConflict('email').ignore();
};
