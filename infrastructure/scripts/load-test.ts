/**
 * Load Test Script
 *
 * Sends rapid sequential GET requests to trigger WAF rate limiting (100 req / 5 min).
 * WAF blocks returns 403; throttling may also return 429.
 *
 * Usage:
 *   API_URL=https://<api-id>.execute-api.<region>.amazonaws.com/prod npx ts-node scripts/load-test.ts
 */

const API_URL = process.env.API_URL;
const REQUEST_COUNT = 150;
const DELAY_MS = 100;

if (!API_URL) {
    console.error('❌  Missing required env var: API_URL');
    process.exit(1);
}

const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

async function runLoadTest(): Promise<void> {
    console.log(`\nLoad Test → ${API_URL}`);
    console.log(`Sending ${REQUEST_COUNT} requests (${DELAY_MS}ms apart)\n`);

    let blocked = 0;
    let authorized = 0;

    for (let i = 0; i < REQUEST_COUNT; i++) {
        const res = await fetch(`${API_URL}/secure-data`, { method: 'GET' });
        const status = res.status;

        process.stdout.write(`${status} `);
        if ((i + 1) % 10 === 0) console.log('');

        if (status === 403 || status === 429) blocked++;
        else authorized++;

        await sleep(DELAY_MS);
    }

    console.log('\n\n--- Results ---');
    console.log(`Total:      ${REQUEST_COUNT}`);
    console.log(`Blocked:    ${blocked}  (403/429)`);
    console.log(`Passed:     ${authorized}  (200/401)`);

    if (blocked > 0) {
        console.log('\n✅  Rate limiting is active.');
    } else {
        console.warn('\n⚠️  No requests blocked — threshold not reached or WAF not active.');
    }
}

runLoadTest().catch((err: unknown) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
