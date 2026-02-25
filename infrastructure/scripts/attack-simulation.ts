/**
 * Attack Simulation Script
 *
 * Simulates SQLi, XSS, and unauthorized access to validate WAF and Cognito Authorizer.
 * Expected results:
 *   - SQLi / XSS payloads → 403 (WAF block)
 *   - No token           → 401 (Cognito Authorizer rejection)
 *
 * Usage:
 *   API_URL=https://<api-id>.execute-api.<region>.amazonaws.com/prod npx ts-node scripts/attack-simulation.ts
 */

const API_URL = process.env.API_URL;

if (!API_URL) {
    console.error('❌  Missing required env var: API_URL');
    process.exit(1);
}

type TestCase = {
    name: string;
    method: 'GET' | 'POST';
    body?: Record<string, unknown>;
    expectedStatus: number;
};

const tests: TestCase[] = [
    {
        name: 'SQL Injection',
        method: 'POST',
        body: { data: "' OR 1=1 --" },
        expectedStatus: 403,
    },
    {
        name: 'XSS Payload',
        method: 'POST',
        body: { data: "<script>alert('XSS')</script>" },
        expectedStatus: 403,
    },
    {
        name: 'No Auth Token',
        method: 'GET',
        expectedStatus: 401,
    },
];

async function runAttackSimulation(): Promise<void> {
    console.log(`\nAttack Simulation → ${API_URL}\n`);
    let passed = 0;

    for (const test of tests) {
        process.stdout.write(`  [${test.name}] `);
        const res = await fetch(`${API_URL}/secure-data`, {
            method: test.method,
            headers: test.body ? { 'Content-Type': 'application/json' } : undefined,
            body: test.body ? JSON.stringify(test.body) : undefined,
        });

        if (res.status === test.expectedStatus) {
            console.log(`✅  ${res.status} (expected ${test.expectedStatus})`);
            passed++;
        } else {
            console.log(`❌  ${res.status} (expected ${test.expectedStatus})`);
        }
    }

    console.log(`\nResult: ${passed}/${tests.length} tests passed.\n`);
    if (passed < tests.length) process.exit(1);
}

runAttackSimulation().catch((err: unknown) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
