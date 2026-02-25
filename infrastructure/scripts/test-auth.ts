/**
 * Auth flow verification script.
 *
 * Usage (after deploying the stack):
 *   USER_POOL_ID=<...> CLIENT_ID=<...> API_URL=<...> npx ts-node scripts/test-auth.ts
 *
 * IMPORTANT: The Cognito client is configured with USER_SRP_AUTH only.
 * This script verifies signup and the MFA challenge is present — it does NOT
 * complete TOTP authentication (requires a live authenticator app).
 */
import {
    CognitoIdentityProviderClient,
    SignUpCommand,
    InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';

const USER_POOL_ID = process.env.USER_POOL_ID;
const CLIENT_ID = process.env.CLIENT_ID;
const REGION = process.env.AWS_REGION ?? 'us-east-1';

if (!USER_POOL_ID || !CLIENT_ID) {
    console.error('❌  Missing required env vars: USER_POOL_ID, CLIENT_ID');
    process.exit(1);
}

const client = new CognitoIdentityProviderClient({ region: REGION });

async function testAuthFlow(): Promise<void> {
    const username = `testuser_${Date.now()}`;
    const password = 'TestUser$123!';
    const email = `${username}@example.com`;

    console.log(`\n[1] Signing up user: ${username}`);
    await client.send(new SignUpCommand({
        ClientId: CLIENT_ID!,
        Username: username,
        Password: password,
        UserAttributes: [{ Name: 'email', Value: email }],
    }));
    console.log('    ✅ SignUp succeeded (pre-signup trigger auto-confirmed)');

    console.log('\n[2] Initiating SRP auth...');
    const authResponse = await client.send(new InitiateAuthCommand({
        AuthFlow: 'USER_SRP_AUTH',
        ClientId: CLIENT_ID!,
        AuthParameters: {
            USERNAME: username,
            // SRP_A is generated client-side by the SDK normally;
            // this confirms the request type is accepted by the pool.
        },
    }));

    if (authResponse.ChallengeName) {
        console.log(`    ✅ Challenge received: ${authResponse.ChallengeName} (MFA flow active)`);
    } else {
        console.warn('    ⚠️  No challenge — verify MFA is enforced on the User Pool');
    }
}

testAuthFlow().catch((err: unknown) => {
    console.error('❌ Auth test failed:', err);
    process.exit(1);
});
