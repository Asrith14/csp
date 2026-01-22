import * as AWS from 'aws-sdk';
// NOTE: This script is for post-deployment verification
// It requires AWS Credentials to be configured in the environment

const cognito = new AWS.CognitoIdentityServiceProvider({ region: process.env.AWS_REGION });
// Replace these with actual values from CDK Output after deployment
const USER_POOL_ID = 'REPLACE_ME';
const CLIENT_ID = 'REPLACE_ME';
const API_URL = 'REPLACE_ME';

async function testAuthFlow() {
    const username = `testuser_${Date.now()}`;
    const password = 'TestUser123!';
    const email = `${username}@example.com`;

    console.log(`1. Creating user: ${username}`);
    try {
        await cognito.signUp({
            ClientId: CLIENT_ID,
            Username: username,
            Password: password,
            UserAttributes: [{ Name: 'email', Value: email }],
        }).promise();
        console.log('   User signed up.');

        // Simulating Admin Confirmation (since we haven't set up email for this demo)
        // In real flow, user gets code. For demo, we might need Admin privileges or manual verify
        // But since we built a pre-signup trigger, it might be auto-confirmed?
        // Let's assume manual confirmation for robust test or try to login

        console.log('   Attempting login...');
        const authResult = await cognito.initiateAuth({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: CLIENT_ID,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            },
        }).promise();

        if (authResult.ChallengeName === 'MFA_SETUP') {
            console.log('   MFA Setup Required (Good!)');
            // We stop here for the script as handling MFA setup programmatically requires TOTP generation
            // This confirms Day 2 MFA requirement
        } else {
            console.log('   Logged in (No MFA? Check config)');
        }

    } catch (err) {
        console.error('Error during test:', err);
    }
}

testAuthFlow();
