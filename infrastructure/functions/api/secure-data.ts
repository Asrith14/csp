// aws-sdk provided by Lambda runtime
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

export const handler = async (event: any) => {
    console.log(JSON.stringify({
        level: 'INFO',
        message: 'Processing secure-data request',
        requestId: event.requestContext?.requestId,
        path: event.path,
        sourceIp: event.requestContext?.identity?.sourceIp
    }));

    // Day 3: Claims Validation
    // The Authorizer verification happens at the Gateway, but we can inspect claims here
    const claims = event.requestContext?.authorizer?.claims;

    if (!claims) {
        // This should theoretically be blocked by API Gateway Authorizer before reaching here
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Unauthorized: No claims found' }),
        };
    }

    // Day 4: Retrieve Secret
    let secretValue = 'Not Found';
    const secretName = process.env.SECRET_NAME;

    if (secretName) {
        try {
            const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
            if (data.SecretString) {
                // In a real app, we would parse this JSON and use the credentials
                const secret = JSON.parse(data.SecretString);
                secretValue = `Retrieved user: ${secret.username} (Password hidden)`;
            }
        } catch (err) {
            console.error('Error retrieving secret:', err);
            secretValue = 'Error retrieving secret';
        }
    }

    // Business Logic
    return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            message: 'Secure Data Retrieved Successfully',
            user: claims.email || claims.username,
            role: 'AuthenticatedUser', // Validation simplified for demo
            data: {
                secretInfo: secretValue,
                timestamp: new Date().toISOString(),
            },
        }),
    };
};
