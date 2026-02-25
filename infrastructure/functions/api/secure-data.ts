import {
    SecretsManagerClient,
    GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import type {
    APIGatewayProxyEvent,
    APIGatewayProxyResult,
} from 'aws-lambda';

const secretsClient = new SecretsManagerClient({});

const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, extra?: Record<string, unknown>) => {
    console.log(JSON.stringify({ level, message, ...extra }));
};

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    log('INFO', 'Processing secure-data request', {
        requestId: event.requestContext.requestId,
        path: event.path,
        sourceIp: event.requestContext.identity.sourceIp,
    });

    const claims = event.requestContext.authorizer?.claims as Record<string, string> | undefined;

    if (!claims) {
        // Defense-in-depth: Authorizer should have already blocked this
        return {
            statusCode: 401,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: 'Unauthorized' }),
        };
    }

    const secretName = process.env.SECRET_NAME;
    let secretInfo = 'Not configured';

    if (secretName) {
        try {
            const response = await secretsClient.send(
                new GetSecretValueCommand({ SecretId: secretName }),
            );
            if (response.SecretString) {
                const secret = JSON.parse(response.SecretString) as Record<string, string>;
                secretInfo = `Retrieved credentials for user: ${secret.username}`;
            }
        } catch (err) {
            // A failed Secrets Manager call is a critical backend dependency failure.
            // Return 500 — never return 200 OK when the system cannot fulfil the request.
            log('ERROR', 'Failed to retrieve secret', { secretName, error: String(err) });
            return {
                statusCode: 500,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'Internal Server Error' }),
            };
        }
    }

    return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            message: 'OK',
            user: claims['email'] ?? claims['cognito:username'],
            data: {
                secretInfo,
                timestamp: new Date().toISOString(),
            },
        }),
    };
};
