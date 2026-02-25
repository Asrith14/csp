import { handler } from '../../functions/api/secure-data';

// Define mock instances variables
const mockPromise = jest.fn();
const mockGetSecretValue = jest.fn().mockReturnValue({
    promise: mockPromise
});

// Jest Mock Factory
jest.mock('aws-sdk', () => {
    return {
        SecretsManager: jest.fn(() => ({
            getSecretValue: mockGetSecretValue
        }))
    };
});

describe('Secure Data Lambda', () => {
    beforeEach(() => {
        mockGetSecretValue.mockClear();
        mockPromise.mockClear();
        process.env.SECRET_NAME = 'test-secret';

        // Ensure mock returns correct structure
        mockGetSecretValue.mockImplementation(() => ({
            promise: mockPromise
        }));
    });

    afterAll(() => {
        delete process.env.SECRET_NAME;
    });

    test('should return 200 and secret data when invoked', async () => {
        // Setup mock return
        mockPromise.mockResolvedValueOnce({
            SecretString: JSON.stringify({ username: 'admin', password: 'secret_password' })
        });

        const event = {
            requestContext: {
                authorizer: {
                    claims: {
                        sub: 'test-user-id',
                        email: 'test@example.com'
                    }
                }
            }
        } as any;

        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body).toHaveProperty('data');
        expect(body.data).toHaveProperty('secretInfo');
        expect(body.data.secretInfo).toContain('admin');
    });

    test('should handle missing secret name env var', async () => {
        delete process.env.SECRET_NAME;

        const event = {
            requestContext: {
                authorizer: {
                    claims: { sub: 'test-user-id' }
                }
            }
        } as any;

        const result = await handler(event);
        expect(result.statusCode).toBe(200); // Our code returns 200 even if secret missing, just doesn't show it
    });

    test('should handle secrets manager error', async () => {
        mockPromise.mockRejectedValueOnce(new Error('AccessDenied'));

        const event = {
            requestContext: {
                authorizer: {
                    claims: { sub: 'test-user-id' }
                }
            }
        } as any;

        const result = await handler(event);
        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.data.secretInfo).toBe('Error retrieving secret');
    });
});

