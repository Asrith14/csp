import {
    CognitoIdentityProviderClient,
    AdminAddUserToGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import type { PostConfirmationTriggerEvent } from 'aws-lambda';

const cognitoClient = new CognitoIdentityProviderClient({});

const DEFAULT_GROUP = 'Viewer';

/**
 * Post-Confirmation Trigger: assigns all newly confirmed users to the default 'Viewer' group.
 * Group assignment failure is logged but does not block the confirmation to avoid locking users out.
 */
export const handler = async (event: PostConfirmationTriggerEvent): Promise<PostConfirmationTriggerEvent> => {
    const { userPoolId, userName } = event;

    console.log(JSON.stringify({ level: 'INFO', message: 'PostConfirmation trigger fired', userName }));

    try {
        await cognitoClient.send(
            new AdminAddUserToGroupCommand({
                GroupName: DEFAULT_GROUP,
                UserPoolId: userPoolId,
                Username: userName,
            }),
        );
        console.log(JSON.stringify({ level: 'INFO', message: `Assigned user to group`, userName, group: DEFAULT_GROUP }));
    } catch (err) {
        // Non-fatal: log and continue. Do not block user confirmation.
        console.log(JSON.stringify({ level: 'ERROR', message: 'Failed to assign user to group', userName, error: String(err) }));
    }

    return event;
};
