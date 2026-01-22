// aws-sdk is provided by the Lambda runtime
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AWS = require('aws-sdk');
const cognito = new AWS.CognitoIdentityServiceProvider();

export const handler = async (event: any) => {
    console.log(JSON.stringify(event, null, 2));

    const userPoolId = event.userPoolId;
    const userName = event.userName;

    // Day 2: Assign default group 'Viewer' to new users
    const params = {
        GroupName: 'Viewer',
        UserPoolId: userPoolId,
        Username: userName,
    };

    try {
        await cognito.adminAddUserToGroup(params).promise();
        console.log(`Added user ${userName} to group Viewer`);
    } catch (error) {
        console.error(`Error adding user to group: ${error}`);
        // Don't fail the authentication just because group assignment failed, 
        // but log it seriously.
    }

    return event;
};
