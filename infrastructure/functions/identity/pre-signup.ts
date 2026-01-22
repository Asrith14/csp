export const handler = async (event: any) => {
    console.log(JSON.stringify(event, null, 2));

    // Day 2: Auto-confirm users or perform validation
    // For now, we just auto-confirm everyone to simplify testing
    // In production, we might check for specific email domains
    event.response.autoConfirmUser = true;
    event.response.autoVerifyEmail = true;

    return event;
};
