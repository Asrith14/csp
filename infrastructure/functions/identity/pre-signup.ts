import type { PreSignUpTriggerEvent } from 'aws-lambda';

/**
 * Pre-SignUp Trigger: auto-confirms users so they can proceed without email verification code.
 * In production, replace this with domain allowlist logic.
 */
export const handler = async (event: PreSignUpTriggerEvent): Promise<PreSignUpTriggerEvent> => {
  console.log(JSON.stringify({ level: 'INFO', message: 'PreSignUp trigger fired', userName: event.userName }));

  event.response.autoConfirmUser = true;
  event.response.autoVerifyEmail = true;

  return event;
};
