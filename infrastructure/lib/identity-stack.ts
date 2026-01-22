import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

interface IdentityStackProps extends cdk.StackProps {
  preSignUpFunction: lambda.Function;
  postConfirmationFunction: lambda.Function;
}

export class IdentityStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props: IdentityStackProps) {
    super(scope, id, props);

    // Day 2 Foundations: User Pool
    this.userPool = new cognito.UserPool(this, 'ZeroTrustUserPool', {
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      // MFA Configuration
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      // Lambda Triggers
      lambdaTriggers: {
        preSignUp: props.preSignUpFunction,
        postConfirmation: props.postConfirmationFunction,
      },
    });

    // Groups
    const groups = ['Admin', 'Developer', 'Viewer'];
    groups.forEach(groupName => {
      new cognito.CfnUserPoolGroup(this, `Group${groupName}`, {
        userPoolId: this.userPool.userPoolId,
        groupName: groupName,
        description: `${groupName} group`,
      });
    });

    // Grant Post-Confirmation Lambda permission to add user to groups
    // We create a separate Policy in this stack to avoid circular dependency (Identity -> Compute -> Identity)
    if (props.postConfirmationFunction.role) {
      const groupPolicy = new iam.Policy(this, 'UserPoolGroupPolicy', {
        statements: [
          new iam.PolicyStatement({
            actions: ['cognito-idp:AdminAddUserToGroup'],
            resources: [this.userPool.userPoolArn],
          }),
        ],
      });
      groupPolicy.attachToRole(props.postConfirmationFunction.role);
    }
    // props.postConfirmationFunction.addToRolePolicy(addToGroupPolicy);

    this.userPoolClient = this.userPool.addClient('AppClient', {
      authFlows: {
        userSrp: true, // Recommended for mobile/web
      },
      accessTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(1), // Rotation enabled implicitly by refresh token validity
    });

    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
  }
}
