#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/network-stack';
import { IdentityStack } from '../lib/identity-stack';
import { ApiStack } from '../lib/api-stack';
import { ComputeStack } from '../lib/compute-stack';
import { SecurityStack } from '../lib/security-stack';
import { ObservabilityStack } from '../lib/observability-stack';

const app = new cdk.App();

const env: cdk.Environment = {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
};

// Day 7: NetworkStack must be first — all other stacks depend on the VPC
const networkStack = new NetworkStack(app, 'NetworkStack', { env });

// ComputeStack: Lambda functions run inside the AppVpc private subnets
const computeStack = new ComputeStack(app, 'ComputeStack', {
    env,
    vpc: networkStack.appVpc,
    lambdaSecurityGroup: networkStack.lambdaSecurityGroup,
});

const identityStack = new IdentityStack(app, 'IdentityStack', {
    env,
    preSignUpFunction: computeStack.preSignUpFunction,
    postConfirmationFunction: computeStack.postConfirmationFunction,
});

const securityStack = new SecurityStack(app, 'SecurityStack', { env });

const apiStack = new ApiStack(app, 'ApiStack', {
    env,
    userPool: identityStack.userPool,
    secureDataFunction: computeStack.secureDataFunction,
    webAclArn: securityStack.webAcl.attrArn,
});

new ObservabilityStack(app, 'ObservabilityStack', {
    env,
    api: apiStack.api,
    alertEmail: process.env.ALERT_EMAIL ?? 'ops-team@example.com',
});
