#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { IdentityStack } from '../lib/identity-stack';
import { ApiStack } from '../lib/api-stack';
import { ComputeStack } from '../lib/compute-stack';
import { SecurityStack } from '../lib/security-stack';
import { ObservabilityStack } from '../lib/observability-stack';

const app = new cdk.App();

// Day 1: Infrastructure Stacks
// We use the account/region from CLI configuration by default
const env = { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION };

const computeStack = new ComputeStack(app, 'ComputeStack', { env });

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

const observabilityStack = new ObservabilityStack(app, 'ObservabilityStack', {
    env,
    api: apiStack.api,
});
