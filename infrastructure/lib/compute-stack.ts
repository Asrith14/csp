import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as path from 'path';
import { Construct } from 'constructs';

interface ComputeStackProps extends cdk.StackProps {
    databaseSecret?: secretsmanager.Secret;
}

export class ComputeStack extends cdk.Stack {
    public readonly preSignUpFunction: lambda.Function;
    public readonly postConfirmationFunction: lambda.Function;
    public readonly secureDataFunction: lambda.Function;

    constructor(scope: Construct, id: string, props?: ComputeStackProps) {
        super(scope, id, props);

        // Day 2: Identity Triggers
        // We use pre-built assets to avoid CDK bundling issues
        this.preSignUpFunction = new lambda.Function(this, 'PreSignUpFunc', {
            runtime: lambda.Runtime.NODEJS_20_X,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/identity'), {
                exclude: ['post-confirmation.js'],
            }),
            handler: 'pre-signup.handler',
            tracing: lambda.Tracing.ACTIVE,
        });

        this.postConfirmationFunction = new lambda.Function(this, 'PostConfirmationFunc', {
            runtime: lambda.Runtime.NODEJS_20_X,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/identity'), {
                exclude: ['pre-signup.js'],
            }),
            handler: 'post-confirmation.handler',
            tracing: lambda.Tracing.ACTIVE,
        });

        // Day 3: API Functions
        this.secureDataFunction = new lambda.Function(this, 'SecureDataFunc', {
            runtime: lambda.Runtime.NODEJS_20_X,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/api'), {
                exclude: [],
            }),
            handler: 'secure-data.handler',
            tracing: lambda.Tracing.ACTIVE,
            environment: {
                SECRET_NAME: props?.databaseSecret?.secretName || '',
            },
        });

        // Day 4: Grant Permissions
        if (props?.databaseSecret) {
            props.databaseSecret.grantRead(this.secureDataFunction);
        }
    }
}
