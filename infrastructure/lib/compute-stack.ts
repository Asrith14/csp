import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as path from 'path';
import { Construct } from 'constructs';

interface ComputeStackProps extends cdk.StackProps {
    /** VPC to place Lambda functions in (private subnets). */
    vpc: ec2.IVpc;
    /** Security group to attach to Lambda functions. */
    lambdaSecurityGroup: ec2.ISecurityGroup;
    /** Optional secret to grant read access to secureDataFunction. */
    databaseSecret?: secretsmanager.ISecret;
}

export class ComputeStack extends cdk.Stack {
    public readonly preSignUpFunction: lambda.Function;
    public readonly postConfirmationFunction: lambda.Function;
    public readonly secureDataFunction: lambda.Function;

    constructor(scope: Construct, id: string, props: ComputeStackProps) {
        super(scope, id, props);

        const runtime = lambda.Runtime.NODEJS_20_X;
        const tracing = lambda.Tracing.ACTIVE;
        const timeout = cdk.Duration.seconds(15);
        const memorySize = 256;

        // All Lambda functions run inside AppVpc private subnets.
        // The Lambda SG allows only HTTPS egress to VPC endpoints (Secrets Manager, KMS).
        const vpcConfig: Pick<lambda.FunctionProps, 'vpc' | 'vpcSubnets' | 'securityGroups'> = {
            vpc: props.vpc,
            vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [props.lambdaSecurityGroup],
        };

        // Cognito PreSignUp trigger
        this.preSignUpFunction = new lambda.Function(this, 'PreSignUpFunc', {
            ...vpcConfig,
            runtime,
            tracing,
            timeout,
            memorySize,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/identity'), {
                exclude: ['post-confirmation.js'],
            }),
            handler: 'pre-signup.handler',
            description: 'Cognito PreSignUp trigger — auto-confirms users',
        });

        // Cognito PostConfirmation trigger
        this.postConfirmationFunction = new lambda.Function(this, 'PostConfirmationFunc', {
            ...vpcConfig,
            runtime,
            tracing,
            timeout,
            memorySize,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/identity'), {
                exclude: ['pre-signup.js'],
            }),
            handler: 'post-confirmation.handler',
            description: 'Cognito PostConfirmation trigger — assigns default group',
        });

        // Secure data endpoint handler
        this.secureDataFunction = new lambda.Function(this, 'SecureDataFunc', {
            ...vpcConfig,
            runtime,
            tracing,
            timeout,
            memorySize,
            code: lambda.Code.fromAsset(path.join(__dirname, '../dist/functions/api')),
            handler: 'secure-data.handler',
            description: 'Handler for /secure-data endpoint — fetches secret at runtime',
            environment: {
                SECRET_NAME: props.databaseSecret?.secretName ?? '',
            },
        });

        if (props.databaseSecret) {
            props.databaseSecret.grantRead(this.secureDataFunction);
        }
    }
}
