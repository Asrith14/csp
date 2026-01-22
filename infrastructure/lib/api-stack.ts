import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

interface ApiStackProps extends cdk.StackProps {
    userPool: cognito.UserPool;
    secureDataFunction: lambda.Function;
    webAclArn: string;
}

export class ApiStack extends cdk.Stack {
    public readonly api: apigateway.RestApi;

    constructor(scope: Construct, id: string, props: ApiStackProps) {
        super(scope, id, props);

        // Day 3 Foundations: API Gateway
        this.api = new apigateway.RestApi(this, 'ZeroTrustApi', {
            restApiName: 'Zero Trust API',
            description: 'Main API Gateway for Zero Trust Architecture',
            deployOptions: {
                stageName: 'prod',
                tracingEnabled: true, // Day 5 Observability: X-Ray
                metricsEnabled: true, // Day 5 Observability: CloudWatch
            },
            defaultCorsPreflightOptions: {
                allowOrigins: apigateway.Cors.ALL_ORIGINS,
                allowMethods: apigateway.Cors.ALL_METHODS,
            },
            policy: new iam.PolicyDocument({
                statements: [
                    new iam.PolicyStatement({
                        effect: iam.Effect.ALLOW,
                        principals: [new iam.AnyPrincipal()],
                        actions: ['execute-api:Invoke'],
                        resources: ['execute-api:/*'],
                    }),
                    new iam.PolicyStatement({
                        effect: iam.Effect.DENY,
                        principals: [new iam.AnyPrincipal()],
                        actions: ['execute-api:Invoke'],
                        resources: ['execute-api:/*'],
                        conditions: {
                            IpAddress: {
                                'aws:SourceIp': ['0.0.0.0/0'] // Placeholder for blacklist
                            },
                        },
                    }),
                ],
            }),
        });

        // WAF Association
        new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
            resourceArn: this.api.deploymentStage.stageArn,
            webAclArn: props.webAclArn,
        });

        // Cognito Authorizer
        const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'ZeroTrustAuthorizer', {
            cognitoUserPools: [props.userPool],
        });

        // Request Validator
        const requestValidator = this.api.addRequestValidator('RequestValidator', {
            validateRequestBody: true,
            validateRequestParameters: true,
        });

        // Secure Data Resource
        const secureData = this.api.root.addResource('secure-data');

        // GET Method (Authorized)
        secureData.addMethod('GET', new apigateway.LambdaIntegration(props.secureDataFunction), {
            authorizer,
            authorizationType: apigateway.AuthorizationType.COGNITO,
        });

        // POST Method (Authorized + Validated)
        // Define Model
        const dataModel = this.api.addModel('DataModel', {
            contentType: 'application/json',
            modelName: 'DataModel',
            schema: {
                type: apigateway.JsonSchemaType.OBJECT,
                required: ['action', 'payload'],
                properties: {
                    action: { type: apigateway.JsonSchemaType.STRING },
                    payload: { type: apigateway.JsonSchemaType.OBJECT },
                },
            },
        });

        secureData.addMethod('POST', new apigateway.LambdaIntegration(props.secureDataFunction), {
            authorizer,
            authorizationType: apigateway.AuthorizationType.COGNITO,
            requestValidator,
            requestModels: {
                'application/json': dataModel,
            },
        });

        new cdk.CfnOutput(this, 'ApiUrl', { value: this.api.url });
    }
}
