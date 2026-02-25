import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
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

        this.api = new apigateway.RestApi(this, 'ZeroTrustApi', {
            restApiName: 'Zero Trust API',
            description: 'Zero Trust API Gateway for hybrid and multi-cloud network architecture',
            deployOptions: {
                stageName: 'prod',
                tracingEnabled: true,
                metricsEnabled: true,
                loggingLevel: apigateway.MethodLoggingLevel.INFO,
                dataTraceEnabled: false, // Do not log full request bodies (PII risk)
            },
            defaultCorsPreflightOptions: {
                allowOrigins: apigateway.Cors.ALL_ORIGINS,
                allowMethods: apigateway.Cors.ALL_METHODS,
            },
        });

        // Associate WAF WebACL with the API Gateway deployment stage
        new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
            resourceArn: this.api.deploymentStage.stageArn,
            webAclArn: props.webAclArn,
        });

        // Cognito Authorizer — all routes require a valid JWT
        const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'ZeroTrustAuthorizer', {
            cognitoUserPools: [props.userPool],
        });

        // Request Validator — enforce body schema and query params
        const requestValidator = this.api.addRequestValidator('RequestValidator', {
            validateRequestBody: true,
            validateRequestParameters: true,
        });

        const secureData = this.api.root.addResource('secure-data');

        secureData.addMethod('GET', new apigateway.LambdaIntegration(props.secureDataFunction), {
            authorizer,
            authorizationType: apigateway.AuthorizationType.COGNITO,
        });

        // POST requires a valid JSON body matching the schema below
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
            requestModels: { 'application/json': dataModel },
        });

        new cdk.CfnOutput(this, 'ApiUrl', { value: this.api.url });
    }
}
