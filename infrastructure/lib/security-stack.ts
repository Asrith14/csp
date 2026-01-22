import * as cdk from 'aws-cdk-lib';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

export class SecurityStack extends cdk.Stack {
    public readonly webAcl: wafv2.CfnWebACL;

    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Day 3: WAF Rules
        this.webAcl = new wafv2.CfnWebACL(this, 'ApiGatewayWebAcl', {
            defaultAction: { allow: {} },
            scope: 'REGIONAL',
            visibilityConfig: {
                cloudWatchMetricsEnabled: true,
                metricName: 'ApiGatewayWebAclMetric',
                sampledRequestsEnabled: true,
            },
            rules: [
                // Rule 1: Rate Limiting (100 req / 5 min)
                {
                    name: 'RateLimitRule',
                    priority: 100,
                    statement: {
                        rateBasedStatement: {
                            limit: 100,
                            aggregateKeyType: 'IP',
                        },
                    },
                    action: { block: {} },
                    visibilityConfig: {
                        cloudWatchMetricsEnabled: true,
                        metricName: 'RateLimitMetric',
                        sampledRequestsEnabled: true,
                    },
                },
                // Rule 2: AWS Managed Rules (Common)
                {
                    name: 'AWSCommonRules',
                    priority: 200,
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesCommonRuleSet',
                        },
                    },
                    overrideAction: { none: {} },
                    visibilityConfig: {
                        cloudWatchMetricsEnabled: true,
                        metricName: 'AWSCommonRulesMetric',
                        sampledRequestsEnabled: true,
                    },
                },
                // Rule 3: AWS Managed Rules (SQLi)
                {
                    name: 'AWSSQLiRules',
                    priority: 300,
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesSQLiRuleSet',
                        },
                    },
                    overrideAction: { none: {} },
                    visibilityConfig: {
                        cloudWatchMetricsEnabled: true,
                        metricName: 'AWSSQLiRulesMetric',
                        sampledRequestsEnabled: true,
                    },
                },
            ],
        });

        new cdk.CfnOutput(this, 'WebAclArn', { value: this.webAcl.attrArn });
    }
}
