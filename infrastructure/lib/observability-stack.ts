import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as budgets from 'aws-cdk-lib/aws-budgets';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import { Construct } from 'constructs';

interface ObservabilityStackProps extends cdk.StackProps {
    api: apigateway.RestApi;
}

export class ObservabilityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: ObservabilityStackProps) {
        super(scope, id, props);

        // Day 5: CloudWatch Dashboard
        const dashboard = new cloudwatch.Dashboard(this, 'ZeroTrustDashboard', {
            dashboardName: 'ZeroTrust-Operational-Dashboard',
        });

        // API Gateway Metrics
        const api5xxMetric = new cloudwatch.Metric({
            namespace: 'AWS/ApiGateway',
            metricName: '5XXError',
            dimensionsMap: { ApiName: props.api.restApiName },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
        });

        const apiLatencyMetric = new cloudwatch.Metric({
            namespace: 'AWS/ApiGateway',
            metricName: 'Latency',
            dimensionsMap: { ApiName: props.api.restApiName },
            statistic: 'Average',
            period: cdk.Duration.minutes(1),
        });

        const apiRequestsMetric = new cloudwatch.Metric({
            namespace: 'AWS/ApiGateway',
            metricName: 'Count',
            dimensionsMap: { ApiName: props.api.restApiName },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
        });

        dashboard.addWidgets(
            new cloudwatch.GraphWidget({
                title: 'API Traffic & Errors',
                left: [apiRequestsMetric],
                right: [api5xxMetric],
                width: 12,
            }),
            new cloudwatch.GraphWidget({
                title: 'API Latency',
                left: [apiLatencyMetric],
                width: 12,
            })
        );

        // Day 5: Alarms
        // Trigger if > 1% of requests are 5XX errors (simplified as > 5 errors for demo)
        new cloudwatch.Alarm(this, 'HighErrorRateAlarm', {
            metric: api5xxMetric,
            threshold: 5,
            evaluationPeriods: 1,
            comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarmDescription: 'Alarm if API Gateway 5XX errors > 5 in 1 minute',
        });

        // Day 5: Cost Budget (USD 10.00)
        new budgets.CfnBudget(this, 'MonthlyBudget', {
            budget: {
                budgetType: 'COST',
                timeUnit: 'MONTHLY',
                budgetLimit: {
                    amount: 10,
                    unit: 'USD',
                },
            },
            notificationsWithSubscribers: [
                {
                    notification: {
                        notificationType: 'FORECASTED',
                        comparisonOperator: 'GREATER_THAN',
                        threshold: 100, // 100% of budget
                        thresholdType: 'PERCENTAGE',
                    },
                    subscribers: [
                        {
                            subscriptionType: 'EMAIL',
                            address: 'admin@example.com', // Placeholder
                        },
                    ],
                },
            ],
        });
    }
}
