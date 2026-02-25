import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

/**
 * NetworkStack — Hybrid & Multi-Cloud Connectivity Layer (Day 7)
 *
 * Two VPCs are created:
 *   AppVpc     (10.0.0.0/16) — Primary application network. Lambda runs here.
 *   OnPremVpc  (10.1.0.0/16) — Simulates an on-prem datacenter or external cloud (Azure/GCP).
 *
 * They are connected via VPC Peering (L3 IP routing), but peering alone does NOT
 * grant trust. Security Groups and NACLs enforce Zero Trust at the network layer:
 * on-prem hosts cannot reach Lambda or AWS services directly — they must go through
 * the API Gateway with a valid JWT.
 */
export class NetworkStack extends cdk.Stack {
    /** Primary VPC where application resources (Lambda, VPC Endpoints) reside. */
    public readonly appVpc: ec2.Vpc;
    /** Security Group to be attached to Lambda functions — restricts traffic to VPC only. */
    public readonly lambdaSecurityGroup: ec2.SecurityGroup;

    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // ─── PRIMARY APP VPC ─────────────────────────────────────────────────────
        this.appVpc = new ec2.Vpc(this, 'AppVpc', {
            ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
            maxAzs: 2,
            natGateways: 1, // 1 NAT GW total (cost-conscious; 1 per AZ in production)
            subnetConfiguration: [
                {
                    // NAT Gateways must be placed in a public subnet.
                    // This subnet hosts only the NAT GW — all app resources stay in Private.
                    name: 'Public',
                    subnetType: ec2.SubnetType.PUBLIC,
                    cidrMask: 28, // Minimal — only needs to fit the NAT GW ENI
                },
                {
                    // Lambda and all app resources run here.
                    name: 'Private',
                    subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidrMask: 24,
                },
            ],
        });

        // ─── ON-PREM / EXTERNAL CLOUD VPC ────────────────────────────────────────
        // Represents: an on-prem datacenter, Azure VNET, or GCP VPC.
        // CIDR must NOT overlap with AppVpc — prerequisite for peering.
        const onPremVpc = new ec2.Vpc(this, 'OnPremVpc', {
            ipAddresses: ec2.IpAddresses.cidr('10.1.0.0/16'),
            maxAzs: 1,
            natGateways: 0, // Simulated env — no egress needed
            subnetConfiguration: [
                {
                    name: 'OnPrem',
                    subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
                    cidrMask: 24,
                },
            ],
        });

        // ─── VPC PEERING ─────────────────────────────────────────────────────────
        // Establishes IP-level reachability between the two VPCs.
        // This is L3 routing ONLY — it does NOT override Security Groups or NACLs.
        const peering = new ec2.CfnVPCPeeringConnection(this, 'AppOnPremPeering', {
            vpcId: this.appVpc.vpcId,
            peerVpcId: onPremVpc.vpcId,
        });

        // Route traffic destined for OnPremVpc CIDR through the peering connection
        // (from each private subnet in AppVpc)
        this.appVpc.privateSubnets.forEach((subnet, idx) => {
            new ec2.CfnRoute(this, `AppToOnPremRoute${idx}`, {
                routeTableId: subnet.routeTable.routeTableId,
                destinationCidrBlock: '10.1.0.0/16',
                vpcPeeringConnectionId: peering.ref,
            });
        });

        // Route traffic destined for AppVpc CIDR through the peering connection
        // (from each isolated subnet in OnPremVpc)
        onPremVpc.isolatedSubnets.forEach((subnet, idx) => {
            new ec2.CfnRoute(this, `OnPremToAppRoute${idx}`, {
                routeTableId: subnet.routeTable.routeTableId,
                destinationCidrBlock: '10.0.0.0/16',
                vpcPeeringConnectionId: peering.ref,
            });
        });

        // ─── NETWORK ACL FOR APP PRIVATE SUBNETS ─────────────────────────────────
        // NACLs are stateless and evaluated before Security Groups.
        // We explicitly deny all traffic originating from the on-prem CIDR
        // except for HTTPS (443) which is needed for VPC Endpoint access from authorised clients.
        const appNacl = new ec2.NetworkAcl(this, 'AppPrivateNacl', {
            vpc: this.appVpc,
            subnetSelection: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        });

        // DENY all inbound from on-prem CIDR (priority 90 — evaluated first)
        appNacl.addEntry('DenyOnPremInbound', {
            ruleNumber: 90,
            cidr: ec2.AclCidr.ipv4('10.1.0.0/16'),
            traffic: ec2.AclTraffic.allTraffic(),
            direction: ec2.TrafficDirection.INGRESS,
            ruleAction: ec2.Action.DENY,
        });

        // ALLOW all inbound from within AppVpc CIDR (Lambda-to-Lambda, endpoint traffic)
        appNacl.addEntry('AllowAppVpcInbound', {
            ruleNumber: 100,
            cidr: ec2.AclCidr.ipv4('10.0.0.0/16'),
            traffic: ec2.AclTraffic.allTraffic(),
            direction: ec2.TrafficDirection.INGRESS,
            ruleAction: ec2.Action.ALLOW,
        });

        // ALLOW ephemeral port responses inbound (required for TCP return traffic)
        appNacl.addEntry('AllowEphemeralInbound', {
            ruleNumber: 110,
            cidr: ec2.AclCidr.anyIpv4(),
            traffic: ec2.AclTraffic.tcpPortRange(1024, 65535),
            direction: ec2.TrafficDirection.INGRESS,
            ruleAction: ec2.Action.ALLOW,
        });

        // ALLOW all outbound (Security Groups enforce egress at instance level)
        appNacl.addEntry('AllowAllOutbound', {
            ruleNumber: 100,
            cidr: ec2.AclCidr.anyIpv4(),
            traffic: ec2.AclTraffic.allTraffic(),
            direction: ec2.TrafficDirection.EGRESS,
            ruleAction: ec2.Action.ALLOW,
        });

        // ─── LAMBDA SECURITY GROUP ────────────────────────────────────────────────
        // Attached to all Lambda functions. Controls what can reach them and
        // what they can call outbound.
        this.lambdaSecurityGroup = new ec2.SecurityGroup(this, 'LambdaSecurityGroup', {
            vpc: this.appVpc,
            description: 'Security group for Lambda functions — allows HTTPS egress to VPC endpoints only',
            allowAllOutbound: false,
        });

        // Lambda may only send outbound HTTPS (to VPC endpoints for Secrets Manager, KMS, etc.)
        this.lambdaSecurityGroup.addEgressRule(
            ec2.Peer.ipv4(this.appVpc.vpcCidrBlock),
            ec2.Port.tcp(443),
            'Allow HTTPS egress within VPC (to VPC Endpoints)',
        );

        // ─── VPC ENDPOINTS (PrivateLink) ─────────────────────────────────────────
        // Lambda calls to these services never leave the AWS network backbone.
        // Without these, a Lambda in a private subnet would need a NAT Gateway
        // to reach Secrets Manager / KMS — adding cost and internet exposure.

        const endpointSg = new ec2.SecurityGroup(this, 'VpcEndpointSecurityGroup', {
            vpc: this.appVpc,
            description: 'Allows inbound HTTPS from Lambda SG to VPC Interface Endpoints',
        });
        endpointSg.addIngressRule(
            ec2.Peer.securityGroupId(this.lambdaSecurityGroup.securityGroupId),
            ec2.Port.tcp(443),
            'Allow Lambda SG to reach VPC Endpoints',
        );

        // Secrets Manager endpoint
        new ec2.InterfaceVpcEndpoint(this, 'SecretsManagerEndpoint', {
            vpc: this.appVpc,
            service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSg],
            privateDnsEnabled: true, // Lambda uses the standard hostname — no code changes needed
        });

        // KMS endpoint
        new ec2.InterfaceVpcEndpoint(this, 'KmsEndpoint', {
            vpc: this.appVpc,
            service: ec2.InterfaceVpcEndpointAwsService.KMS,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSg],
            privateDnsEnabled: true,
        });

        // API Gateway endpoint — allows resources inside AppVpc to call the API internally
        new ec2.InterfaceVpcEndpoint(this, 'ApiGatewayEndpoint', {
            vpc: this.appVpc,
            service: ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSg],
            privateDnsEnabled: true,
        });

        // ─── OUTPUTS ──────────────────────────────────────────────────────────────
        new cdk.CfnOutput(this, 'AppVpcId', { value: this.appVpc.vpcId });
        new cdk.CfnOutput(this, 'OnPremVpcId', { value: onPremVpc.vpcId });
        new cdk.CfnOutput(this, 'PeeringConnectionId', { value: peering.ref });
        new cdk.CfnOutput(this, 'LambdaSecurityGroupId', { value: this.lambdaSecurityGroup.securityGroupId });
    }
}
