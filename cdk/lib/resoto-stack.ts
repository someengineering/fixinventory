import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { readFileSync } from 'fs';

export class ResotoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'resoto-vpc', {
      maxAzs: 1,
      subnetConfiguration: [{
          name: 'public', 
          cidrMask: 24,
          subnetType: ec2.SubnetType.PUBLIC,
        }]
    });

    const resotocoreSG = new ec2.SecurityGroup(this, 'resotocore-sg', {
      vpc: vpc,
      description: 'Allow https and ssh traffic to resotocore',
      allowAllOutbound: true,
    });

    resotocoreSG.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(22),
      'allow ssh access to the instance from anywhere'
    );

    const resotoRole = new iam.Role(this, 'resoto-role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
    });

    const image = ec2.MachineImage.latestAmazonLinux({
      generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
    });


    const init = ec2.CloudFormationInit.fromElements(...
      readFileSync("./lib/setup_resoto.sh", "utf-8")
      .split("/n")
      .map((line) => ec2.InitCommand.shellCommand(line))
    );

    const instance = new ec2.Instance(this, 'resoto-instance', {
      vpc: vpc,
      vpcSubnets: { 
        subnetType: ec2.SubnetType.PUBLIC 
      },
      role: resotoRole,
      securityGroup: resotocoreSG,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T3,
        ec2.InstanceSize.LARGE
      ),
      machineImage: image,
      blockDevices: [
        {
          deviceName: '/dev/xvda', // make the root volume bigger
          volume: ec2.BlockDeviceVolume.ebs(50),
        },
      ],
      init: init,
      initOptions: {
        timeout: cdk.Duration.minutes(5),
      },
      keyName: 'nm-resoto-ec2-keypair',
    });

    // print the public IP of the instance in the end
    const output = new cdk.CfnOutput(this, 'resoto-public-ip', {
      value: instance.instancePublicIp,
      description: 'Public IP of the resoto instance',
      exportName: 'resoto-public-ip',
    });
  }
}
