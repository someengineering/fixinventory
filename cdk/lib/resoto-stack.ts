import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

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


    const dockerComposeSetupCommands = ec2.UserData.forLinux();
    dockerComposeSetupCommands.addCommands(
      // docker setup
      'sudo yum update',
      'sudo yum install docker',
      'sudo usermod -a -G docker ec2-user',
      'id ec2-user',
      'newgrp docker',
      // docker compose setup
      'wget https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)',
      'sudo mv docker-compose-$(uname -s)-$(uname -m) /usr/local/bin/docker-compose',
      'sudo chmod -v +x /usr/local/bin/docker-compose',
      'sudo systemctl enable docker.service',
      'sudo systemctl start docker.service',
      // resoto setup
      'mkdir -p resoto/dockerV2',
      'cd resoto',
      'curl -o docker-compose.yaml https://raw.githubusercontent.com/someengineering/resoto/2.4.3/docker-compose.yaml',
      'curl -o dockerV2/prometheus.yml https://raw.githubusercontent.com/someengineering/resoto/2.4.3/dockerV2/prometheus.yml',
      'docker-compose up -d',
    )


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
      keyName: 'nm-resoto-ec2-keypair',
      userData: dockerComposeSetupCommands,
    });

    // print the public IP of the instance in the end
    const output = new cdk.CfnOutput(this, 'resoto-public-ip', {
      value: instance.instancePublicIp,
      description: 'Public IP of the resoto instance',
      exportName: 'resoto-public-ip',
    });


  }
}
