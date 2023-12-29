
- SEC02-BP06: check all custom permissions if they allow privilege escalation
  e.g. iam:*, (iam:PassRole and ec2:RunInstances), (iam:PassRole and lambda:CreateFunction and lambda:InvokeFunction)
- SEC03-BP07: SQS queue and SNS topic not publicly accessible check is missing (policy)
- SEC04-BP04: Cloudwatch: ensure alerts for log metric filters are configured
