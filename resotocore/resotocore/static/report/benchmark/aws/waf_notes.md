
- SEC02-BP06: prowler implements a check that checks all custom permissions if they allow privilege escalation
  e.g. iam:*, (iam:PassRole and ec2:RunInstances), (iam:PassRole and lambda:CreateFunction and lambda:InvokeFunction)
- IAM Policy: we currently can not distinguish between custom and aws managed policies
- SEC03-BP07: SQS queue and SNS topic not publicly accessible check is missing (policy)
- SEC03-BP07: SSM document: fetch account owners
