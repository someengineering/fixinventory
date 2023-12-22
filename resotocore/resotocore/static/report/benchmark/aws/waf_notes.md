
- SEC02-BP06: prowler implements a check that checks all custom permissions if they allow privilege escalation
  e.g. iam:*, (iam:PassRole and ec2:RunInstances), (iam:PassRole and lambda:CreateFunction and lambda:InvokeFunction)
- SEC03-BP02: steampipe has a check for AWS EMR to make sure it uses kerberos
- IAM Policy: we currently can not distinguish between custom and aws managed policies
- SEC03-BP06: prowler checks appstream fleet session duration, disconnect and idle timeouts
- SEC03-BP06: prowler checks ECR repositories for an existing lifecycle policy. This policy needs to be fetched explicitly for every repository.
- SEC03-BP06: steampipe checks for codebuild_project_build_greater_then_90_days
- Check that guardduty is enabled
-
