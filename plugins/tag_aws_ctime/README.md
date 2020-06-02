# cloudkeeper-plugin-tag_aws_ctime
AWS ctime tagging plugin for Cloudkeeper

This plugin tags AWS resources whose API does not return a creation time with the time it was first seen by Cloudkeeper.

## Usage
```
$ cloudkeeper -v --tag-aws-ctime
```

## Implementation details
Most resources in AWS provide a creation time timestamp. However some like ALB target groups, Network ACLs and EC2 Keypairs
do not. Those resources however support tags. When this plugin is activated we will create a tag called
`cloudkeeper:ctime` with an ISO 8601 timestamp containing the first time we have encountered this resource.
Every resource in Cloudkeeper has an attribute `ctime` (and a resulting `age` attribute) which by default contains whatever
creation time the cloud API returned.

If Cloudkeeper finds a `cloudkeeper:ctime` tag on a resource and is able to parse it it will by default return this value for the
`ctime` attribute. Meaning once tagged every other plugin can make use of this updated `ctime`.

## List of arguments
```
  --tag-aws-ctime       Tag AWS ctime (default: False)
```
