# cloudkeeper-plugin-aws
An AWS collector plugin for Cloudkeeper.

## Usage
When the collector is enabled (`--collector aws`) it will automatically collect any accounts the AWS boto3 SDK can authenticate for.
By default it will check for environment variables like `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `AWS_SESSION_TOKEN`.
Optionally credentials can be given as commandline arguments using the `--aws-access-key-id` and `--aws-secret-access-key` arguments.

If cloudkeeper should assume an IAM role that role can be given via `--aws-role SomeRoleName`.

The collector will scrape resources in all regions unless regions are specified using e.g. `--aws-region us-east-1 us-west-2`.

## List of arguments
```
  --aws-access-key-id AWS_ACCESS_KEY_ID
                        AWS Access Key ID
  --aws-secret-access-key AWS_SECRET_ACCESS_KEY
                        AWS Secret Access Key
  --aws-role AWS_ROLE   AWS IAM Role
  --aws-role-override   Override any stored roles (e.g. from remote graphs) (default: False)
  --aws-account AWS_ACCOUNT [AWS_ACCOUNT ...]
                        AWS Account
  --aws-region AWS_REGION [AWS_REGION ...]
                        AWS Region (default: all)
  --aws-scrape-org      Scrape the entire AWS Org (default: False)
  --aws-scrape-exclude-account AWS_SCRAPE_EXCLUDE_ACCOUNT [AWS_SCRAPE_EXCLUDE_ACCOUNT ...]
                        AWS exclude this Account when scraping the org
  --aws-assume-current  Assume role in current account (default: False)
  --aws-dont-scrape-current
                        Don't scrape current account (default: False)
  --aws-account-pool-size AWS_ACCOUNT_POOL_SIZE
                        AWS Account Thread Pool Size (default: 5)
  --aws-region-pool-size AWS_REGION_POOL_SIZE
                        AWS Region Thread Pool Size (default: 20)
```

## Scraping multiple accounts
If the given credentials are allowed to assume the specified role in other accounts of your AWS organisation cloudkeeper
can collect multiple accounts at the same time. To do so provide the account IDs to the `--aws-account` argument.

## Scraping the entire organisation
Instead of giving a list of account IDs manually you could also specify `--aws-scrape-org`, which will make cloudkeeper
try to get the list of all accounts using the [ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) API.

If certain accounts are to be excluded from that list they can be specified using the `--aws-scrape-exclde-account` argument.

## Worker pools
Since most of the work is I/O bound the AWS collector will spawn multiple threads to collect accounts and regions in parallel.
The number of which can be specified using the `--aws-account-pool-size` and `--aws-region-pool-size` arguments.
The defaults are chosen so cloudkeeper would collect five accounts and all regions at a time.

## Miscellaneous Options
When working with distributed cloudkeeper instances cloudkeeper stores the role name that was used to retrieve a resource originally inside the graph.
In a scenario where for example you would have multiple collector instances and one cleaner instance this would mean that each instance can be given a unique role with very locked down access permissions. However when a cleaner instance collects all these remote graphs and merges them into one you might not want to use the same role that was used for collection of resources. In this case the cleaner could make use of its own role `--aws-role` and specify `--aws-role-override` so that cloudkeeper knows to use that role when performing any operations (like tagging or deleting) on those resources.

When collecting multiple accounts cloudkeeper by default will collect the accounts it finds in the org as well as the one it is currently authenticated as.
If you do not want it to scrape the account that was used to get the list of all org accounts (e.g. your root account) you can specify `--aws-dont-scrape-current`.

If instead of using the current credentials you would like cloudkeeper to assume the specified role (`--aws-role`) even for the current account you can specify the options
`--aws-assume-current` and `--aws-dont-scrape-current`. This would make it so that cloudkeeper does not scrape the current account using default credentials but instead assume the specified IAM role even for the current account.
