# resoto-plugin-aws
An AWS collector plugin for resoto.

## Usage
When the collector is enabled (`--collector aws`) it will automatically collect any accounts the AWS boto3 SDK can authenticate for.
By default it will check for environment variables like `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `AWS_SESSION_TOKEN`.
Optionally credentials can be given as commandline arguments using the `--aws-access-key-id` and `--aws-secret-access-key` arguments.

If resoto should assume an IAM role that role can be given via `--aws-role SomeRoleName`.

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
  --aws-fork            Use forked processes instead of threads (default: False)
  --aws-scrape-exclude-account AWS_SCRAPE_EXCLUDE_ACCOUNT [AWS_SCRAPE_EXCLUDE_ACCOUNT ...]
                        AWS exclude this Account when scraping the org
  --aws-assume-current  Assume role in current account (default: False)
  --aws-dont-scrape-current
                        Don't scrape current account (default: False)
  --aws-account-pool-size AWS_ACCOUNT_POOL_SIZE
                        AWS Account Thread Pool Size (default: 5)
  --aws-region-pool-size AWS_REGION_POOL_SIZE
                        AWS Region Thread Pool Size (default: 20)
  --aws-collect AWS_COLLECT [AWS_COLLECT ...]
                        AWS services to collect (default: all)
  --aws-no-collect AWS_NO_COLLECT [AWS_NO_COLLECT ...]
                        AWS services not to collect
```

## Scraping multiple accounts
If the given credentials are allowed to assume the specified role in other accounts of your AWS organisation resoto
can collect multiple accounts at the same time. To do so provide the account IDs to the `--aws-account` argument.

## Scraping the entire organisation
Instead of giving a list of account IDs manually you could also specify `--aws-scrape-org`, which will make resoto
try to get the list of all accounts using the [ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) API.

If certain accounts are to be excluded from that list they can be specified using the `--aws-scrape-exclde-account` argument.

## Worker pools
Since a lot of the work is I/O bound the AWS collector will spawn multiple threads to collect accounts and regions in parallel.
The number of which can be specified using the `--aws-account-pool-size` and `--aws-region-pool-size` arguments.
The defaults are chosen so resoto would collect five accounts and all regions at a time.

For better performance at the expense of higher memory and CPU consumption during collection specify `--aws-fork`. To give an idea of the performance that can be expected. In our organization on a decent server with 32 cores and 128 GB RAM collecting 40 accounts with `--aws-account-pool-size 40 --aws-region-pool-size 15` using standard Python ThreadPools takes on the order of one hour. Specifying `--aws-fork` will reduce that time to about six minutes. On the other hand running the same on a low end m5.xlarge instance with an account pool size of 8 did not show any significant performance improvements but consumed four times the memory during collection compared to the thread pool method. Once the graph is collected and merged there is no difference in memory consumption between both methods.

So the recommendation is, if you want to collect more than a handful of accounts in high intervals use a high end system and specify `--aws-fork`.

## Miscellaneous Options
When working with distributed resoto instances resoto stores the role name that was used to retrieve a resource originally inside the graph.
In a scenario where for example you would have multiple collector instances and one cleaner instance this would mean that each instance can be given a unique role with very locked down access permissions. However when a cleaner instance collects all these remote graphs and merges them into one you might not want to use the same role that was used for collection of resources. In this case the cleaner could make use of its own role `--aws-role` and specify `--aws-role-override` so that resoto knows to use that role when performing any operations (like tagging or deleting) on those resources.

When collecting multiple accounts resoto by default will collect the accounts it finds in the org as well as the one it is currently authenticated as.
If you do not want it to scrape the account that was used to get the list of all org accounts (e.g. your root account) you can specify `--aws-dont-scrape-current`.

If instead of using the current credentials you would like resoto to assume the specified role (`--aws-role`) even for the current account you can specify the options
`--aws-assume-current` and `--aws-dont-scrape-current`. This would make it so that resoto does not scrape the current account using default credentials but instead assume the specified IAM role even for the current account.
