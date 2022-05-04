# resoto-plugin-aws
An AWS collector plugin for Resoto.

## Usage
For details on how to edit configuration, please see [the documentation](https://resoto.com/docs/getting-started/configuring-resoto).

When the collector is enabled (`resotoworker.collector = [aws]`) it will automatically collect any accounts the AWS boto3 SDK can authenticate for.
By default it will check for environment variables like `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `AWS_SESSION_TOKEN`.

If Resoto should assume an IAM role that role can be given via `resotoworker.aws.role = SomeRoleName`.

The collector will scrape resources in all regions unless regions are specified using e.g. `resotoworker.aws.region = [us-east-1, us-west-2]`.


## Scraping multiple accounts
If the given credentials are allowed to assume the specified role in other accounts of your AWS organisation, Resoto
can collect multiple accounts at the same time. To do so provide the account IDs to the `resotoworker.aws.account` configuration.

## Scraping the entire organisation
Instead of giving a list of account IDs manually you could also specify `resotoworker.aws.scrape_org`, which will make Resoto try to get the list of all accounts using the [ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) API.

If certain accounts are to be excluded from that list they can be specified using the `resotoworker.aws.scrape_exclude_account` config option.

## Miscellaneous Options
When collecting multiple accounts Resoto by default will collect the accounts it finds in the org as well as the one it is currently authenticated as.
If you do not want it to scrape the account that was used to get the list of all org accounts (e.g. your root account) you can specify `resotoworker.aws.dont_scrape_current`.

If instead of using the current credentials you would like Resoto to assume the specified role (`resotoworker.aws.role`) even for the current account you can specify the options
`resotoworker.aws.assume_current` and `resotoworker.aws.dont_scrape_current`. This would make it so that Resoto does not scrape the current account using default credentials but instead assume the specified IAM role even for the current account.
