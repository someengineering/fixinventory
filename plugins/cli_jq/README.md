# cloudkeeper-plugin-cli_jq
Cloudkeeper CLI plugin providing the jq command

Items are processed one by one. I.e. the default input is a single resource.
```
> match kind = aws_account | jq .rtdname
```

If the entire resource list is required the `dump --json` command can help.
```
> match kind = aws_account | dump --json | jq .[].rtdname
```

This will require the entire resource list to be temporarily held in memory
as one large JSON string object. However jq processing is typically faster
in this mode of operation.
