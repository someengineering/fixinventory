# `resh`
Resoto Shell


## Table of contents

* [Overview](#overview)
* [Usage](#usage)
* [Examples](#examples)
    * [Basics](#basics)
    * [Intermediate](#intermediate)
    * [Advanced](#advanced)
* [Contact](#contact)
* [License](#license)


## Overview
`resh` starts the resoto shell. It is used to interact with `resotocore`. It allows you to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.

More information can be found below and in [the docs](https://resoto.com/docs/concepts/components/shell).


## Usage
`resh` uses the following commandline arguments:
```
  --resotocore-uri RESOTOCORE_URI
                        resotocore URI (default: https://localhost:8900)
  --resotocore-section RESOTOCORE_SECTION
                        All queries are interpreted with this section name. If not set, the server default is used.
  --resotocore-graph RESOTOCORE_GRAPH
                        The name of the graph to use by default. If not set, the server default is used.
  --download-directory DOWNLOAD_DIRECTORY
                        If files are received, they are written to this directory.
  --no-color            Output should be rendered plain without any color escape sequences.
  --stdin               Read from STDIN instead of opening a shell
  --verbose, -v         Verbose logging
  --quiet               Only log errors
  --psk PSK             Pre-shared key
  --ca-cert CA_CERT     Path to custom CA certificate file
  --no-verify-certs     Turn off certificate verification
```

ENV Prefix: `RESOTOSHELL_`
Every CLI arg can also be specified using ENV variables.

For instance `--resotocore-uri http://foobar.tld:8900` would become `RESOTOSHELL_RESOTOCORE_URI=http://foobar.tld:8900`.



## Examples
### Basics
Enter `help` into `resh` to get an overview of all available commands

Using `help` followed by a command will provide more information about that command.


### Intermediate
Show all storage volumes that are in use
```
> search is(volume) and volume_status = in-use
```

Show all storage volumes in use and format the output as CSV
```
> search is(volume) and volume_status = in-use | format {kind},{id},{name},{ctime}
```

Show all storage volumes not in use with a size of more than 10 GB
```
> search is(volume) and volume_status = available and volume_size > 10
```


### Advanced
Find volumes in cloud AWS that are in use
```
search is(volume) and volume_status = in-use and /ancestors.cloud.reported.name = aws
```

Alternatively instead of filtering for storage volumes of the generic `volume` kind we can also be more specific
```
search is(aws_ec2_volume) and volume_status = in-use
```

Find unused AWS volumes older than 30 days with no I/O in the past 7 days
```
search is(aws_ec2_volume) and volume_status = available and ctime < -30d and atime < -7d and mtime < -7d
```


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/someengineering) or [open a GitHub issue](https://github.com/someengineering/resoto/issues/new).


## License
```
Copyright 2022 Some Engineering Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
