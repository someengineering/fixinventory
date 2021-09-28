# `cksh`
Cloudkeeper Shell


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
`cksh` starts the Cloudkeeper shell. It is used to interact with `ckcore`. It allows you to explore the graph, find resources of interest, mark them for cleanup, fix their tagging, aggregate over their metadata to create metrics and format the output for use in a 3rd party script or system.


## Usage
`cksh` uses the following commandline arguments:
```
  -h, --help            show this help message and exit
  --ckcore-uri CKCORE_URI
                        ckcore URI (default: http://localhost:8900)
  --ckcore-ws-uri CKCORE_WS_URI
                        ckcore Websocket URI (default: ws://localhost:8900)
  --ckcore-graph CKCORE_GRAPH
                        ckcore graph name (default: ck)
  --stdin               Read from STDIN instead of opening a shell
  --verbose, -v         Verbose logging
  --logfile LOGFILE     Logfile to log into
```

ENV Prefix: `CKSH_`  
Every CLI arg can also be specified using ENV variables.

For instance `--ckcore-uri http://foobar.tld:8900` would become `CKSH_CKCORE_URI=http://foobar.tld:8900`.



## Examples
### Basics
Enter `help` into `cksh` to get an overview of all available commands
```
> help
Valid placeholder string:
   @UTC@ -> 2021-09-28T16:08:32Z
   @NOW@ -> 2021-09-28T16:08:32Z
   @TODAY@ -> 2021-09-28
   @TOMORROW@ -> 2021-09-29
   @YESTERDAY@ -> 2021-09-27
   @YEAR@ -> 2021
   @MONTH@ -> 09
   @DAY@ -> 28
   @TIME@ -> 16:08:32
   @HOUR@ -> 16
   @MINUTE@ -> 08
   @SECOND@ -> 32
   @TZ_OFFSET@ -> +0000
   @TZ@ -> UTC
   @MONDAY@ -> 2021-10-04
   @TUESDAY@ -> 2021-09-28
   @WEDNESDAY@ -> 2021-09-29
   @THURSDAY@ -> 2021-09-30
   @FRIDAY@ -> 2021-10-01
   @SATURDAY@ -> 2021-10-02
   @SUNDAY@ -> 2021-10-03
Available Commands:
   add_job - Add job to the system.
   aggregate - Aggregate this query by the provided specification
   ancestors - Select all ancestors of this node in the graph.
   chunk - Chunk incoming elements in batches.
   clean - Mark all incoming database objects for cleaning.
   count - Count incoming elements or sum defined property.
   delete_job - Remove job from the system.
   descendants - Select all descendants of this node in the graph.
   desired - Matches a property in the desired section.
   echo - Send the provided message to downstream
   env - Retrieve the environment and pass it to the output stream.
   flatten - Take incoming batches of elements and flattens them to a stream of single elements.
   format - Transform incoming objects as string with a defined format.
   head - Return n first elements of the stream.
   help - Shows available commands, as well as help for any specific command.
   jobs - list all jobs in the system.
   json - Parse json and pass parsed objects to the output stream.
   kind - Retrieves information about the graph data kinds.
   merge_ancestors - Merge the results of this query with the content of ancestor nodes of given type
   metadata - Matches a property in the metadata section.
   predecessors - Select all predecessors of this node in the graph.
   protect - Mark all incoming database objects as protected.
   query - Matches a property in all sections.
   reported - Matches a property in the reported section.
   set_desired - Allows to set arbitrary properties as desired for all incoming database objects.
   set_metadata - Allows to set arbitrary properties as metadata for all incoming database objects.
   sleep - Suspend execution for an interval of time
   start_task - Start a task with the given name.
   successors - Select all successor of this node in the graph.
   tag - Update a tag with provided value or delete a tag
   tail - Return n last elements of the stream.
   tasks - Lists all currently running tasks.
   uniq - Remove all duplicated objects from the stream.
Available Aliases:
   match (reported) - Matches a property in the reported section.
   start_workflow (start_task) - Start a task with the given name.
   start_job (start_task) - Start a task with the given name.
Note that you can pipe commands using the pipe character (|)
and chain multiple commands using the semicolon (;).
```

Using `help` followed by a command will provide more information about that command.
```
> help query
query - Matches a property in all sections.
Usage: query <property.path> <op> <value"
Part of a query.
With this command you can query all sections directly.
In order to define the section, all parameters have to be prefixed by the section name.
The property is the complete path in the json structure.
Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
value is a json encoded value to match.
Example:
    query reported.prop1 == "a"          # matches documents with reported section like { "prop1": "a" ....}
    query desired.some.nested in [1,2,3] # matches documents with desired section like { "some": { "nested" : 1 ..}
    query reported.array[*] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }
    query reported.array[1] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }
Environment Variables:
    graph [mandatory]: the name of the graph to operate on
```


### Intermediate
Show all storage volumes that are in use
```
> match is(volume) and volume_status = in-use
```

Show all storage volumes in use and format the output as CSV
```
> match is(volume) and volume_status = in-use | format {reported.kind},{reported.id},{reported.name},{reported.ctime}
```

Show all storage volumes not in use with a size of more than 10 GB
```
> match is(volume) and volume_status = available and volume_size > 10
```


### Advanced
The `match` command is an alias for `reported` meaning it is searching in the reported section of the resource. To query outside the reported section we have to use the `query` command. The syntax is like before just that now whenever we want to filter for an attribute within the reported section we will have to prefix that attribute.

Find volumes in cloud AWS that are in use
```
query is(volume) and reported.volume_status = in-use and metadata.ancestors.cloud.name == aws
```

Alternatively instead of filtering for storage volumes of the generic `volume` kind we can also be more specific
```
match is(aws_ec2_volume) and volume_status = in-use
```

Find unused AWS volumes older than 30 days with no IO in the past 7
```
match is(aws_ec2_volume) and volume_status = available and ctime < -30d and atime < -7d and mtime < -7d
```


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/3G3sX6y3bt) or [open a GitHub issue](https://github.com/someengineering/cloudkeeper/issues/new).


## License
```
Copyright 2021 Some Engineering Inc.

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
