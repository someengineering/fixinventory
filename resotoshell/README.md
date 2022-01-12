# `resh`
resoto Shell


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


## Usage
`resh` uses the following commandline arguments:
```
  -h, --help            show this help message and exit
  --resotocore-uri RESOTOCORE_URI
                        resotocore URI (default: http://localhost:8900)
  --resotocore-ws-uri RESOTOCORE_WS_URI
                        resotocore Websocket URI (default: ws://localhost:8900)
  --resotocore-graph RESOTOCORE_GRAPH
                        resotocore graph name (default: resoto)
  --stdin               Read from STDIN instead of opening a shell
  --verbose, -v         Verbose logging
  --logfile LOGFILE     Logfile to log into
```

ENV Prefix: `resh_`
Every CLI arg can also be specified using ENV variables.

For instance `--resotocore-uri http://foobar.tld:8900` would become `resh_RESOTOCORE_URI=http://foobar.tld:8900`.



## Examples
### Basics
Enter `help` into `resh` to get an overview of all available commands
```
> help

resotocore CLI


Valid placeholder string:
   @UTC@ -> 2022-01-12T09:20:02Z
   @NOW@ -> 2022-01-12T10:20:02Z
   @TODAY@ -> 2022-01-12
   @TOMORROW@ -> 2022-01-13
   @YESTERDAY@ -> 2022-01-11
   @YEAR@ -> 2022
   @MONTH@ -> 01
   @DAY@ -> 12
   @TIME@ -> 10:20:02
   @HOUR@ -> 10
   @MINUTE@ -> 20
   @SECOND@ -> 02
   @TZ_OFFSET@ -> +0100
   @TZ@ -> CET
   @MONDAY@ -> 2022-01-17
   @TUESDAY@ -> 2022-01-18
   @WEDNESDAY@ -> 2022-01-12
   @THURSDAY@ -> 2022-01-13
   @FRIDAY@ -> 2022-01-14
   @SATURDAY@ -> 2022-01-15
   @SUNDAY@ -> 2022-01-16

Available Commands:
   aggregate - Aggregate this query by the provided specification
   ancestors - Select all ancestors of this node in the graph.
   chunk - Chunk incoming elements in batches.
   clean - Mark all incoming database objects for cleaning.
   count - Count incoming elements or sum defined property.
   descendants - Select all descendants of this node in the graph.
   desired - Matches a property in the desired section.
   dump - Dump all properties of incoming objects.
   echo - Send the provided message to downstream
   env - Retrieve the environment and pass it to the output stream.
   flatten - Take incoming batches of elements and flattens them to a stream of single elements.
   format - Transform incoming objects as string with a defined format.
   head - Return n first elements of the stream.
   help - Shows available commands, as well as help for any specific command.
   jobs - List all jobs in the system.
   jq - Filter and process json.
   json - Parse json and pass parsed objects to the output stream.
   kind - Retrieves information about the graph data kinds.
   list - Transform incoming objects as string with defined properties.
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
   system - Access and manage system wide properties.
   tag - Update a tag with provided value or delete a tag
   tail - Return n last elements of the stream.
   templates - Access the query template library.
   uniq - Remove all duplicated objects from the stream.
   write - Writes the incoming stream of data to a file in the defined format.

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

Usage: query [--include-edges] [--explain] <property.path> <op> <value"

Part of a query.
With this command you can query all sections directly.
In order to define the section, all parameters have to be prefixed by the section name.

The property is the complete path in the json structure.
Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
value is a json encoded value to match.

Use --explain to understand the cost of a query. A query explanation has this form (example):
{
    "available_nr_items": 142670,
    "estimated_cost": 61424,
    "estimated_nr_items": 1,
    "full_collection_scan": false,
    "rating": "Simple"
}

- `available_nr_items` describe the number of all available nodes in the graph.
- `estimated_cost` shows the absolute cost of this query. See rating for an interpreted number.
- `estimated_nr_items` estimated number of items returned for this query.
                       It is computed based on query statistics and heuristics and does not reflect the real number.
- `full_collection_scan` indicates, if a full collection scan is required.
                         In case this is true, the query does not take advantage of any indexes.
- `rating` The more general rating of this query.
           Simple: The estimated cost is fine - the query will most probably run smoothly.
           Complex: The estimated cost is quite high. Check other properties. Maybe an index can be used?
           Bad: The estimated cost is very high. It will most probably run long and/or will take a lot of resources.

Parameter:
    --include-edges: This flag indicates, that not only nodes should be returned, but also all related edges.
    --explain: Instead of executing this query, explain the query cost

Example:
    query reported.prop1 == "a"          # matches documents with reported section like { "prop1": "a" ....}
    query desired.some.nested in [1,2,3] # matches documents with desired section like { "some": { "nested" : 1 ..}
    query reported.array[*] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }
    query reported.array[1] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }
    query --include-edges is(graph_root) -[0:2]-> # returns the descendants from the graph root 2 levels deep
    query --explain is(graph_root) -[0:2]->       # Shows the query cost of provided query
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
The `match` command is an alias for `reported` meaning it is searching in the reported section of the resource. To query outside the reported section we have to use the `query` command. The syntax is like before just that now whenever we want to filter for an attribute within the reported section we will have to prefix that attribute accordingly.

Find volumes in cloud AWS that are in use
```
query is(volume) and reported.volume_status = in-use and metadata.ancestors.cloud.name = aws
```

Alternatively instead of filtering for storage volumes of the generic `volume` kind we can also be more specific
```
match is(aws_ec2_volume) and volume_status = in-use
```

Find unused AWS volumes older than 30 days with no I/O in the past 7 days
```
match is(aws_ec2_volume) and volume_status = available and ctime < -30d and atime < -7d and mtime < -7d
```


## Contact
If you have any questions feel free to [join our Discord](https://discord.gg/someengineering) or [open a GitHub issue](https://github.com/someengineering/resoto/issues/new).


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
