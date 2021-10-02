# `ckui`
Cloudkeeper UI prototype


## Table of contents

* [Overview](#overview)
* [How to get the UI running](#overview)
    * [Importing your cloud data into the UI](#importing-your-cloud-data-into-the-ui)
* [Contact](#contact)
* [License](#license)


## Overview
This serves to communicate the vision we work on for the Cloudkeeper UI.
At the moment, this is just a prototype with no functionality except the visual rendition of an exported Cloudkeeper Graph and some fancy UI elements.

**Our goals for this and the upcoming releases**
 - Establishing a basic navigation concept.
 - Trying to rethink the dashboard from a display tool to a deeply connected entry point.
 - Find an intuitive way of integrating the Cloudkeeper query language.
 - Exploring ways of displaying the graph and give the user intuitive tools to navigate it.
 - Having fun exploring the cloud environment.
 - Easy and useful ways of searching the graph and integrate queries into this concept.

This UI currently has no backend connection to Cloudkeeper. It uses static `.json` files in the `src/data/` directory.
It is here to give an idea of how the UI will be looking and feeling and to start early working on it in the frame of the project.


## How to get the UI running
**Follow these steps:**
- Download the [latest Godot 3.x stable](https://godotengine.org/download) (We develop in the standard version).
- Start the engine and import the project in the Project Manager (click import, select the 'project.godot' file).
- Open the project from the Project Manager.
- Run the Project by clicking on the "Play" button in the upper right corner.


### Importing your cloud data into the UI
Right now it is not possible to get your data into the UI as the format of the json files has changed in Cloudkeeper core.

We will add instructions of how to generate your own `.json` files soon.

Until then look at the format inside the `example_data.gd` file to get an idea of the required input.

The UI uses two files for the data it processes:
- `data/graph_dump.json` - This is a dump of the whole node graph from Cloudkeeper
- `data/prometheus_metrics.json` - This is an export from the Prometheus tsdb


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
