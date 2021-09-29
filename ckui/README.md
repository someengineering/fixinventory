# Cloudkeeper UI - Prototype
**Cloudkeeper user interface prototype made in Godot (3.3)**

This serves to communicate the vision we work on for the Cloudkeeper UI.
At the moment, this is just a prototype with no functionality except the visual rendition of an exported Cloudkeeper Graph and some fancy UI elements.

**Our goals for this and the upcoming stages**
 - Establishing a basic navigation concept.
 - Trying to rethink the dashboard from a display tool to a deeply connected entry point.
 - Find a smart and intuitive way of integrating the powerful Cloudkeeper query language.
 - Exploring ways of displaying the graph and give the user intuitive tools to navigate it.
 - Having fun exploring the cloud / multi-cloud environment.
 - Easy and useful ways of searching the graph and integrate queries into this concept.

## Disclaimer
This UI currently has no backend connection to Cloudkeeper. It uses static .json files in the src/data/ directory.
It is here to give an idea of how the UI will be looking and feeling and to start early working on it in the frame of the project.

## How to get the UI running
**Follow these steps:**
- Download the [latest Godot 3.x stable](https://godotengine.org/download) (We develop in the standard version).
- Start the engine and import the project in the Project Manager (click import, select the 'project.godot' file).
- Open the project from the Project Manager.
- Run the Project by clicking on the "Play" button in the upper right corner.

## How to get your Cloud data into the UI?
Right now it is not possible to get your data into the UI as the format of the json files has changed in Cloudkeeper core.
We will add instructions of how to generate your own .json files soon.

Until then look at the format inside the 'example_data.gd' file to get an idea of the required input.
The UI uses two files for the data it processes:
data/graph_dump.json - This is a dump of the whole node graph from Cloudkeeper
data/prometheus_metrics.json - This is an export from the Prometheus tsdb
