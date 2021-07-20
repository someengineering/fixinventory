# cloudkeeper-plugin-keepercore
Keepercore Plugin for Cloudkeeper (Pre-Alpha)

An MVP that takes a Cloudkeeper Graph, extracts the model and pushes it to [Keepercore](https://github.com/someengineering/keepercore) for persistance.


## Usage
When a keepercore endpoint URI is specified (`--keepercore-uri`) the plugin will subscribe to the `COLLECT_FINISH` event and when called push the graph data to keepercore.

## List of arguments
```
  --keepercore-uri KEEPERCORE_URI
                        Keepercore URI
```
