# cloudkeeper-plugin-ckcore
ckcore Plugin for Cloudkeeper (Pre-Alpha)

An MVP that takes a Cloudkeeper Graph, extracts the model and pushes it to [ckcore](https://github.com/someengineering/ckcore) for persistance.


## Usage
When a ckcore endpoint URI is specified (`--ckcore-uri`) the plugin will subscribe to the `COLLECT_FINISH` event and when called push the graph data to ckcore.

## List of arguments
```
  --ckcore-uri CKCORE_URI
                        ckcore URI
```
