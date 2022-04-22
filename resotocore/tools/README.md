# Getting started with graph rendering script

## Setup process
1. If you haven't done this already, install the [resoto development environment](https://resoto.com/docs/contributing/components).
2. Now, you need to [install graphviz](https://graphviz.org/download/). 
3. Additionally, you will need access to a running resotocore instance.

## Usage

To run the script, use a python interpreter and provide the search command. For example:

```
python3 render_dot.py 'search --with-edges is(digitalocean_droplet) <-[0:]->'
```
It is also possible to change the graphviz layout engine to render the graph differently:

```
python3 render_dot.py 'search --with-edges is(digitalocean_droplet) <-[0:]->' --engine dot
```

Possible layout engines are `dot`, `neato`, `twopi`, `circo`, `fdp`, `osage`, `patchwork`, and `sfdp`.


Full list of launch options:
```
usage: render_dot.py [-h] [--engine ENGINE] [--format FORMAT] [--output OUTPUT] [--psk PSK] [--resotocore-uri URI] query

positional arguments:
  query                 query for visualization

optional arguments:
  -h, --help            show this help message and exit
  --engine ENGINE       graphviz layout engine to use
  --format FORMAT       output format
  --output OUTPUT       output file
  --psk PSK             Pre shared key to be passed to resh
  --resotocore-uri URI  resotocore URI
  ```
