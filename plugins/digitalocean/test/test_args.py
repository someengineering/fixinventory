from resotolib import graph
from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_digitalocean import DigitalOceanCollectorPlugin
import resoto_digitalocean_openapi_client
from resoto_plugin_digitalocean.client import StreamingWrapper
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
import os
import json
import re
from resotolib.graph import sanitize


def test_args():
    arg_parser = get_arg_parser()
    DigitalOceanCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.digitalocean_region is None
