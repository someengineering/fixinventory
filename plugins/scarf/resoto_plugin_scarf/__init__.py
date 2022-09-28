import requests
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .config import ScarfConfig
from typing import Optional
from .resources import (
    ScarfOrganization,
    ScarfPackage,
)
from base64 import b64encode


class ScarfCollectorPlugin(BaseCollectorPlugin):
    cloud = "scarf"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.scarf_uri = "https://scarf.sh/api/v1/"

    def collect(self) -> None:
        log.debug("plugin: collecting Scarf resources")

        for organization in Config.scarf.organizations:
            log.debug(f"Collecting Scarf packages in organization {organization}")

            uri = f"{self.scarf_uri}{organization}"

            r = fetch_uri(uri)

            o = ScarfNamespace.new(r)
            self.graph.add_resource(self.graph.root, o)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(ScarfConfig)


def fetch_uri(uri: str) -> Optional[dict]:
    log.debug(f"Getting {uri}")
    headers = {"Authorization": f"Bearer {Config.scarf.token}"}
    r = requests.get(uri, headers=headers)
    if r.status_code != 200:
        log.error(f"Error collecting Scarf resources {uri}: {r.status_code} {r.text}")
        return None
    return r.json()
