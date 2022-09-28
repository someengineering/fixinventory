import requests
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .config import ScarfConfig
from typing import Optional
from .scarf import ScarfAPI


class ScarfCollectorPlugin(BaseCollectorPlugin):
    cloud = "scarf"

    def collect(self) -> None:
        log.debug("plugin: collecting Scarf resources")
        scarf = ScarfAPI(Config.scarf.email, Config.scarf.password)

        for organization in Config.scarf.organizations:
            log.debug(f"Collecting Scarf packages in organization {organization}")
            o = scarf.organization(organization)
            self.graph.add_resource(self.graph.root, o)

        for p in scarf.packages():
            o = self.graph.search_first_all({"id": p.owner, "kind": "scarf_organization"})
            if o:
                self.graph.add_resource(o, p)

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
