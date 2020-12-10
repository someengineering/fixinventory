from cloudkeeper.graph import Graph
from pprint import pformat
import kubernetes


class KubernetesResource:
    def __init__(self, *args, api_response=None, self_link: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_response = pformat(api_response)
        self.self_link = self_link

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented
