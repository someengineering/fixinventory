from cloudkeeper.graph import Graph
from pprint import pformat


class KubernetesResource:
    def __init__(self, *args, api_response=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_response = pformat(api_response)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented
