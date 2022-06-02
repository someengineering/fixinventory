from kubernetes import config
from resoto_plugin_k8s.collector import K8sClient


class JsonResult:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def test_show() -> None:
    cl = config.new_client_from_config("/Users/matthias/.kube/configs/tmp/dev_resoto")
    client = K8sClient(cl)

    # ns = client.call_api("/api/v1/namespaces", "GET", auth_settings=["BearerToken"], response_type="object")
    # pods = client.call_api("/api/v1/pods", "GET", auth_settings=["BearerToken"], response_type="object")
    # nodes = client.call_api("/api/v1/nodes", "GET", auth_settings=["BearerToken"], response_type="object")
    # dy = client.call_api("/apis/apps/v1/deployments", "GET", auth_settings=["BearerToken"], response_type="object")
    # deploy = client.call_api("/apis/apps/v1/deployments", "GET", auth_settings=["BearerToken"], response_type="object")

    versions = client.apis()
    vs = {v.path.rsplit("/", 1)[0] for v in versions}
    print("\n".join(vs))
