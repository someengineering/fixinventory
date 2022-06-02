from resoto_plugin_k8s import K8sConfig, KubernetesCollectorPlugin
from resotolib.config import Config


class JsonResult:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def test_show() -> None:
    # cl = config.new_client_from_config("/Users/matthias/.kube/configs/tmp/dev_resoto")
    #
    # client = K8sClient(cl)
    # version = client.version()
    # ns = client.call_api("/api/v1/namespaces", "GET", auth_settings=["BearerToken"], response_type="object")
    # pods = client.call_api("/api/v1/pods", "GET", auth_settings=["BearerToken"], response_type="object")
    # nodes = client.call_api("/api/v1/nodes", "GET", auth_settings=["BearerToken"], response_type="object")
    # dy = client.call_api("/apis/apps/v1/deployments", "GET", auth_settings=["BearerToken"], response_type="object")
    # deploy = client.call_api("/apis/apps/v1/deployments", "GET", auth_settings=["BearerToken"], response_type="object")

    # versions = client.apis()
    # vs = {v.path.rsplit("/", 1)[0] for v in versions}
    # print("\n".join(vs))

    Config.k8s = K8sConfig(config="/Users/matthias/.kube/configs/tmp/dev_resoto")
    plugin = KubernetesCollectorPlugin()
    plugin.collect()
