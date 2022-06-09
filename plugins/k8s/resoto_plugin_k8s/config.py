import logging
from dataclasses import dataclass, field
from textwrap import dedent
from typing import List, ClassVar, Dict

from kubernetes.client import Configuration
from kubernetes.config import load_kube_config, list_kube_config_contexts

from resotolib.utils import num_default_threads

log = logging.getLogger("resoto." + __name__)


@dataclass
class K8sAccess:
    kind: ClassVar[str] = "k8s_access"
    name: str = field(metadata={"description": "The name of the kubernetes cluster."})
    certificate_authority_data: str = field(metadata={"description": "The CA certificate string."})
    server: str = field(metadata={"description": "The url of the server to connect to."})
    token: str = field(metadata={"description": "The user access token to use to access this cluster."})

    def to_yaml(self) -> str:
        return dedent(
            f"""
             apiVersion: v1
             clusters:
             - cluster:
                 certificate-authority-data: {self.certificate_authority_data}
                 server: {self.server}
               name: {self.name}
             contexts:
             - context:
                 cluster: {self.name}
                 user: access-{self.name}
                 namespace: resoto
               name: {self.name}
             current-context: {self.name}
             kind: Config
             preferences: {{}}
             users:
             - name: access-{self.name}
               user:
                 token: {self.token}
        """
        )


@dataclass
class K8sConfigFile:
    kind: ClassVar[str] = "k8s_config_file"
    path: str = field(metadata={"description": "Path to the kubeconfig file."})
    contexts: List[str] = field(
        default_factory=list,
        metadata={
            "description": "The contexts to use in the specified config file.\n"
            "You can also set all_contexts to true to use all contexts."
        },
    )
    all_contexts: bool = field(
        default=True,
        metadata={"description": "Collect all contexts found in the kubeconfig file."},
    )


@dataclass
class K8sConfig:
    kind: ClassVar[str] = "k8s"
    configs: List[K8sAccess] = field(
        default_factory=list,
        metadata={
            "description": dedent(
                """
                Configure access to k8s clusters.
                Structure:
                - name: 'k8s-cluster-name'
                  certificate_authority_data: 'CERT'
                  server: 'https://k8s-cluster-server.example.com'
                  token: 'TOKEN'
                """
            ).strip()
        },
    )

    config_files: List[K8sConfigFile] = field(
        default_factory=list,
        metadata={
            "description": dedent(
                """
                Configure access via kubeconfig files.
                Structure:
                Structure:
                  - path: "/path/to/kubeconfig"
                    all_contexts: false
                    contexts: ["context1", "context2"]
                """
            ).strip()
        },
    )

    collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Objects to collect (default: all)"},
    )
    no_collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Objects to exclude (default: none)"},
    )
    pool_size: int = field(
        default_factory=num_default_threads,
        metadata={"description": "Thread/process pool size"},
    )
    fork_process: bool = field(
        default=False,
        metadata={"description": "Fork collector process instead of using threads"},
    )

    def is_allowed(self, kind: str) -> bool:
        return (not self.collect or kind in self.collect) and kind not in self.no_collect

    def cluster_access_configs(self, tmp_dir: str) -> Dict[str, Configuration]:
        result = {}
        cfg_files = self.config_files

        # write all access configs as kubeconfig file and let the loader handle it
        for ca in self.configs:
            filename = tmp_dir + "/" + ca.name + ".yaml"
            with open(filename, "w") as f:
                f.write(ca.to_yaml())
            cfg_files.append(K8sConfigFile(path=filename))

        # load all kubeconfig files
        for cf in cfg_files:
            all_contexts, active_context = list_kube_config_contexts(cf.path)
            contexts = all_contexts if cf.all_contexts else [a for a in all_contexts if a["name"] in cf.contexts]
            for ctx in contexts:
                name = ctx["name"]
                config = Configuration()
                load_kube_config(cf.path, name, client_configuration=config)
                result[name] = config

        return result
