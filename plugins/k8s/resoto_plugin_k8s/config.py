import logging
from dataclasses import dataclass, field
from typing import List, ClassVar, Optional, Dict

from kubernetes import client, config
from kubernetes.client import Configuration
from resotolib.utils import num_default_threads

log = logging.getLogger("resoto." + __name__)


@dataclass
class K8sConfig:
    kind: ClassVar[str] = "k8s"
    context: List[str] = field(default_factory=list, metadata={"description": "Context(s)"})
    config: Optional[str] = field(default=None, metadata={"description": "Config file(s)"})
    cluster: List[str] = field(default_factory=list, metadata={"description": "Cluster name(s)"})
    apiserver: List[str] = field(default_factory=list, metadata={"description": "API Server(s)"})
    token: List[str] = field(default_factory=list, metadata={"description": "Token(s)"})
    cacert: List[str] = field(default_factory=list, metadata={"description": "CA certificate(s)"})
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
    all_contexts: bool = field(
        default=False,
        metadata={"description": "Collect all contexts in kubeconfig file"},
    )

    def is_allowed(self, kind: str) -> bool:
        return (not self.collect or kind in self.collect) and kind not in self.no_collect

    def cluster_access_configs(self) -> Dict[str, Configuration]:
        cfg = {}
        num_k8s_clusters = len(self.cluster)
        num_k8s_apiserver = len(self.apiserver)
        num_k8s_token = len(self.token)
        num_k8s_cacerts = len(self.cacert)

        if not (num_k8s_clusters == num_k8s_token == num_k8s_apiserver == num_k8s_cacerts):
            log_msg = (
                f"Number of K8S clusters ({num_k8s_clusters}), API servers"
                f" ({num_k8s_apiserver}), CA Certs ({num_k8s_cacerts}) and tokens"
                f" ({num_k8s_token}) not equal."
            )
            raise RuntimeError(log_msg)

        if len(self.cluster) != len(set(self.cluster)):
            log_msg = "List of Kubernetes clusters contains duplicate entries"
            raise RuntimeError(log_msg)

        cluster_context_conflicts = set(self.context).intersection(set(self.cluster))
        if len(cluster_context_conflicts) != 0:
            log_msg = "Kubernetes cluster name(s) conflict with context(s):" f" {', '.join(cluster_context_conflicts)}"
            raise RuntimeError(log_msg)

        try:
            contexts, active_context = config.list_kube_config_contexts(config_file=self.config)
        except config.config_exception.ConfigException as e:
            log.error(e)
        else:
            if contexts:
                if self.all_contexts:
                    log.debug("importing all contexts in configuration file since --k8s-all-contexts was specified")
                elif len(self.context) == 0 and len(self.cluster) == 0:
                    active_context = active_context["name"]
                    log.debug(
                        (
                            "no --k8s-context or --k8s-cluster specified, defaulting to"
                            f" active context {active_context}. To import all contexts"
                            " in configuration file, use --k8s-all-contexts"
                        )
                    )
                else:
                    active_context = None

                contexts = [context["name"] for context in contexts]

                for context in contexts:
                    if not self.all_contexts and context not in self.context and context != active_context:
                        log.debug(f"skipping context {context} as it is not specified" " in --k8s-context")
                        continue
                    log.debug(f"loading context {context}")
                    k8s_cfg = client.Configuration()
                    config.load_kube_config(
                        context=context,
                        client_configuration=k8s_cfg,
                        config_file=self.config,
                    )
                    cfg[context] = k8s_cfg

        for idx, cluster in enumerate(self.cluster):
            k8s_cfg = client.Configuration()
            k8s_cfg.host = self.apiserver[idx]
            k8s_cfg.api_key = {"authorization": "Bearer " + self.token[idx]}
            k8s_cfg.ssl_ca_cert = self.cacert[idx]
            cfg[cluster] = k8s_cfg

        return cfg
