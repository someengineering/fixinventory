import resotolib.logger
from resotolib.config import Config
from typing import Dict
from kubernetes import client, config


log = resotolib.logger.getLogger("resoto." + __name__)


def k8s_config() -> Dict:
    cfg = {}
    num_k8s_clusters = len(Config.k8s.cluster)
    num_k8s_apiserver = len(Config.k8s.apiserver)
    num_k8s_token = len(Config.k8s.token)
    num_k8s_cacerts = len(Config.k8s.cacert)

    if not (num_k8s_clusters == num_k8s_token == num_k8s_apiserver == num_k8s_cacerts):
        log_msg = (
            f"Number of K8S clusters ({num_k8s_clusters}), API servers"
            f" ({num_k8s_apiserver}), CA Certs ({num_k8s_cacerts}) and tokens"
            f" ({num_k8s_token}) not equal."
        )
        raise RuntimeError(log_msg)

    if len(Config.k8s.cluster) != len(set(Config.k8s.cluster)):
        log_msg = "List of Kubernetes clusters contains duplicate entries"
        raise RuntimeError(log_msg)

    cluster_context_conflicts = set(Config.k8s.context).intersection(
        set(Config.k8s.cluster)
    )
    if len(cluster_context_conflicts) != 0:
        log_msg = (
            "Kubernetes cluster name(s) conflict with context(s):"
            f" {', '.join(cluster_context_conflicts)}"
        )
        raise RuntimeError(log_msg)

    try:
        contexts, active_context = config.list_kube_config_contexts(
            config_file=Config.k8s.config
        )
    except config.config_exception.ConfigException as e:
        log.error(e)
    else:
        if contexts:
            if Config.k8s.all_contexts:
                log.debug(
                    "importing all contexts in configuration file since --k8s-all-contexts was specified"
                )
            elif len(Config.k8s.context) == 0 and len(Config.k8s.cluster) == 0:
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
                if (
                    not Config.k8s.all_contexts
                    and context not in Config.k8s.context
                    and context != active_context
                ):
                    log.debug(
                        f"skipping context {context} as it is not specified"
                        " in --k8s-context"
                    )
                    continue
                log.debug(f"loading context {context}")
                k8s_cfg = client.Configuration()
                config.load_kube_config(
                    context=context,
                    client_configuration=k8s_cfg,
                    config_file=Config.k8s.config,
                )
                cfg[context] = k8s_cfg

    for idx, cluster in enumerate(Config.k8s.cluster):
        k8s_cfg = client.Configuration()
        k8s_cfg.host = Config.k8s.apiserver[idx]
        k8s_cfg.api_key = {"authorization": "Bearer " + Config.k8s.token[idx]}
        k8s_cfg.ssl_ca_cert = Config.k8s.cacert[idx]
        cfg[cluster] = k8s_cfg

    return cfg
