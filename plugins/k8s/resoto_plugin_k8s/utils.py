import resotolib.logging
from resotolib.args import ArgumentParser
from typing import Dict
from kubernetes import client, config


log = resotolib.logging.getLogger("resoto." + __name__)


def k8s_config() -> Dict:
    cfg = {}
    num_k8s_clusters = len(ArgumentParser.args.k8s_cluster)
    num_k8s_apiserver = len(ArgumentParser.args.k8s_apiserver)
    num_k8s_token = len(ArgumentParser.args.k8s_token)
    num_k8s_cacerts = len(ArgumentParser.args.k8s_cacert)

    if not (num_k8s_clusters == num_k8s_token == num_k8s_apiserver == num_k8s_cacerts):
        log_msg = (
            f"Number of K8S clusters ({num_k8s_clusters}), API servers"
            f" ({num_k8s_apiserver}), CA Certs ({num_k8s_cacerts}) and tokens"
            f" ({num_k8s_token}) not equal."
        )
        raise RuntimeError(log_msg)

    if len(ArgumentParser.args.k8s_cluster) != len(
        set(ArgumentParser.args.k8s_cluster)
    ):
        log_msg = "List of Kubernetes clusters contains duplicate entries"
        raise RuntimeError(log_msg)

    cluster_context_conflicts = set(ArgumentParser.args.k8s_context).intersection(
        set(ArgumentParser.args.k8s_cluster)
    )
    if len(cluster_context_conflicts) != 0:
        log_msg = (
            "Kubernetes cluster name(s) conflict with context(s):"
            f" {', '.join(cluster_context_conflicts)}"
        )
        raise RuntimeError(log_msg)

    try:
        contexts, active_context = config.list_kube_config_contexts(
            config_file=ArgumentParser.args.k8s_config
        )
    except config.config_exception.ConfigException as e:
        log.error(e)
    else:
        if contexts:
            if ArgumentParser.args.k8s_all_contexts:
                log.debug(
                    "importing all contexts in configuration file since --k8s-all-contexts was specified"
                )
            elif (
                len(ArgumentParser.args.k8s_context) == 0
                and len(ArgumentParser.args.k8s_cluster) == 0
            ):
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
                    not ArgumentParser.args.k8s_all_contexts
                    and context not in ArgumentParser.args.k8s_context
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
                    config_file=ArgumentParser.args.k8s_config,
                )
                cfg[context] = k8s_cfg

    for idx, cluster in enumerate(ArgumentParser.args.k8s_cluster):
        k8s_cfg = client.Configuration()
        k8s_cfg.host = ArgumentParser.args.k8s_apiserver[idx]
        k8s_cfg.api_key = {
            "authorization": "Bearer " + ArgumentParser.args.k8s_token[idx]
        }
        k8s_cfg.ssl_ca_cert = ArgumentParser.args.k8s_cacert[idx]
        cfg[cluster] = k8s_cfg

    return cfg
