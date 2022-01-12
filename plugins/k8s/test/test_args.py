from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_k8s import KubernetesCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    KubernetesCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert len(ArgumentParser.args.k8s_context) == 0
    assert ArgumentParser.args.k8s_config is None
    assert len(ArgumentParser.args.k8s_cluster) == 0
    assert len(ArgumentParser.args.k8s_apiserver) == 0
    assert len(ArgumentParser.args.k8s_token) == 0
    assert len(ArgumentParser.args.k8s_cacert) == 0
    assert len(ArgumentParser.args.k8s_collect) == 0
    assert len(ArgumentParser.args.k8s_no_collect) == 0
    assert ArgumentParser.args.k8s_pool_size == 5
    assert ArgumentParser.args.k8s_fork is False
