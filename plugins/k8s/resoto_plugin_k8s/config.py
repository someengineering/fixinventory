from dataclasses import dataclass, field
from typing import List, ClassVar, Optional


@dataclass
class K8sConfig:
    kind: ClassVar[str] = "k8s"
    context: List[str] = field(
        default_factory=list, metadata={"description": "Kubernetes Context(s)"}
    )
    config: Optional[List[str]] = field(
        default=None, metadata={"description": "Kubernetes Config File(s)"}
    )
    cluster: List[str] = field(
        default_factory=list, metadata={"description": "Kubernetes Cluster Name(s)"}
    )
    apiserver: List[str] = field(
        default_factory=list, metadata={"description": "Kubernetes API Server(s)"}
    )
    token: List[str] = field(
        default_factory=list, metadata={"description": "Kubernetes Token(s)"}
    )
    cacert: List[str] = field(
        default_factory=list, metadata={"description": "Kubernetes CA Certificate(s)"}
    )
    collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Kubernetes objects to collect (default: all)"},
    )
    no_collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Kubernetes objects to exclude (default: none)"},
    )
    pool_size: int = field(
        default=5, metadata={"description": "Kubernetes thread/process pool size"}
    )
    fork: bool = field(
        default=False,
        metadata={"description": "Fork collector process instead of using threads"},
    )
    all_contexts: bool = field(
        default=False,
        metadata={"description": "Collect all contexts in kubeconfig file"},
    )
