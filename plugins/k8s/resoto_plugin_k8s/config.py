from dataclasses import dataclass, field
from typing import List, ClassVar, Optional


@dataclass
class K8sConfig:
    kind: ClassVar[str] = "k8s"
    context: List[str] = field(
        default_factory=list, metadata={"description": "Context(s)"}
    )
    config: Optional[List[str]] = field(
        default=None, metadata={"description": "Config file(s)"}
    )
    cluster: List[str] = field(
        default_factory=list, metadata={"description": "Cluster name(s)"}
    )
    apiserver: List[str] = field(
        default_factory=list, metadata={"description": "API Server(s)"}
    )
    token: List[str] = field(default_factory=list, metadata={"description": "Token(s)"})
    cacert: List[str] = field(
        default_factory=list, metadata={"description": "CA certificate(s)"}
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
        default=5, metadata={"description": "Thread/process pool size"}
    )
    fork: bool = field(
        default=True,
        metadata={"description": "Fork collector process instead of using threads"},
    )
    all_contexts: bool = field(
        default=False,
        metadata={"description": "Collect all contexts in kubeconfig file"},
    )
