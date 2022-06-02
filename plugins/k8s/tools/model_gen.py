import re
from typing import Dict, List, Tuple, Optional, Set

from prance import ResolvingParser

# base = "https://raw.githubusercontent.com/kubernetes/kubernetes/master/api/openapi-spec/v3/"
base = "/Users/matthias/Documents/Work/someeng/kubernetes/api/openapi-spec/v3/"
api_specs_to_parse = [
    "api__v1_openapi.json",
    "apis__admissionregistration.k8s.io__v1_openapi.json",
    "apis__apps__v1_openapi.json",
    "apis__autoscaling__v1_openapi.json",
    "apis__batch__v1_openapi.json",
    "apis__certificates.k8s.io__v1_openapi.json",
    "apis__coordination.k8s.io__v1_openapi.json",
    "apis__discovery.k8s.io__v1_openapi.json",
    "apis__events.k8s.io__v1_openapi.json",
    "apis__flowcontrol.apiserver.k8s.io__v1beta1_openapi.json",
    "apis__networking.k8s.io__v1_openapi.json",
    "apis__node.k8s.io__v1_openapi.json",
    "apis__policy__v1_openapi.json",
    "apis__rbac.authorization.k8s.io__v1_openapi.json",
    "apis__scheduling.k8s.io__v1_openapi.json",
    "apis__storage.k8s.io__v1_openapi.json",
]

top_level = {
    "ComponentStatus",
    "ConfigMap",
    "Endpoints",
    "Event",
    "LimitRange",
    "Namespace",
    "Node",
    "PersistentVolumeClaim",
    "PersistentVolume",
    "Pod",
    "PodTemplate",
    "ReplicationController",
    "ResourceQuota",
    "Secret",
    "ServiceAccount",
    "Service",
    "APIService",
    "ControllerRevision",
    "DaemonSet",
    "Deployment",
    "ReplicaSet",
    "StatefulSet",
    "Event",
    "HorizontalPodAutoscaler",
    "CronJob",
    "Job",
    "CertificateSigningRequest",
    "IngressClass",
    "Ingress",
    "NetworkPolicy",
    "Ingress",
    "PodDisruptionBudget",
    "ClusterRoleBinding",
    "ClusterRole",
    "RoleBinding",
    "Role",
    "CSIDriver",
    "CSINode",
    "StorageClass",
    "VolumeAttachment",
    "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
    "CustomResourceDefinition",
    "PriorityClass",
    "Lease",
    "RuntimeClass",
    "EndpointSlice",
    "FlowSchema",
    "PriorityLevelConfiguration",
    "Order",
    "Challenge",
    "ArangoBackup",
    "ArangoBackupPolicy",
    "ClusterIssuer",
    "Issuer",
    "Certificate",
    "CertificateRequest",
    "ArangoMember",
    "ArangoDeployment",
    "Probe",
    "Prometheus",
    "ServiceMonitor",
    "Alertmanager",
    "PodMonitor",
    "PrometheusRule",
    "ThanosRuler",
    "ArangoDeploymentReplication",
    "VolumeSnapshot",
    "VolumeSnapshotContent",
    "VolumeSnapshotClass",
    "CiliumExternalWorkload",
    "CiliumLocalRedirectPolicy",
    "CiliumNetworkPolicy",
    "CiliumEndpoint",
    "CiliumNode",
    "CiliumIdentity",
    "CiliumClusterwideNetworkPolicy",
}

allowed_top_level_props = {"status"}
type_map = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
}


def to_snake(name: str):
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


def to_camel(name: str) -> str:
    return "".join(word.title() for word in name.split("_"))


class ModelCreator:
    def __init__(self, specs: List[str]):
        self.classes: Dict[str, str] = {}
        self.specs = specs

    def property(self, kind_name: str, name: str, prop_spec: dict, prefix: Optional[str] = None) -> Tuple[str, str]:
        k8s = "" if kind_name.startswith("Kubernetes") else "Kubernetes"
        complex_kind = f"{k8s}{kind_name}{to_camel(name)}"

        def kind_name(spec: dict) -> Tuple[str, bool]:
            # complex inner kind?
            if "allOf" in spec:
                inner = spec["allOf"][0]
                if inner.get("format") == "date-time":
                    return "datetime", False
                else:
                    self.create_inner_class(complex_kind, inner)
                    return complex_kind, True
            else:
                return complex_kind, False

        snake_name = to_snake((prefix or "") + name)
        tpe = prop_spec.get("type")
        prop = ""
        mapping = ""
        if tpe == "array":
            kind, is_complex = kind_name(prop_spec["items"])
            prop = f"{snake_name}: List[{kind}] = field(default_factory=list)"
            mapping = f'"{snake_name}": OptionalS("{name}", default=[])"'
            if is_complex:
                mapping += f'" >> ForallBend({kind}.mapping)'
        elif tpe == "object" or tpe is None:
            kind, is_complex = kind_name(prop_spec)
            prop = f"{snake_name}: Optional[{kind}] = field(default=None)"
            if is_complex:
                mapping = f'"{snake_name}": OptionalS("{name}", default={{}}) >> Bend({kind}.mapping)'
            else:
                mapping = f'"{snake_name}": OptionalS("{name}")'

        elif tpe in type_map:
            prop = f"{snake_name}: Optional[{type_map[prop_spec['type']]}] = field(default=None)"
            mapping = f'"{snake_name}": OptionalS("{name}")'
        else:
            raise Exception(f"Unknown property type: {prop_spec}")
        return prop, mapping

    def props(
        self,
        kind_name: str,
        schema: dict,
        allowed: Optional[Set[str]] = None,
        prefix: Optional[str] = None,
        add_mapping: Optional[str] = None,
    ) -> str:
        props = ""
        mapping = f"  mapping: ClassVar[Dict[str, Bender]] = {add_mapping or ''} {{\n"
        for prop, prop_spec in schema.get("properties", {}).items():
            if allowed is None or prop in allowed:
                p, m = self.property(kind_name, prop, prop_spec, prefix)
                props += "  " + p + "\n"
                mapping += "    " + m + ",\n"
        return mapping + "  }\n" + props + "\n"

    def create_inner_class(self, name: str, schema: dict) -> None:
        if name in self.classes or not schema.get("properties", {}):
            return
        result = "@dataclass\n"
        result += f"class {name}:\n"
        result += f'  kind: ClassVar[str] = "{to_snake(name)}"\n'
        result += self.props(name, schema)
        self.classes[name] = result

    def create_resource_class(self, name: str, schema: dict) -> None:
        result = "@dataclass\n"
        result += f"class Kubernetes{name}(KubernetesResource):\n"
        result += f'  kind: ClassVar[str] = "{to_snake("kubernetes_"+name)}"\n'
        result += self.props(
            name,
            schema,
            allowed=allowed_top_level_props,
            prefix=name + "_",
            add_mapping=" KubernetesResource.mapping |",
        )
        self.classes[name] = result

    def parse(self) -> None:
        for spec in self.specs:
            print(f"Parsing {spec}")
            parser = ResolvingParser(spec)
            schemas = parser.specification["components"]["schemas"]
            for fqn, schema in schemas.items():
                name = fqn.rsplit(".", maxsplit=1)[-1]
                if name in top_level:
                    self.create_resource_class(name, schema)


if __name__ == "__main__":
    mc = ModelCreator([f"{base}/{a}" for a in api_specs_to_parse])
    mc.parse()
    for name, content in mc.classes.items():
        print(content)
