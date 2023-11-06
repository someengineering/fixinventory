from typing import List

from resotocore.model.model import (
    Model,
    ComplexKind,
    predefined_kinds_by_name,
    Kind,
    SimpleKind,
    ArrayKind,
    DictionaryKind,
    TransformKind,
    Property,
)
from resotocore.types import Json, JsonElement


def json_export_simple_schema(model: Model) -> List[Json]:
    def export_simple(kind: SimpleKind) -> Json:
        result = kind.as_json()
        result["type"] = "simple"
        return result

    def export_property(prop: Property, kind: Kind) -> Json:
        def prop_kind(kd: Kind) -> JsonElement:
            if isinstance(kd, TransformKind):
                assert kd.source_kind is not None, "Source of TransformKind is None!"
                return prop_kind(kd.source_kind)
            elif isinstance(kd, ArrayKind):
                return dict(type="array", items=prop_kind(kd.inner))
            elif isinstance(kd, DictionaryKind):
                return dict(type="dictionary", key=prop_kind(kd.key_kind), value=prop_kind(kd.value_kind))
            elif isinstance(kd, ComplexKind):
                return dict(type="object", fqn=kd.fqn)
            elif isinstance(kd, SimpleKind):
                return dict(type="simple", fqn=kd.fqn)
            else:
                raise ValueError(f"Can not handle kind {kd.fqn}")

        p = dict(
            kind=prop_kind(kind),
            required=prop.required,
            description=prop.description,
            metadata=prop.metadata,
        )
        return p

    def export_complex(kind: ComplexKind) -> Json:
        return dict(
            type="object",
            fqn=kind.fqn,
            bases=kind.bases,
            allow_unknown_props=kind.allow_unknown_props,
            successor_kinds=kind.successor_kinds,
            aggregate_root=kind.aggregate_root,
            metadata=kind.metadata,
            properties={prop.name: export_property(prop, kind) for prop, kind in kind.all_props_with_kind()},
        )

    def export_kind(kind: Kind) -> Json:
        if isinstance(kind, SimpleKind):
            return export_simple(kind)
        elif isinstance(kind, ComplexKind):
            return export_complex(kind)
        elif isinstance(kind, ArrayKind):
            return {"type": "array", "items": export_kind(kind.inner)}
        elif isinstance(kind, DictionaryKind):
            return {"type": "dictionary", "key": export_kind(kind.key_kind), "value": export_kind(kind.value_kind)}
        else:
            raise ValueError(f"Unexpected kind: {kind}")

    # filter out predefined properties
    return [export_kind(k) for k in model.kinds.values() if k.fqn not in predefined_kinds_by_name]
