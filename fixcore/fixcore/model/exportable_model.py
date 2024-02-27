from typing import List

from fixcore.model.model import (
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
from fixcore.types import Json, JsonElement


def json_export_simple_schema(
    model: Model,
    with_properties: bool = True,
    with_relatives: bool = True,
    with_metadata: bool = True,
    aggregate_roots_only: bool = False,
) -> List[Json]:
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
        result = dict(
            type="object",
            fqn=kind.fqn,
            aggregate_root=kind.aggregate_root,
        )
        if with_metadata:
            result["metadata"] = kind.metadata
        if with_properties:
            result["allow_unknown_props"] = kind.allow_unknown_props
            result["properties"] = {prop.name: export_property(prop, kind) for prop, kind in kind.all_props_with_kind()}
        if with_relatives:
            result["bases"] = kind.bases
            result["predecessor_kinds"] = kind.predecessor_kinds()
            result["successor_kinds"] = kind.successor_kinds
        return result

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
