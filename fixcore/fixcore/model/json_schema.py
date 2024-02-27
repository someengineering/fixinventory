import re
from typing import Optional

from fixcore import version
from fixcore.model.model import (
    Kind,
    StringKind,
    BooleanKind,
    NumberKind,
    DateKind,
    DateTimeKind,
    DurationKind,
    TransformKind,
    DictionaryKind,
    AnyKind,
    ComplexKind,
    ArrayKind,
    Model,
    Property,
    any_kind,
)
from fixcore.types import Json
from fixlib.durations import DurationRe


def safe_name(kind: Kind) -> str:
    return re.sub("[^A-Za-z0-9]", "_", kind.fqn)


def simple_type(model: Model, kind: Kind) -> Optional[str]:
    if isinstance(kind, StringKind) and kind.fqn == "string":
        return "string"
    elif isinstance(kind, BooleanKind):
        return "boolean"
    elif isinstance(kind, NumberKind) and kind.fqn in ("int32", "int64"):
        return "integer"
    elif isinstance(kind, NumberKind) and kind.fqn in ("float", "double"):
        return "number"
    elif isinstance(kind, AnyKind):
        return "object"
    elif isinstance(kind, TransformKind):
        return simple_type(model, kind.source_kind or any_kind)
    else:
        return None


def ref_type(model: Model, kind: Kind) -> Json:
    if simple := simple_type(model, kind):
        return {"type": simple}
    elif isinstance(kind, ArrayKind):
        return {
            "type": "array",
            "items": ref_type(model, kind.inner),
        }
    elif isinstance(kind, DictionaryKind):
        return {
            "type": "object",
            "additionalProperties": ref_type(model, kind.value_kind),
        }
    else:
        return {"$ref": f"#/$defs/{safe_name(kind)}"}


def export_kind(model: Model, kind: Kind, is_base: bool) -> Optional[Json]:
    if isinstance(kind, (AnyKind, ArrayKind, DictionaryKind)):
        # no additional type information can be defined here
        return None
    elif isinstance(kind, StringKind):
        if kind.fqn != "string":
            result = {"type": "string", "additionalProperties": False}
            if kind.min_length:
                result["minLength"] = kind.min_length
            if kind.max_length:
                result["maxLength"] = kind.max_length
            if kind.pattern:
                result["pattern"] = kind.pattern
            if kind.enum:
                result["enum"] = kind.enum
            return result
        else:
            # build in type string does not need any additional information
            return None
    elif isinstance(kind, BooleanKind):
        if kind.fqn != "boolean":
            return {"type": "boolean", "additionalProperties": False}
        else:
            # build in type boolean does not need any additional information
            return None
    elif isinstance(kind, NumberKind):
        if kind.fqn not in ("int32", "int64", "float", "double"):
            result = {"additionalProperties": False}
            if kind.runtime_kind in ("int32", "int64"):
                result["type"] = "integer"
            elif kind.runtime_kind in ("float", "double"):
                result["type"] = "number"
            if kind.minimum:
                result["minimum"] = kind.minimum
            if kind.maximum:
                result["maximum"] = kind.maximum
            if kind.enum:
                result["enum"] = kind.enum
            return result
        else:
            # build in type number does not need any additional information
            return None
    elif isinstance(kind, DateKind):
        return {"type": "string", "format": "date"}
    elif isinstance(kind, DateTimeKind):
        return {"type": "string", "format": "date-time"}
    elif isinstance(kind, DurationKind):
        return {"type": "string", "pattern": DurationRe.pattern}
    elif isinstance(kind, TransformKind):
        assert kind.source_kind
        return export_kind(model, kind.source_kind, is_base)
    elif isinstance(kind, ComplexKind):
        ck: ComplexKind = kind

        def prop_model(p: Property) -> Json:
            pr = ref_type(model, ck.property_kind_of(p.name, any_kind))
            if desc := p.description:
                pr["description"] = desc
            return pr

        # we always need to define all properties.
        # Otherwise, it is not allowed to forbid additional properties
        all_props = {rp.name: prop_model(rp) for rp in ck.all_props()}
        # If this is a final kind, we expect a kind property with the name of the kind (constant)
        kind_prop = {} if is_base else {"kind": {"const": safe_name(ck)}}
        result = {
            "type": "object",
            "properties": all_props | kind_prop,
            "required": [prop.name for prop in kind.properties if prop.required],
            "additionalProperties": is_base | kind.allow_unknown_props,
        }
        if kind.bases:
            result["allOf"] = [ref_type(model, model[base]) for base in kind.bases]
        return result
    else:
        raise ValueError(f"Unknown kind: {kind}")


def json_schema(model: Model) -> Json:
    # filter out the predefined properties holder
    kinds = [k for k in model.kinds.values() if k.fqn != "predefined_properties"]
    all_bases = {b for k in kinds if isinstance(k, ComplexKind) for b in k.bases}
    return {
        "$id": f"https://inventory.fix.security/schemas/{version()}/resources.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",  # latest draft
        "title": "Fix Inventory Resource Model Schema",
        "oneOf": [
            ref_type(model, k)
            for k in kinds
            if isinstance(k, ComplexKind) and k.aggregate_root and k.fqn not in all_bases
        ],
        "$defs": {
            n: v
            for n, v in {safe_name(k): export_kind(model, k, k.fqn in all_bases) for k in kinds}.items()
            if v is not None
        },
    }
