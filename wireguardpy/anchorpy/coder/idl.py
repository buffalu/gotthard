from typing import List, Dict

import inflection

from shitty_borsh.borsh import Layout, Struct, RustEnum, Vector, Array
from anchorpy.idl import IdlField, IdlTypeDef

from shitty_borsh.borsh import Bool, U8, I8, U16, I16, U32, I32, U64, I64, U128, I128, Bytes, String, \
    PublicKey, Layout

FIELD_TYPE_MAP: Dict[str, Layout] = {
    "bool": Bool,
    "u8": U8,
    "i8": I8,
    "u16": U16,
    "i16": I16,
    "u32": U32,
    "i32": I32,
    "u64": U64,
    "i64": I64,
    "u128": U128,
    "i128": I128,
    "bytes": Bytes,
    "string": String,
    "publicKey": PublicKey,
}


class IdlCoder(object):
    @staticmethod
    def typedef_layout(typedef: IdlTypeDef, types: List[IdlTypeDef], name: str = "") -> Layout:
        if typedef.type_of.kind == "struct":
            field_layouts = [IdlCoder.field_layout(field, types) for field in typedef.type_of.fields]
            return Struct(field_layouts, name)
        elif typedef.type_of.kind == "enum":
            variants = []
            for variant in typedef.type_of.variants:
                name = inflection.camelize(variant.name)
                if not variant.fields:
                    variants.append(Struct([], name))
                else:
                    fields = []
                    for f in variant.fields:
                        if not f.name:
                            raise Exception("Tuple enum variants not yet implemented")
                        fields.append(IdlCoder.field_layout(f, types))
                    variants.append(Struct(fields, name))
            return RustEnum(variants, name)
        else:
            raise Exception(f"Unknown type {typedef.type_of.kind}")

    @staticmethod
    def field_layout(field: IdlField, types: List[IdlTypeDef]) -> Layout:
        # This method might diverge a bit from anchor.ts stuff but the behavior should be the sames
        field_name = inflection.camelize(field.name, False) if field.name else ""
        if not isinstance(field.type_of, dict) and field.type_of in FIELD_TYPE_MAP:
            return FIELD_TYPE_MAP[field.type_of](field_name)
        else:
            type_of = list(field.type_of.keys())[0]
            if type_of == "vec":
                return Vector(IdlCoder.field_layout(IdlField(
                    name="",
                    type_of=field.type_of["vec"]
                ), types), field_name)
            elif type_of == "option":
                raise Exception("TODO: option type")
            elif type_of == "defined":
                if not types:
                    raise Exception("User defined types not provided")
                filtered = list(filter(lambda t: t.name == field.type_of["defined"], types))
                if len(filtered) != 1:
                    raise Exception(f"Type not found {field.type_of['defined']}")
                return IdlCoder.typedef_layout(filtered[0], types, field_name)
            elif type_of == "array":
                array_ty = field.type_of["array"][0]
                array_len = field.type_of["array"][1]
                inner_layout = IdlCoder.field_layout(IdlField(name="", type_of=array_ty), types)
                return Array(inner_layout, array_len, field_name)
            else:
                raise Exception(f"Field {field} not implemented yet")
