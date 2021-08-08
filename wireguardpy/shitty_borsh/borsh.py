import struct
import traceback
from abc import ABC, abstractmethod
from types import SimpleNamespace
from typing import List, Any, Tuple

import solana.publickey


class Layout(ABC):
    def __init__(self, field_name: str):
        self.field_name = field_name

    def __repr__(self):
        return f"{self.__class__.__name__}<{self.field_name}>"

    @abstractmethod
    def encode(self, data: Any) -> bytes:
        ...

    @abstractmethod
    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        """
        Modifies b in place
        """
        ...


class BorshSimpleType(Layout, ABC):
    def __init__(self, field_name: str, fmt: str):
        super().__init__(field_name)
        self.fmt = fmt

    def encode(self, data: Any) -> bytes:
        return struct.pack(self.fmt, data)

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        try:
            s_size = struct.calcsize(self.fmt)
            ret = struct.unpack(self.fmt, b[:s_size])[0]
            bytes_left = b[s_size:]
            return bytes_left, ret
        except struct.error:
            raise Exception(f"Error unpacking {self.fmt=}, {b=}")


class Bool(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<?")


class U8(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<B")


class I8(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<b")


class U16(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<H")


class I16(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<h")


class U32(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<I")


class I32(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<i")


class U64(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<Q")


class I64(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<q")


class U128(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<QQ")

    def encode(self, data: Any) -> bytes:
        return struct.pack(self.fmt, (data >> 64) & 0xFFFFFFFFFFFFFFFF, data & 0xFFFFFFFFFFFFFFFF)

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        val1, val2 = struct.unpack(self.fmt, b[:16])
        b = b[16:]
        return b, (val1 << 64) | val2


class I128(BorshSimpleType):
    def __init__(self, field_name: str):
        super().__init__(field_name, "<QQ")

    def encode(self, data: Any) -> bytes:
        raise Exception("I128 not supported yet")
        return struct.pack(self.fmt, (data >> 64) & 0xFFFFFFFFFFFFFFFF, data & 0xFFFFFFFFFFFFFFFF)

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        raise Exception("I128 not supported yet")
        # val1, val2 = struct.unpack(self.fmt, b[128:])
        # # TODO find sign and flip if needed
        # ret = (val1 << 64) | val2
        # return ret


class Bytes(Layout):
    def encode(self, data: bytes) -> bytes:
        return struct.pack("<I", len(data)) + data

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        bytes_len = struct.unpack("<I", b[:4])[0]
        ret = b[4:4 + bytes_len]
        b = b[4 + bytes_len:]
        return b, ret


class String(Bytes):
    def encode(self, data: str) -> bytes:
        return super().encode(data.encode())

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        bytes_left, ret = super().decode(b)
        return bytes_left, ret.decode("utf-8")


class PublicKey(Layout):
    def encode(self, data: str) -> bytes:
        return bytes(data)[:32]

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        ret = b[:32]
        b = b[32:]
        return b, solana.publickey.PublicKey(ret)


class Vector(Layout):
    def __init__(self, layout: Layout, name: str = ""):
        super().__init__(name)
        self.layout = layout

    def encode(self, data: Any) -> bytes:
        vec_len_byte = struct.pack("<I", len(data))
        b = bytes()
        for d in data:
            b += self.layout.encode(d)
        return vec_len_byte + b

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        vec = list()
        vec_len = struct.unpack("<I", b[:4])[0]
        bytes_left = b[4:]
        for idx in range(vec_len):
            bytes_left, decoded = self.layout.decode(bytes_left)
            vec.append(decoded)
        return bytes_left, vec


class Array(Layout):
    def __init__(self, layout: Layout, length: int, name: str = ""):
        super().__init__(name)
        self.layout = layout
        self.length = length

    def __repr__(self):
        return f"Array<layout={self.layout}, length={self.length}, name={self.field_name}>"

    def encode(self, data: List[Any]) -> bytes:
        if len(data) != self.length:
            raise Exception(f"Array {self.field_name} expected length {self.length}, got {len(data)}")
        b = bytes()
        for d in data:
            b += self.layout.encode(d)
        return b

    def decode(self, b: bytes) -> Tuple[bytes, List[Any]]:
        decoded = list()
        bytes_left = b
        for i in range(self.length):
            bytes_left, d = self.layout.decode(bytes_left)
            decoded.append(d)
        return bytes_left, decoded


class Struct(Layout):
    def __init__(self, field_layouts: List[Layout], name: str = ""):
        super().__init__(name)
        self.field_layouts = field_layouts

    def __repr__(self):
        return f"Struct<name={self.field_name}, field_layouts={self.field_layouts}>"

    def encode(self, data: Any) -> bytes:
        if len(data) != len(self.field_layouts):
            raise Exception(f"{len(data)} != {len(self.field_layouts)}")
        b = bytes()
        for layout in self.field_layouts:
            encoded = layout.encode(data[layout.field_name])
            b += encoded
        return b

    def decode(self, b: bytes) -> Tuple[bytes, Any]:
        ret = SimpleNamespace()
        bytes_left = b
        for layout in self.field_layouts:
            # decode modifies b in place so the offsets are computed automatically for the next layout
            try:
                # print(f"decoding: {layout.field_name}, {layout.__class__.__name__}bytes={bytes_left}", flush=True)
                bytes_left, decoded = layout.decode(bytes_left)
                setattr(ret, layout.field_name, decoded)
            except:
                print(traceback.format_exc(), flush=True)
                raise
        return bytes_left, ret


class RustEnum(Layout):
    def __init__(self, variants: List[Struct], name: str = ""):
        super().__init__(name)
        self.variants = variants

    def encode(self, data: Any) -> bytes:
        raise Exception(f"Implement type RustEnum")

    def decode(self, b: bytes) -> Any:
        raise Exception(f"Implement type RustEnum")


def main():
    TEST_CASES = [
        (Bool, True),
        (Bool, False),
        (U8, 10),

        (I8, -126),
        (U16, 0xDEAD),
        (I16, 0xEAD),
        (U32, 0xDEADBEEF),
        (I32, 0xEADBEEF),
        (U64, 0xDEADBEEFDEADBEEF),
        (I64, 0xEADBEEFDEADBEEF),
        (U128, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        # (I128, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        # (I128, -1),
        (Bytes, b"testing 1234"),
        (String, "testing 1234"),
    ]

    for datatype, input_val in TEST_CASES:
        t = datatype("foo")
        # print(f"Datatype={datatype}, input={input_val}")

        encoded = t.encode(input_val)
        _, decoded = t.decode(encoded)
        assert input_val == decoded

    s = Struct([U128("u128_1"), String("string_field"), U128("u128")], "struct_name")
    _, ret = s.decode(s.encode({"string_field": "abc", "u128": 123456, "u128_1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}))
    assert ret.string_field == "abc"
    assert ret.u128 == 123456
    assert ret.u128_1 == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    v = Vector(U128("foo"), "vector")
    encoded = v.encode([1, 2, 3, 4])
    print(encoded)
    print(len(encoded))
    bytes_left, decoded = v.decode(v.encode([1, 2, 3, 4]))
    assert decoded == [1, 2, 3, 4]

    v2 = Vector(String("s"), "vector")
    bytes_left, decoded = v2.decode(v2.encode(["a", "b", "c", "d", "e"]))
    print(decoded)

    a = Array(String(""), 5, "some_arr")
    bytes_left, decoded = a.decode(a.encode(["a", "b", "c", "d", "e", "f"]))
    print(decoded)


if __name__ == '__main__':
    main()
