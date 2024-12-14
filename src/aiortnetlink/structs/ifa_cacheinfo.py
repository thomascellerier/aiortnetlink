import struct
from typing import NamedTuple

__all__ = ["IFACacheInfo"]


_UINT32_MAX = (2**32) - 1


_IFACacheInfoStruct = struct.Struct(
    b"I"  # Preferred
    b"I"  # Valid
    b"I"  # cstamp
    b"I"  # tstamp
)


class IFACacheInfo(NamedTuple):
    ifa_preferred: int
    ifa_valid: int
    cstamp: int
    tstamp: int

    @staticmethod
    def decode(data: memoryview) -> "IFACacheInfo":
        return IFACacheInfo(*_IFACacheInfoStruct.unpack_from(data))

    def friendly_str(self) -> str:
        parts = [
            "valid_lft",
            "forever" if self.ifa_valid == _UINT32_MAX else str(self.ifa_valid),
            "preferred_lft",
            "forever" if self.ifa_preferred == _UINT32_MAX else str(self.ifa_preferred),
        ]
        return " " * 8 + " ".join(parts)
