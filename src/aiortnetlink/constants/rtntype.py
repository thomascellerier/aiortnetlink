"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["RTNType"]


class RTNType(IntEnum):
    UNSPEC: Final = 0
    UNICAST: Final = 1
    LOCAL: Final = 2
    BROADCAST: Final = 3
    ANYCAST: Final = 4
    MULTICAST: Final = 5
    BLACKHOLE: Final = 6
    UNREACHABLE: Final = 7
    PROHIBIT: Final = 8
    THROW: Final = 9
    NAT: Final = 10
    XRESOLVE: Final = 11

    @property
    def constant_name(self) -> str:
        return f"RTN_{self.name}"
