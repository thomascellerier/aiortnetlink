"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["TunIffFlag"]


class TunIffFlag(IntEnum):
    TUN = 1 << 0
    TAP = 1 << 1
    NO_PI = 1 << 12
    ONE_QUEUE = 1 << 13
    VNET_HDR = 1 << 14
    TUN_EXCL = 1 << 15

    @property
    def constant_name(self) -> str:
        return f"IFF_{self.name}"
