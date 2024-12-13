# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["TunIffFlag"]


class TunIffFlag(IntEnum):
    TUN: Final = 1 << 0
    TAP: Final = 1 << 1
    NO_PI: Final = 1 << 12
    ONE_QUEUE: Final = 1 << 13
    VNET_HDR: Final = 1 << 14
    TUN_EXCL: Final = 1 << 15

    @property
    def constant_name(self) -> str:
        return f"IFF_{self.name}"
