# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["ARPHRDType"]


class ARPHRDType(IntEnum):
    ETHER: Final = 1
    NONE: Final = 65534
    LOOPBACK: Final = 772

    @property
    def constant_name(self) -> str:
        return f"ARPHRD_{self.name}"

