"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["IFOper"]


class IFOper(IntEnum):
    UNKNOWN: Final = 0x0
    NOTPRESENT: Final = 1 << 0
    DOWN: Final = 1 << 1
    LOWERLAYERDOWN: Final = 0x3
    TESTING: Final = 1 << 2
    DORMANT: Final = 0x5
    UP: Final = 0x6

    @property
    def constant_name(self) -> str:
        return f"IF_OPER_{self.name}"
