"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["CtrlAttr"]


class CtrlAttr(IntEnum):
    UNSPEC = 0
    FAMILY_ID = 1
    FAMILY_NAME = 2
    VERSION = 3
    HDRSIZE = 4
    MAXATTR = 5
    OPS = 6
    MCAST_GROUPS = 7

    @property
    def constant_name(self) -> str:
        return f"CTRL_ATTR_{self.name}"
