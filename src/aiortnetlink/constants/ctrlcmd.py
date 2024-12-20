"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["CtrlCmd"]


class CtrlCmd(IntEnum):
    UNSPEC = 0
    NEWFAMILY = 1
    DELFAMILY = 2
    GETFAMILY = 3
    NEWOPS = 4
    DELOPS = 5
    GETOPS = 6
    NEWMCAST_GRP = 7
    DELMCAST_GRP = 8
    GETMCAST_GRP = 9

    @property
    def constant_name(self) -> str:
        return f"CTRL_CMD_{self.name}"
