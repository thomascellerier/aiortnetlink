# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["RTNLFamily"]


class RTNLFamily(IntEnum):
    IPMR: Final = 128
    IP6MR: Final = 129

    @property
    def constant_name(self) -> str:
        return f"RTNL_FAMILY_{self.name}"