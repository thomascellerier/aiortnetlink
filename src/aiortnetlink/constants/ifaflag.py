# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["IFAFlag"]


class IFAFlag(IntEnum):
    SECONDARY: Final = 1 << 0
    NODAD: Final = 1 << 1
    OPTIMISTIC: Final = 1 << 2
    DADFAILED: Final = 1 << 3
    HOMEADDRESS: Final = 1 << 4
    DEPRECATED: Final = 1 << 5
    TENTATIVE: Final = 1 << 6
    PERMANENT: Final = 1 << 7
    MANAGETEMPADDR: Final = 1 << 8
    NOPREFIXROUTE: Final = 1 << 9
    MCAUTOJOIN: Final = 1 << 10
    STABLE_PRIVACY: Final = 1 << 11

    @property
    def constant_name(self) -> str:
        return f"IFA_F_{self.name}"