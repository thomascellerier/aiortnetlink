"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["RTNLGroup"]


class RTNLGroup(IntEnum):
    NONE: Final = 0
    LINK: Final = 1
    NOTIFY: Final = 2
    NEIGH: Final = 3
    TC: Final = 4
    IPV4_IFADDR: Final = 5
    IPV4_MROUTE: Final = 6
    IPV4_ROUTE: Final = 7
    IPV4_RULE: Final = 8
    IPV6_IFADDR: Final = 9
    IPV6_MROUTE: Final = 10
    IPV6_ROUTE: Final = 11
    IPV6_IFINFO: Final = 12
    DECnet_IFADDR: Final = 13
    NOP2: Final = 14
    DECnet_ROUTE: Final = 15
    DECnet_RULE: Final = 16
    NOP4: Final = 17
    IPV6_PREFIX: Final = 18
    IPV6_RULE: Final = 19
    ND_USEROPT: Final = 20
    PHONET_IFADDR: Final = 21
    PHONET_ROUTE: Final = 22

    @property
    def constant_name(self) -> str:
        return f"RTNLGRP_{self.name}"
