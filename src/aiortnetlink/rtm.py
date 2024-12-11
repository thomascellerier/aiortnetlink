from enum import IntEnum
from typing import Final

__all__ = [
    "RTMType",
    "RTNLGroup",
]


class RTMType(IntEnum):
    NEWLINK: Final = 16
    DELLINK: Final = 17
    GETLINK: Final = 18

    NEWADDR: Final = 20
    DELADDR: Final = 21
    GETADDR: Final = 22

    NEWROUTE: Final = 24
    DELROUTE: Final = 25
    GETROUTE: Final = 26

    NEWRULE: Final = 32
    DELRULE: Final = 33
    GETRULE: Final = 34


class RTNLGroup(IntEnum):
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

    NOP2: Final = 13
    DECnet_ROUTE: Final = 14
    DECnet_RULE: Final = 15
    NOP4: Final = 16

    IPV6_PREFIX: Final = 17
    IPV6_RULE: Final = 18
