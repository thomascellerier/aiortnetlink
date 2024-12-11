from enum import IntEnum
from typing import Final

__all__ = [
    "RTMType",
    "RTNLGRP_LINK",
    "RTNLGRP_IPV4_ROUTE",
    "RTNLGRP_IPV4_RULE",
    "RTNLGRP_IPV4_IFADDR",
    "RTNLGRP_IPV6_ROUTE",
    "RTNLGRP_IPV6_RULE",
    "RTNLGRP_IPV6_IFADDR",
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


RTNLGRP_LINK: Final = 1
RTNLGRP_NOTIFY: Final = 2
RTNLGRP_NEIGH: Final = 3
RTNLGRP_TC: Final = 4

RTNLGRP_IPV4_IFADDR: Final = 5
RTNLGRP_IPV4_MROUTE: Final = 6
RTNLGRP_IPV4_ROUTE: Final = 7
RTNLGRP_IPV4_RULE: Final = 8

RTNLGRP_IPV6_IFADDR: Final = 9
RTNLGRP_IPV6_MROUTE: Final = 10
RTNLGRP_IPV6_ROUTE: Final = 11
RTNLGRP_IPV6_IFINFO: Final = 12

RTNLGRP_NOP2: Final = 13
RTNLGRP_DECnet_ROUTE: Final = 14
RTNLGRP_DECnet_RULE: Final = 15
RTNLGRP_NOP4: Final = 16

RTNLGRP_IPV6_PREFIX: Final = 17
RTNLGRP_IPV6_RULE: Final = 18
