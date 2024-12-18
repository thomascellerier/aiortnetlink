"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["RTAType"]


class RTAType(IntEnum):
    UNSPEC: Final = 0
    DST: Final = 1
    SRC: Final = 2
    IIF: Final = 3
    OIF: Final = 4
    GATEWAY: Final = 5
    PRIORITY: Final = 6
    PREFSRC: Final = 7
    METRICS: Final = 8
    MULTIPATH: Final = 9
    PROTOINFO: Final = 10
    FLOW: Final = 11
    CACHEINFO: Final = 12
    SESSION: Final = 13
    MP_ALGO: Final = 14
    TABLE: Final = 15
    MARK: Final = 16
    MFC_STATS: Final = 17
    VIA: Final = 18
    NEWDST: Final = 19
    PREF: Final = 20
    ENCAP_TYPE: Final = 21
    ENCAP: Final = 22
    EXPIRES: Final = 23
    PAD: Final = 24
    UID: Final = 25
    TTL_PROPAGATE: Final = 26
    IP_PROTO: Final = 27
    SPORT: Final = 28
    DPORT: Final = 29
    NH_ID: Final = 30

    @property
    def constant_name(self) -> str:
        return f"RTA_{self.name}"
