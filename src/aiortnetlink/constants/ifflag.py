# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["IFFlag"]


class IFFlag(IntEnum):
    UP: Final = 1 << 0
    BROADCAST: Final = 1 << 1
    DEBUG: Final = 1 << 2
    LOOPBACK: Final = 1 << 3
    POINTOPOINT: Final = 1 << 4
    NOTRAILERS: Final = 1 << 5
    RUNNING: Final = 1 << 6
    NOARP: Final = 1 << 7
    PROMISC: Final = 1 << 8
    ALLMULTI: Final = 1 << 9
    MASTER: Final = 1 << 10
    SLAVE: Final = 1 << 11
    MULTICAST: Final = 1 << 12
    PORTSEL: Final = 1 << 13
    AUTOMEDIA: Final = 1 << 14
    DYNAMIC: Final = 1 << 15
    LOWER_UP: Final = 1 << 16
    DORMANT: Final = 1 << 17
    ECHO: Final = 1 << 18

    @property
    def constant_name(self) -> str:
        return f"IFF_{self.name}"
