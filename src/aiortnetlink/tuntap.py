import fcntl
import os
import struct
import typing
from enum import IntEnum
from typing import Final, Literal

__all__ = ["create_tuntap", "delete_tuntap"]


class TunIoctl(IntEnum):
    SETNOCSUM: Final = 0x400454C8
    SETDEBUG: Final = 0x400454C9
    SETIFF: Final = 0x400454CA
    SETPERSIST: Final = 0x400454CB
    SETOWNER: Final = 0x400454CC
    SETLINK: Final = 0x400454CD
    SETGROUP: Final = 0x400454CE
    GETFEATURES: Final = -0x7FFBAB31
    SETOFFLOAD: Final = 0x400454D0
    SETTXFILTER: Final = 0x400454D1
    GETIFF: Final = -0x7FFBAB2E
    GETSNDBUF: Final = -0x7FFBAB2D
    SETSNDBUF: Final = 0x400454D4
    ATTACHFILTER: Final = 0x401054D5
    DETACHFILTER: Final = 0x401054D6
    GETVNETHDRSZ: Final = -0x7FFBAB29
    SETVNETHDRSZ: Final = 0x400454D8
    SETVNETBE: Final = 0x400454DE
    GETVNETBE: Final = -0x7FFBAB21
    SETSTEERINGEBPF: Final = -0x7FFBAB20
    SETFILTEREBPF: Final = -0x7FFBAB1F
    SETCARRIER: Final = 0x400454E2
    GETDEVNETNS: Final = 0x54E3

    @property
    def constant_name(self) -> str:
        return f"TUN{self.name}"


class TunIffFlag(IntEnum):
    TUN: Final = 1 << 0
    TAP: Final = 1 << 1
    NO_PI: Final = 1 << 12
    ONE_QUEUE: Final = 1 << 13
    VNET_HDR: Final = 1 << 14
    TUN_EXCL: Final = 1 << 15

    @property
    def constant_name(self) -> str:
        return f"IFF_{self.name}"


IFNAMSIZ: Final = 16

_IFReq = struct.Struct(
    f"{IFNAMSIZ}s"  # Interface name
    "h"  # Flags
    "x"  # Padding
    "x"  # Padding
)


def _ifreq_setiff(name: str, mode: Literal["tun", "tap"]) -> bytes:
    flags = 0
    match mode:
        case "tun":
            flags |= TunIffFlag.TUN
        case "tap":
            flags |= TunIffFlag.TAP
        case unreachable:
            typing.assert_never(unreachable)
    return _IFReq.pack(name.encode("ascii"), flags)


def create_tuntap(
    name: str,
    mode: Literal["tun", "tap"],
    uid: int | None = None,
    gid: int | None = None,
    *,
    dev_tun_path: str | os.PathLike[str] = "/dev/net/tun",
) -> None:
    with open(dev_tun_path, "rb") as f:
        fd = f.fileno()
        fcntl.ioctl(fd, TunIoctl.SETIFF, _ifreq_setiff(name, mode))
        if uid is not None:
            fcntl.ioctl(fd, TunIoctl.SETOWNER, uid)
        if gid is not None:
            fcntl.ioctl(fd, TunIoctl.SETGROUP, gid)
        fcntl.ioctl(fd, TunIoctl.SETPERSIST, 1)


def delete_tuntap(
    name: str,
    mode: Literal["tun", "tap"],
    *,
    dev_tun_path: str | os.PathLike[str] = "/dev/net/tun",
) -> None:
    with open(dev_tun_path, "rb") as f:
        fd = f.fileno()
        fcntl.ioctl(fd, TunIoctl.SETIFF, _ifreq_setiff(name, mode))
        fcntl.ioctl(fd, TunIoctl.SETPERSIST, 0)
