import fcntl
import os
import struct
import typing
from typing import Literal

__all__ = ["create_tuntap", "delete_tuntap"]

from aiortnetlink.constants.miscconstants import MiscConstants
from aiortnetlink.constants.tuniffflag import TunIffFlag
from aiortnetlink.constants.tunioctl import TunIoctl

_IFReq = struct.Struct(
    f"{MiscConstants.IFNAMSIZ}s"  # Interface name
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
