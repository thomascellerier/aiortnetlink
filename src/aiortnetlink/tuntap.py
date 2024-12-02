import fcntl
import os
import struct
import typing
from typing import Final, Literal

__all__ = ["create_tuntap", "delete_tuntap"]


_IOC_NRBITS: Final = 8
_IOC_TYPEBITS: Final = 8
_IOC_SIZEBITS: Final = 14
_IOC_DIRBITS: Final = 2

_IOC_NRSHIFT: Final = 0
_IOC_TYPESHIFT: Final = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT: Final = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT: Final = _IOC_SIZESHIFT + _IOC_SIZEBITS

IOC_WRITE: Final = 1
IOC_READ: Final = 2


def _ioc(dir_: int, type_: int, nr: int, size: int) -> int:
    return (
        (dir_ << _IOC_DIRSHIFT)
        | (type_ << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _iow(type_: int, nr: int, size: int) -> int:
    return _ioc(IOC_WRITE, type_, nr, size)


def _ior(type_: int, nr: int, size: int) -> int:
    return _ioc(IOC_READ, type_, nr, size)


TUNSETIFF: Final = _iow(ord("T"), 202, struct.calcsize("i"))
TUNSETPERSIST: Final = _iow(ord("T"), 203, struct.calcsize("i"))
TUNSETOWNER: Final = _iow(ord("T"), 204, struct.calcsize("i"))
TUNSETGROUP: Final = _iow(ord("T"), 206, struct.calcsize("i"))
TUNGETIFF: Final = _ior(ord("T"), 210, struct.calcsize("I"))

IFF_TUN: Final = 0x0001
IFF_TAP: Final = 0x0002

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
            flags |= IFF_TUN
        case "tap":
            flags |= IFF_TAP
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
        fcntl.ioctl(fd, TUNSETIFF, _ifreq_setiff(name, mode))
        if uid is not None:
            fcntl.ioctl(fd, TUNSETOWNER, uid)
        if gid is not None:
            fcntl.ioctl(fd, TUNSETGROUP, gid)
        fcntl.ioctl(fd, TUNSETPERSIST, 1)


def delete_tuntap(
    name: str,
    mode: Literal["tun", "tap"],
    *,
    dev_tun_path: str | os.PathLike[str] = "/dev/net/tun",
) -> None:
    with open(dev_tun_path, "rb") as f:
        fd = f.fileno()
        fcntl.ioctl(fd, TUNSETIFF, _ifreq_setiff(name, mode))
        fcntl.ioctl(fd, TUNSETPERSIST, 0)
