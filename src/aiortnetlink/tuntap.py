"""
See https://www.kernel.org/doc/Documentation/networking/tuntap.txt
"""

import fcntl
import os
import struct
import typing
from typing import Final, Literal

__all__ = ["create_tuntap", "delete_tuntap"]


# See <linux/uapi/asm-generic/ioctl.h>
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


# See <linux/uapi/linux/if_tun.h>
TUNSETIFF: Final = _iow(ord("T"), 202, struct.calcsize("i"))
TUNSETPERSIST: Final = _iow(ord("T"), 203, struct.calcsize("i"))
TUNSETOWNER: Final = _iow(ord("T"), 204, struct.calcsize("i"))
TUNSETGROUP: Final = _iow(ord("T"), 206, struct.calcsize("i"))
TUNGETIFF: Final = _ior(ord("T"), 210, struct.calcsize("I"))

IFF_TUN: Final = 0x0001
IFF_TAP: Final = 0x0002


# See <linux/uapi/linux/if.h>
IFNAMSIZ: Final = 16

_IFREQFMT: Final = f"{IFNAMSIZ}shxx"


def _ifreq_setiff(name: str, mode: Literal["tun", "tap"]) -> bytes:
    """
    struct ifreq {
        char ifr_name[IFNAMSIZ]; /* Interface name */
        union {
            [...]
            short           ifr_flags;
            [...]
        };
    };
    """
    flags = 0
    match mode:
        case "tun":
            flags |= IFF_TUN
        case "tap":
            flags |= IFF_TAP
        case unreachable:
            typing.assert_never(unreachable)
    return struct.pack(_IFREQFMT, name.encode("ascii"), flags)


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


if __name__ == "__main__":
    import argparse

    tuntap_parser = argparse.ArgumentParser()
    subparsers = tuntap_parser.add_subparsers(dest="command")

    tuntap_add_parser = subparsers.add_parser("add")
    tuntap_add_parser.add_argument("NAME")
    tuntap_add_parser.add_argument("MODE", choices=("tun", "tap"))
    tuntap_add_parser.add_argument("--user")
    tuntap_add_parser.add_argument("--group")

    tuntap_del_parser = subparsers.add_parser("del")
    tuntap_del_parser.add_argument("NAME")
    tuntap_del_parser.add_argument("MODE", choices=("tun", "tap"))

    args = tuntap_parser.parse_args()

    match args:
        case argparse.Namespace(command="del"):
            delete_tuntap(args.NAME, args.MODE)

        case argparse.Namespace(command="add", user=user, group=group):
            uid: int | None
            match user:
                case str():
                    try:
                        uid = int(user)
                    except ValueError:
                        import pwd

                        uid = pwd.getpwnam(user).pw_uid
                case _:
                    uid = None

            gid: int | None
            match group:
                case str():
                    try:
                        gid = int(group)
                    except ValueError:
                        import grp

                        gid = grp.getgrnam(group).gr_gid
                case _:
                    gid = None

            create_tuntap(args.NAME, args.MODE, uid=uid, gid=gid)

        case _:
            assert False, "unreachable"
