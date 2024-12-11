"""
Generic netlink
"""

import struct
from enum import IntEnum
from typing import Final, Literal

from aiortnetlink.netlink import (
    NLM_F_ACK,
    NLM_F_REQUEST,
    NLMSG_MIN_TYPE,
    NetlinkRequest,
    NLAttr,
)

__all__ = ["get_family_request", "CtrlCmd"]


GENL_ID_CTRL: Final = NLMSG_MIN_TYPE


class CtrlCmd(IntEnum):
    UNSPEC: Final = 0
    NEWFAMILY: Final = 1
    DELFAMILY: Final = 2
    GETFAMILY: Final = 3
    NEWOPS: Final = 4
    DELOPS: Final = 5
    GETOPS: Final = 6
    NEWMCAST_GRP: Final = 7
    DELMCAST_GRP: Final = 8
    GETMCAST_GRP: Final = 9  # unused


class CtrlAttr(IntEnum):
    UNSPEC: Final = 0
    FAMILY_ID: Final = 1
    FAMILY_NAME: Final = 2
    VERSION: Final = 3
    HDRSIZE: Final = 4
    MAXATTR: Final = 5
    OPS: Final = 6
    MCAST_GROUPS: Final = 7


_GENMSGHDR_FMT: Final = (
    b"B"  # Command
    b"B"  # Version
    b"I"  # Reserved
)
_GENMSGHDR_SIZE: Final = struct.calcsize(_GENMSGHDR_FMT)


def _genmsghdr(
    cmd: int,
    version: Literal[1, 2] = 1,
    reserved: int = 0,
) -> bytes:
    return struct.pack(_GENMSGHDR_FMT, cmd, version, reserved)


def get_family_request(family: str) -> NetlinkRequest:
    flags = NLM_F_REQUEST | NLM_F_ACK
    parts = [
        _genmsghdr(CtrlCmd.GETFAMILY, 1),
        NLAttr.from_string(CtrlAttr.FAMILY_NAME, family),
    ]
    data = b"".join(parts)
    return NetlinkRequest(GENL_ID_CTRL, flags, data, GENL_ID_CTRL)
