"""
Generic netlink
"""

import struct
from typing import Final, Literal

from aiortnetlink.netlink import (
    NLM_F_ACK,
    NLM_F_REQUEST,
    NLMSG_MIN_TYPE,
    NetlinkRequest,
    NLAttr,
)

__all__ = ["get_family_request"]


GENL_ID_CTRL: Final = NLMSG_MIN_TYPE

CTRL_CMD_UNSPEC: Final = 0
CTRL_CMD_NEWFAMILY: Final = 1
CTRL_CMD_DELFAMILY: Final = 2
CTRL_CMD_GETFAMILY: Final = 3
CTRL_CMD_NEWOPS: Final = 4
CTRL_CMD_DELOPS: Final = 5
CTRL_CMD_GETOPS: Final = 6
CTRL_CMD_NEWMCAST_GRP: Final = 7
CTRL_CMD_DELMCAST_GRP: Final = 8
CTRL_CMD_GETMCAST_GRP: Final = 9  # unused

CTRL_ATTR_UNSPEC: Final = 0
CTRL_ATTR_FAMILY_ID: Final = 1
CTRL_ATTR_FAMILY_NAME: Final = 2
CTRL_ATTR_VERSION: Final = 3
CTRL_ATTR_HDRSIZE: Final = 4
CTRL_ATTR_MAXATTR: Final = 5
CTRL_ATTR_OPS: Final = 6
CTRL_ATTR_MCAST_GROUPS: Final = 7


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
        _genmsghdr(CTRL_CMD_GETFAMILY, 1),
        NLAttr.from_string(CTRL_ATTR_FAMILY_NAME, family),
    ]
    data = b"".join(parts)
    return NetlinkRequest(GENL_ID_CTRL, flags, data, GENL_ID_CTRL)
