"""
Generic netlink
"""

import struct
from typing import Final, Literal

from aiortnetlink.constants.ctrlattr import CtrlAttr
from aiortnetlink.constants.ctrlcmd import CtrlCmd
from aiortnetlink.constants.nlflag import NLFlag
from aiortnetlink.constants.nlmsgtype import NLMsgType
from aiortnetlink.netlink import (
    NetlinkRequest,
    NLAttr,
)

__all__ = ["get_family_request"]


GENL_ID_CTRL: Final = NLMsgType.MIN_TYPE


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
    flags = NLFlag.REQUEST | NLFlag.ACK
    parts = [
        _genmsghdr(CtrlCmd.GETFAMILY, 1),
        NLAttr.from_string(CtrlAttr.FAMILY_NAME, family),
    ]
    data = b"".join(parts)
    return NetlinkRequest(GENL_ID_CTRL, flags, data, GENL_ID_CTRL)
