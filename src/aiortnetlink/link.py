import struct
from dataclasses import dataclass
from typing import Final

from aiortnetlink.netlink import (
    NLM_F_DUMP,
    NLM_F_REQUEST,
    NetlinkGetRequest,
    NLMsg,
    encode_nlattr_str,
)
from aiortnetlink.rtm import RTM_GETLINK, RTM_NEWLINK

__all__ = ["IFLink", "IFLA_IFNAME", "ifinfomsg"]

# See <linux/if_arp.h>
ARPHRD_LOOPBACK: Final = 772
ARPHRD_ETHER: Final = 1

# See <linux/if_link.h>
IFLA_UNSPEC: Final = 0
IFLA_ADDRESS: Final = 1
IFLA_BROADCAST: Final = 2
IFLA_IFNAME: Final = 3
# TODO: The rest of the values

_IFINFOMSG_FMT: Final = b"BxHiII"
_IFINFOMSG_SIZE: Final = struct.calcsize(_IFINFOMSG_FMT)


def ifinfomsg(
    family: int = 0,
    ifi_type: int = 0,
    index: int = 0,
    flags: int = 0,
    change: int = 0,
) -> bytes:
    """

    struct ifinfomsg {
        unsigned char  ifi_family; /* AF_UNSPEC */
        unsigned char  __ifi_pad;
        unsigned short ifi_type;   /* Device type */
        int            ifi_index;  /* Interface index */
        unsigned int   ifi_flags;  /* Device flags  */
        unsigned int   ifi_change; /* change mask */
    };
    """
    return struct.pack(_IFINFOMSG_FMT, family, ifi_type, index, flags, change)


@dataclass(slots=True)
class IFLink:
    family: int
    if_type: int
    index: int
    flags: int
    change: int
    name: str

    @classmethod
    def from_nlmsg(cls, msg: NLMsg) -> "IFLink":
        data = memoryview(msg.data)
        ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack(
            _IFINFOMSG_FMT, data[:_IFINFOMSG_SIZE]
        )

        name: str | None = None

        for nlattr in msg.attrs(_IFINFOMSG_SIZE):
            if nlattr.attr_type == IFLA_IFNAME:
                name = nlattr.as_string()

        assert name is not None

        return IFLink(
            family=ifi_family,
            index=ifi_index,
            name=name,
            if_type=ifi_type,
            flags=ifi_flags,
            change=ifi_change,
        )

    @classmethod
    def rtm_get(
        cls, ifi_index: int = 0, ifi_name: str | None = None
    ) -> NetlinkGetRequest:
        return get_link_request(ifi_index, ifi_name)


def get_link_request(
    ifi_index: int = 0, ifi_name: str | None = None
) -> NetlinkGetRequest:
    parts = [ifinfomsg(index=ifi_index)]
    flags = NLM_F_REQUEST
    if ifi_name is not None:
        parts.append(encode_nlattr_str(IFLA_IFNAME, ifi_name))
    elif ifi_index == 0:
        flags |= NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkGetRequest(RTM_GETLINK, flags, data, RTM_NEWLINK)
