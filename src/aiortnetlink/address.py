import struct
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    ip_address,
    ip_interface,
)
from typing import Final, Literal

from aiortnetlink.link import IFLA_IFNAME
from aiortnetlink.netlink import (
    NLM_F_DUMP,
    NLM_F_REQUEST,
    NetlinkGetRequest,
    NetlinkValueError,
    NLMsg,
    encode_nlattr_str,
)
from aiortnetlink.rtm import RTM_GETADDR, RTM_NEWADDR

__all__ = ["ifaddrmsg", "get_addr_request", "IFAddr"]

IFA_UNSPEC: Final = 0
IFA_ADDRESS: Final = 1
IFA_LOCAL: Final = 2
IFA_LABEL: Final = 3
IFA_BROADCAST: Final = 4
IFA_ANYCAST: Final = 5
IFA_CACHEINFO: Final = 6
IFA_MULTICAST: Final = 7

_IFADDRMSG_FMT = b"BBBBI"
_IFADDRMSG_SIZE = struct.calcsize(_IFADDRMSG_FMT)


def ifaddrmsg(
    family: int = 0,
    prefixlen: int = 0,
    flags: int = 0,
    scope: int = 0,
    index: int = 0,
) -> bytes:
    """

    struct ifaddrmsg {
        unsigned char ifa_family;    /* Address type */
        unsigned char ifa_prefixlen; /* Prefixlength of address */
        unsigned char ifa_flags;     /* Address flags */
        unsigned char ifa_scope;     /* Address scope */
        unsigned int  ifa_index;     /* Interface index */
    };
    """
    return struct.pack(_IFADDRMSG_FMT, family, prefixlen, flags, scope, index)


def get_addr_request(
    ifi_index: int = 0, ifi_name: str | None = None
) -> NetlinkGetRequest:
    parts = [ifaddrmsg(index=ifi_index)]
    flags = NLM_F_REQUEST
    if ifi_name is not None:
        parts.append(encode_nlattr_str(IFLA_IFNAME, ifi_name))
    elif ifi_index == 0:
        flags |= NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkGetRequest(RTM_GETADDR, flags, data, RTM_NEWADDR)


IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface


@dataclass(slots=True)
class IFAddr:
    family: int
    prefixlen: int
    scope: int
    flags: int
    if_index: int
    address: IPAddress

    @property
    def interface(self) -> IPInterface:
        return ip_interface((self.address, self.prefixlen))

    @property
    def ip_version(self) -> Literal[4, 6]:
        return self.address.version

    @classmethod
    def from_nlmsg(cls, msg: NLMsg) -> "IFAddr":
        data = memoryview(msg.data)
        ifa_family, ifa_prefixlen, ifa_flags, ifa_scope, ifa_index = struct.unpack(
            _IFADDRMSG_FMT, data[:_IFADDRMSG_SIZE]
        )

        address: IPAddress | None = None

        for nlattr in msg.attrs(_IFADDRMSG_SIZE):
            if nlattr.attr_type == IFA_ADDRESS:
                address = ip_address(nlattr.data.tobytes())

        if address is None:
            raise NetlinkValueError(
                f"Invalid netlink address, missing {IFA_ADDRESS=} attribute"
            )

        return IFAddr(
            family=ifa_family,
            prefixlen=ifa_prefixlen,
            scope=ifa_scope,
            flags=ifa_flags,
            if_index=ifa_index,
            address=address,
        )

    @classmethod
    def rtm_get(
        cls, ifi_index: int = 0, ifi_name: str | None = None
    ) -> NetlinkGetRequest:
        return get_addr_request(ifi_index, ifi_name)
