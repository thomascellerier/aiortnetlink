"""
See https://docs.kernel.org/networking/netlink_spec/rt_addr.html
"""

import struct
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    ip_interface,
)
from typing import Callable, Final, Literal, NamedTuple

from aiortnetlink.link import IFLAType
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


class IFA_Type(IntEnum):
    UNSPEC: Final = 0
    ADDRESS: Final = 1
    LOCAL: Final = 2
    LABEL: Final = 3
    BROADCAST: Final = 4
    ANYCAST: Final = 5
    CACHEINFO: Final = 6
    MULTICAST: Final = 7
    FLAGS: Final = 8
    RT_PRIORITY: Final = 9
    TARGET_NETNSID: Final = 10
    PROTO: Final = 11

    @property
    def attr_name(self) -> str:
        return f"IFA_{self.name}"


class IFA_Flags(IntEnum):
    SECONDARY: Final = 0x01
    NODAD: Final = 0x02
    OPTIMISTIC: Final = 0x04
    DADFAILED: Final = 0x08
    HOMEADDRESS: Final = 0x10
    DEPRECATED: Final = 0x20
    TENTATIVE: Final = 0x40
    PERMANENT: Final = 0x80
    MANAGETEMPADDR: Final = 0x100
    NOPREFIXROUTE: Final = 0x200
    MCAUTOJOIN: Final = 0x400
    STABLE_PRIVACY: Final = 0x800


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
        parts.append(encode_nlattr_str(IFLAType.IFNAME, ifi_name))
    elif ifi_index == 0:
        flags |= NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkGetRequest(RTM_GETADDR, flags, data, RTM_NEWADDR)


IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface


_UINT32_MAX = (2**32) - 1


class IFACacheInfo(NamedTuple):
    ifa_preferred: int
    ifa_valid: int
    cstamp: int
    tstamp: int

    @staticmethod
    def decode(data: memoryview) -> "IFACacheInfo":
        return IFACacheInfo(*struct.unpack("IIII", data))

    def friendly_str(self) -> str:
        parts = [
            "valid_lft",
            "forever" if self.ifa_valid == _UINT32_MAX else str(self.ifa_valid),
            "preferred_lft",
            "forever" if self.ifa_preferred == _UINT32_MAX else str(self.ifa_preferred),
        ]
        return " " * 8 + " ".join(parts)


@dataclass(slots=True)
class IFAddr:
    family: int
    prefixlen: int
    scope: int
    flags: int
    if_index: int
    address: IPAddress
    broadcast: IPAddress | None = None
    label: str | None = None
    cache_info: IFACacheInfo | None = None

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

        # If IFA_FLAGS is set, ifa_flags is ignored
        flags = ifa_flags
        address: IPAddress | None = None
        broadcast: IPAddress | None = None
        label: str | None = None
        cache_info: IFACacheInfo | None = None

        for nlattr in msg.attrs(_IFADDRMSG_SIZE):
            match nlattr.attr_type:
                case IFA_Type.ADDRESS:
                    address = nlattr.as_ipaddress()
                case IFA_Type.BROADCAST:
                    broadcast = nlattr.as_ipaddress()
                case IFA_Type.LABEL:
                    label = nlattr.as_string()
                case IFA_Type.FLAGS:
                    flags = nlattr.as_int()
                case IFA_Type.CACHEINFO:
                    cache_info = IFACacheInfo.decode(nlattr.data)
                case _:
                    # TODO: Handle remaining attribute types like IFA_LOCAL, IFA_UNSPEC
                    pass

        if address is None:
            raise NetlinkValueError(
                f"Invalid netlink address, missing {IFA_Type.ADDRESS.attr_name} attribute"
            )

        return IFAddr(
            family=ifa_family,
            prefixlen=ifa_prefixlen,
            scope=ifa_scope,
            flags=flags,
            if_index=ifa_index,
            address=address,
            broadcast=broadcast,
            label=label,
            cache_info=cache_info,
        )

    @classmethod
    def rtm_get(
        cls, ifi_index: int = 0, ifi_name: str | None = None
    ) -> NetlinkGetRequest:
        return get_addr_request(ifi_index, ifi_name)

    def friendly_str(
        self, scope_id_to_name: Callable[[int], str | None] = lambda _: None
    ) -> str:
        parts = ["inet" if self.ip_version == 4 else "inet6", str(self.interface)]

        if self.broadcast:
            parts.extend(["brd", str(self.broadcast)])

        parts.extend(["scope", scope_id_to_name(self.scope) or str(self.scope)])

        flags = []
        if not (self.flags & IFA_Flags.PERMANENT):
            flags.append("dynamic")
        for flag in IFA_Flags:
            if self.flags & flag:
                flags.append(flag.name.lower())
        parts.extend(flags)

        if self.label:
            parts.append(self.label)

        parts_str = " ".join(parts)
        if self.cache_info:
            parts_str += "\n" + self.cache_info.friendly_str()
        return parts_str
