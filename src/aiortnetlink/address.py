import socket
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

from aiortnetlink.netlink import (
    NLM_F_ACK,
    NLM_F_CREATE,
    NLM_F_DUMP,
    NLM_F_EXCL,
    NLM_F_REQUEST,
    NetlinkRequest,
    NetlinkValueError,
    NLAttr,
    NLMsg,
    encode_nlattr_str,
)
from aiortnetlink.rtm import RTMType

__all__ = ["IFAddr"]


class IFAType(IntEnum):
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
    def constant_name(self) -> str:
        return f"IFA_{self.name}"


class IFAFlags(IntEnum):
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


_IFAddrStruct = struct.Struct(
    b"B"  # Family
    b"B"  # Prefix length of the address
    b"B"  # Flags
    b"B"  # Scope
    b"I"  # Interface index
)


class IFAddrMsg(NamedTuple):
    family: int = 0
    prefixlen: int = 0
    flags: int = 0
    scope: int = 0
    if_index: int = 0

    def pack(self) -> bytes:
        return _IFAddrStruct.pack(*self)

    @staticmethod
    def unpack(data: bytes | memoryview) -> "tuple[IFAddrMsg, int]":
        return IFAddrMsg(*_IFAddrStruct.unpack_from(data)), _IFAddrStruct.size


def get_addr_request(ifi_index: int = 0, ifi_name: str | None = None) -> NetlinkRequest:
    parts = [IFAddrMsg(if_index=ifi_index).pack()]
    flags = NLM_F_REQUEST
    if ifi_name is not None:
        parts.append(encode_nlattr_str(IFAType.LABEL, ifi_name))
    elif ifi_index == 0:
        flags |= NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkRequest(RTMType.GETADDR, flags, data, RTMType.NEWADDR)


IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface


def add_addr_request(address: IPInterface, ifi_index: int) -> NetlinkRequest:
    if ifi_index < 1:
        raise NetlinkValueError(
            f"Interface index must be specified when deleting address {address}"
        )
    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    parts = [
        IFAddrMsg(
            family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
            prefixlen=address.network.prefixlen,
            scope=0,  # global
            if_index=ifi_index,
            flags=IFAFlags.PERMANENT,
        ).pack(),
        NLAttr.from_ipaddress(IFAType.LOCAL, address.ip),
    ]
    data = b"".join(parts)
    return NetlinkRequest(RTMType.NEWADDR, flags, data, RTMType.NEWADDR)


def del_addr_request(address: IPInterface, ifi_index: int) -> NetlinkRequest:
    if ifi_index < 1:
        raise NetlinkValueError(
            f"Interface index must be specified when deleting address {address}"
        )
    flags = NLM_F_REQUEST | NLM_F_ACK
    parts = [
        IFAddrMsg(
            family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
            prefixlen=address.network.prefixlen,
            scope=0,
            if_index=ifi_index,
            flags=0,
        ).pack(),
        NLAttr.from_ipaddress(IFAType.LOCAL, address.ip),
    ]
    data = b"".join(parts)
    return NetlinkRequest(RTMType.DELADDR, flags, data, RTMType.NEWADDR)


_UINT32_MAX = (2**32) - 1


_IFACacheInfoStruct = struct.Struct(
    b"I"  # Preferred
    b"I"  # Valid
    b"I"  # cstamp
    b"I"  # tstamp
)


class IFACacheInfo(NamedTuple):
    ifa_preferred: int
    ifa_valid: int
    cstamp: int
    tstamp: int

    @staticmethod
    def decode(data: memoryview) -> "IFACacheInfo":
        return IFACacheInfo(*_IFACacheInfoStruct.unpack_from(data))

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
        ifaddr, size = IFAddrMsg.unpack(data)

        # If IFA_FLAGS is set, ifa_flags is ignored
        flags = ifaddr.flags
        address: IPAddress | None = None
        broadcast: IPAddress | None = None
        label: str | None = None
        cache_info: IFACacheInfo | None = None

        for nlattr in msg.attrs(size):
            match nlattr.attr_type:
                case IFAType.ADDRESS:
                    address = nlattr.as_ipaddress()
                case IFAType.BROADCAST:
                    broadcast = nlattr.as_ipaddress()
                case IFAType.LABEL:
                    label = nlattr.as_string()
                case IFAType.FLAGS:
                    flags = nlattr.as_int()
                case IFAType.CACHEINFO:
                    cache_info = IFACacheInfo.decode(nlattr.data)
                case _:
                    # TODO: Handle remaining attribute types like IFA_LOCAL, IFA_UNSPEC
                    pass

        if address is None:
            raise NetlinkValueError(
                f"Invalid netlink address, missing {IFAType.ADDRESS.constant_name} attribute"
            )

        return IFAddr(
            family=ifaddr.family,
            prefixlen=ifaddr.prefixlen,
            scope=ifaddr.scope,
            flags=flags,
            if_index=ifaddr.if_index,
            address=address,
            broadcast=broadcast,
            label=label,
            cache_info=cache_info,
        )

    @classmethod
    def rtm_get(cls, ifi_index: int = 0, ifi_name: str | None = None) -> NetlinkRequest:
        return get_addr_request(ifi_index, ifi_name)

    @classmethod
    def rtm_add(cls, address: IPInterface, ifi_index: int) -> NetlinkRequest:
        return add_addr_request(address, ifi_index)

    @classmethod
    def rtm_del(cls, address: IPInterface, ifi_index: int) -> NetlinkRequest:
        return del_addr_request(address, ifi_index)

    def friendly_str(
        self, scope_id_to_name: Callable[[int], str | None] = lambda _: None
    ) -> str:
        parts = ["inet" if self.ip_version == 4 else "inet6", str(self.interface)]

        if self.broadcast:
            parts.extend(["brd", str(self.broadcast)])

        parts.extend(["scope", scope_id_to_name(self.scope) or str(self.scope)])

        flags = []
        if not (self.flags & IFAFlags.PERMANENT):
            flags.append("dynamic")
        for flag in IFAFlags:
            if self.flags & flag:
                flags.append(flag.name.lower())
        parts.extend(flags)

        if self.label:
            parts.append(self.label)

        parts_str = " " * 4 + " ".join(parts)
        if self.cache_info:
            parts_str += "\n" + self.cache_info.friendly_str()
        return parts_str
