import ipaddress
import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Callable, Literal, NamedTuple

from aiortnetlink.constants.icmpv6routerpref import ICMPv6RouterPref
from aiortnetlink.constants.nlflag import NLFlag
from aiortnetlink.constants.rtatype import RTAType
from aiortnetlink.constants.rtmtype import RTMType
from aiortnetlink.constants.rtntype import RTNType
from aiortnetlink.netlink import NetlinkRequest, NLMsg

__all__ = [
    "RTNType",
    "RTMsg",
    "get_route_request",
    "Route",
]


_RTMsgStruct = struct.Struct(
    b"B"  # Family
    b"B"  # Destination length
    b"B"  # Source length
    b"B"  # TOS filter
    b"B"  # Routing table id, attribute takes precedence
    b"B"  # Protocol
    b"B"  # Scope
    b"B"  # Type
    b"I"  # Flags
)


class RTMsg(NamedTuple):
    family: int = 0
    dst_len: int = 0
    src_len: int = 0
    tos: int = 0
    table: int = 0
    protocol: int = 0
    scope: int = 0
    rtm_type: int = 0
    flags: int = 0

    @classmethod
    def decode[BufferT: (bytes, memoryview)](cls, data: BufferT) -> "tuple[RTMsg, int]":
        return RTMsg(*_RTMsgStruct.unpack_from(data)), _RTMsgStruct.size

    def encode(self) -> bytes:
        return _RTMsgStruct.pack(*self)


def get_route_request() -> NetlinkRequest:
    parts = [RTMsg().encode()]
    flags = NLFlag.REQUEST | NLFlag.DUMP
    data = b"".join(parts)
    return NetlinkRequest(RTMType.GETROUTE, flags, data, RTMType.NEWROUTE)


@dataclass(slots=True)
class Route:
    family: int
    dst_len: int
    src_len: int
    tos: int
    table: int
    protocol: int
    scope: int
    rtm_type: int
    flags: int
    priority: int | None = None
    gateway: IPv4Address | IPv6Address | None = None
    dst: IPv4Address | IPv6Address | None = None
    src: IPv4Address | IPv6Address | None = None
    prefsrc: IPv4Address | IPv6Address | None = None
    iif: int | None = None
    oif: int | None = None
    pref: int | None = None
    mark: int | None = None

    @property
    def ip_version(self) -> Literal[4, 6]:
        match self.family:
            case socket.AF_INET:
                return 4
            case socket.AF_INET6:
                return 6
            case _:
                raise ValueError(f"Invalid IP family: {self.family}")

    @classmethod
    def from_nlmsg(cls, msg: NLMsg) -> "Route":
        data = memoryview(msg.data)
        rtm, rtm_size = RTMsg.decode(data)

        # If RTAType.TABLE is set, rtm.table is ignored
        table = rtm.table
        iif: int | None = None
        oif: int | None = None
        dst: IPv4Address | IPv6Address | None = None
        src: IPv4Address | IPv6Address | None = None
        gateway: IPv4Address | IPv6Address | None = None
        prefsrc: IPv4Address | IPv6Address | None = None
        priority: int | None = None
        pref: int | None = None
        mark: int | None = None

        for nlattr in msg.attrs(rtm_size):
            match nlattr.attr_type:
                case RTAType.TABLE:
                    table = nlattr.as_int()
                case RTAType.OIF:
                    oif = nlattr.as_int()
                case RTAType.IIF:
                    iif = nlattr.as_int()
                case RTAType.DST:
                    dst = nlattr.as_ipaddress()
                case RTAType.GATEWAY:
                    gateway = nlattr.as_ipaddress()
                case RTAType.PRIORITY:
                    priority = nlattr.as_int()
                case RTAType.PREF:
                    pref = nlattr.as_int()
                case RTAType.PREFSRC:
                    prefsrc = nlattr.as_ipaddress()
                case RTAType.SRC:
                    src = nlattr.as_ipaddress()
                case RTAType.MARK:
                    mark = nlattr.as_int()
                case _:
                    # TODO: Handle remaining attributes, e.g. RTAType.UNSPEC and RTAType.CACHEINFO
                    pass

        return Route(
            family=rtm.family,
            dst_len=rtm.dst_len,
            src_len=rtm.src_len,
            tos=rtm.tos,
            table=table,
            protocol=rtm.protocol,
            scope=rtm.scope,
            rtm_type=rtm.rtm_type,
            flags=rtm.flags,
            iif=iif,
            oif=oif,
            dst=dst,
            src=src,
            gateway=gateway,
            priority=priority,
            pref=pref,
            prefsrc=prefsrc,
            mark=mark,
        )

    @classmethod
    def rtm_get(cls) -> NetlinkRequest:
        return get_route_request()

    def friendly_str(
        self,
        show_table: bool = True,
        table_id_to_name: Callable[[int], str | None] = lambda _: None,
        proto_id_to_name: Callable[[int], str | None] = lambda _: None,
        scope_id_to_name: Callable[[int], str | None] = lambda _: None,
        link_index_to_name: Callable[[int], str | None] = lambda _: None,
    ) -> str:
        parts: list[str] = []

        if self.rtm_type != RTNType.UNICAST:
            rtm_type = RTNType(self.rtm_type).name.lower()
            parts.append(rtm_type)

        if self.dst:
            if self.dst_len == self.dst.max_prefixlen:
                parts.append(str(self.dst))
            else:
                parts.append(str(ipaddress.ip_interface((self.dst, self.dst_len))))
        else:
            parts.append("default")

        if self.src:
            if self.src_len == self.src.max_prefixlen:
                parts.extend(["from", str(self.src)])
            else:
                parts.extend(
                    ["from", str(ipaddress.ip_interface((self.src, self.src_len)))]
                )
        elif self.src_len > 0:
            parts.extend(["from", f"0/{self.src_len}"])

        if self.gateway:
            parts.extend(["via", str(self.gateway)])

        if self.iif is not None:
            iif = link_index_to_name(self.iif) or str(self.iif)
            parts.extend(["iif", iif])

        if self.oif is not None:
            oif = link_index_to_name(self.oif) or str(self.oif)
            parts.extend(["dev", oif])

        if self.tos:
            parts.extend(["tos", str(self.tos)])

        if self.protocol:
            proto = proto_id_to_name(self.protocol) or str(self.protocol)
            parts.extend(["proto", proto])

        if self.scope:
            scope = scope_id_to_name(self.scope) or str(self.scope)
            parts.extend(["scope", scope])

        if self.prefsrc:
            parts.extend(["src", str(self.prefsrc)])

        if self.priority is not None:
            parts.extend(["metric", str(self.priority)])

        if self.pref is not None:
            parts.extend(
                [
                    "pref",
                    ICMPv6RouterPref(self.pref).name.lower(),
                ]
            )

        if self.mark is not None:
            parts.extend(
                ["mark", hex(self.mark) if self.mark >= 16 else str(self.mark)]
            )

        if show_table:
            table = table_id_to_name(self.table) or str(self.table)
            parts.extend(["table", table])

        return " ".join(parts)
