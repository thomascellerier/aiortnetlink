import ipaddress
import socket
import struct
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Callable, Literal, NamedTuple

from aiortnetlink.constants.icmpv6routerpref import ICMPv6RouterPref
from aiortnetlink.constants.nlflag import NLFlag
from aiortnetlink.constants.rtatype import RTAType
from aiortnetlink.constants.rtcflag import RTCFlag
from aiortnetlink.constants.rtmflag import RTMFlag
from aiortnetlink.constants.rtmtype import RTMType
from aiortnetlink.constants.rtntype import RTNType
from aiortnetlink.constants.rtprot import RTProt
from aiortnetlink.constants.rtscope import RTScope
from aiortnetlink.constants.rttable import RTTable
from aiortnetlink.netlink import NetlinkRequest, NLAttr, NLMsg
from aiortnetlink.structs.ifa_cacheinfo import IFACacheInfo

__all__ = [
    "RTNType",
    "RTMsg",
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


def _build_route(
    dst: IPv4Network | IPv6Network | None = None,
    gateway: IPv4Address | IPv6Address | None = None,
    oif: int | None = None,
    family: int | None = None,
    protocol: RTProt | None = None,
    scope: RTScope | None = None,
    table: int | None = None,
    rtm_type: RTNType | None = None,
) -> "Route":
    if not family:
        if dst:
            family = socket.AF_INET if dst.version == 4 else socket.AF_INET6
        elif gateway:
            family = socket.AF_INET if gateway.version == 4 else socket.AF_INET6
        else:
            family = socket.AF_UNSPEC
    return Route(
        rtm_type=rtm_type if rtm_type is not None else RTNType.UNICAST,
        protocol=protocol if protocol is not None else RTProt.BOOT,
        scope=scope if scope is not None else RTScope.LINK,
        dst=dst.network_address if dst else None,
        dst_len=dst.prefixlen if dst else 0,
        gateway=gateway,
        oif=oif,
        family=family,
        table=table if table is not None else RTTable.MAIN,
    )


@dataclass(slots=True)
class Route:
    family: int = socket.AF_UNSPEC
    dst_len: int = 0
    src_len: int = 0
    tos: int = 0
    table: int = RTTable.UNSPEC
    protocol: int = RTProt.UNSPEC
    scope: int = RTScope.UNIVERSE
    rtm_type: int = RTAType.UNSPEC
    flags: int = 0
    priority: int | None = None
    gateway: IPv4Address | IPv6Address | None = None
    dst: IPv4Address | IPv6Address | None = None
    src: IPv4Address | IPv6Address | None = None
    prefsrc: IPv4Address | IPv6Address | None = None
    iif: int | None = None
    oif: int | None = None
    pref: int | None = None
    mark: int | None = None
    uid: int | None = None
    cache_info: IFACacheInfo | None = None

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
        uid: int | None = None
        cache_info: IFACacheInfo | None = None

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
                case RTAType.UID:
                    uid = nlattr.as_int()
                case RTAType.CACHEINFO:
                    cache_info = IFACacheInfo.decode(nlattr.data)
                case _:
                    # TODO: Handle remaining attributes
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
            uid=uid,
            cache_info=cache_info,
        )

    def to_nlmsg(self) -> bytes:
        if self.table < 256:
            rtm_table = self.table
        else:
            rtm_table = RTTable.UNSPEC

        parts = [
            RTMsg(
                family=self.family,
                dst_len=self.dst_len,
                src_len=self.src_len,
                tos=self.tos,
                table=rtm_table,
                protocol=self.protocol,
                scope=self.scope,
                rtm_type=self.rtm_type,
                flags=self.flags,
            ).encode(),
        ]

        if self.table >= 256:
            parts.append(NLAttr.from_int_u32(RTAType.TABLE, self.table))

        if self.dst is not None:
            parts.append(NLAttr.from_ipaddress(RTAType.DST, self.dst))

        if self.oif is not None:
            parts.append(NLAttr.from_int_u32(RTAType.OIF, self.oif))

        if self.iif is not None:
            parts.append(NLAttr.from_int_u32(RTAType.IIF, self.iif))

        if self.gateway is not None:
            parts.append(NLAttr.from_ipaddress(RTAType.GATEWAY, self.gateway))

        if self.pref is not None:
            parts.append(NLAttr.from_int_u8(RTAType.PREF, self.pref))

        if self.prefsrc is not None:
            parts.append(NLAttr.from_ipaddress(RTAType.PREFSRC, self.prefsrc))

        if self.src is not None:
            parts.append(NLAttr.from_ipaddress(RTAType.SRC, self.src))

        if self.mark is not None:
            parts.append(NLAttr.from_int_u32(RTAType.MARK, self.mark))

        if self.uid is not None:
            parts.append(NLAttr.from_int_u32(RTAType.UID, self.uid))

        if self.priority is not None:
            parts.append(NLAttr.from_int_u32(RTAType.PRIORITY, self.priority))

        return b"".join(parts)

    @classmethod
    def rtm_get(
        cls, dst: IPv4Interface | IPv6Interface | None = None
    ) -> NetlinkRequest:
        flags: int = NLFlag.REQUEST
        if dst is None:
            flags |= NLFlag.DUMP
        route = _build_route(
            dst=dst.network if dst is not None else dst,
            rtm_type=RTNType.UNSPEC,
            scope=RTScope.UNIVERSE,
            protocol=RTProt.UNSPEC,
            table=RTTable.UNSPEC,
        )
        return NetlinkRequest(
            RTMType.GETROUTE, flags, route.to_nlmsg(), RTMType.NEWROUTE
        )

    @staticmethod
    def rtm_add(
        dst: IPv4Network | IPv6Network | None = None,
        gateway: IPv4Address | IPv6Address | None = None,
        oif: int | None = None,
        family: int | None = None,
        table: int | None = None,
    ) -> NetlinkRequest:
        flags: int = NLFlag.REQUEST | NLFlag.CREATE | NLFlag.ACK
        route = _build_route(
            dst=dst,
            gateway=gateway,
            oif=oif,
            family=family,
            table=table,
        )
        return NetlinkRequest(
            RTMType.NEWROUTE, flags, route.to_nlmsg(), RTMType.NEWROUTE
        )

    @staticmethod
    def rtm_del(
        dst: IPv4Network | IPv6Network | None = None,
        gateway: IPv4Address | IPv6Address | None = None,
        oif: int | None = None,
        family: int | None = None,
        table: int | None = None,
    ) -> NetlinkRequest:
        flags: int = NLFlag.REQUEST | NLFlag.CREATE | NLFlag.ACK
        route = _build_route(
            dst=dst,
            gateway=gateway,
            oif=oif,
            family=family,
            table=table,
        )
        return NetlinkRequest(
            RTMType.DELROUTE, flags, route.to_nlmsg(), RTMType.NEWROUTE
        )

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

        if self.uid is not None:
            parts.extend(["uid", str(self.uid)])

        if show_table:
            table = table_id_to_name(self.table) or str(self.table)
            parts.extend(["table", table])

        route_str = " ".join(parts)

        if self.family == socket.AF_INET and self.flags & RTMFlag.CLONED:
            route_str += "\n    cache"
            flags = self.flags & ~0xFFFF
            if flags != 0:
                flag_strs = []
                for flag in RTCFlag:
                    if bool(flags & flag):
                        flag_strs.append(flag.name.lower())
                route_str += f" <{','.join(flag_strs)}>"

        return route_str
