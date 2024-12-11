import ipaddress
import socket
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Callable, Final, Literal

from aiortnetlink.netlink import NLM_F_DUMP, NLM_F_REQUEST, NetlinkRequest, NLMsg
from aiortnetlink.route import RTMsg, RTNType
from aiortnetlink.rtm import RTMType

__all__ = ["Rule"]


RTNL_FAMILY_IPMR: Final = 128
RTNL_FAMILY_IP6MR: Final = 129


class FRAType(IntEnum):
    UNSPEC: Final = 0
    DST: Final = 1
    SRC: Final = 2
    IIFNAME: Final = 3
    GOTO: Final = 4
    UNUSED2: Final = 5
    PRIORITY: Final = 6
    UNUSED3: Final = 7
    UNUSED4: Final = 8
    UNUSED5: Final = 9
    FWMARK: Final = 10
    FLOW: Final = 11
    UNUSED6: Final = 12
    SUPPRESS_IFGROUP: Final = 12
    SUPPRESS_PREFIXLEN: Final = 13
    TABLE: Final = 14
    FWMASK: Final = 15
    OIFNAME: Final = 16
    UID_START: Final = 17
    UID_END: Final = 18


def get_rule_request() -> NetlinkRequest:
    parts = [RTMsg().encode()]
    flags = NLM_F_REQUEST | NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkRequest(RTMType.GETRULE, flags, data, RTMType.NEWRULE)


@dataclass(slots=True)
class Rule:
    family: int
    dst_len: int
    src_len: int
    tos: int
    table: int
    protocol: int
    scope: int
    rtm_type: int
    flags: int
    priority: int
    iif_name: str | None = None
    oif_name: str | None = None
    dst: IPv4Address | IPv6Address | None = None
    src: IPv4Address | IPv6Address | None = None
    fwmark: int | None = None
    fwmask: int | None = None

    @property
    def ip_version(self) -> Literal[4, 6] | None:
        match self.family:
            case socket.AF_INET:
                return 4
            case socket.AF_INET6:
                return 6
            case _:
                raise ValueError(f"Invalid IP family: {self.family}")

    @classmethod
    def from_nlmsg(cls, msg: NLMsg) -> "Rule":
        data = memoryview(msg.data)
        rtm, rtm_size = RTMsg.decode(data)

        iif_name: str | None = None
        oif_name: str | None = None
        dst: IPv4Address | IPv6Address | None = None
        src: IPv4Address | IPv6Address | None = None
        fwmark: int | None = None
        fwmask: int | None = None
        priority: int = 0

        for nlattr in msg.attrs(rtm_size):
            match nlattr.attr_type:
                case FRAType.IIFNAME:
                    iif_name = nlattr.as_string()
                case FRAType.OIFNAME:
                    oif_name = nlattr.as_string()
                case FRAType.DST:
                    dst = nlattr.as_ipaddress()
                case FRAType.SRC:
                    src = nlattr.as_ipaddress()
                case FRAType.FWMARK:
                    fwmark = nlattr.as_int()
                case FRAType.FWMASK:
                    fwmask = nlattr.as_int()
                case FRAType.PRIORITY:
                    priority = nlattr.as_int()
                case _:
                    # TODO: Parse remaining nlattrs.
                    pass

        return Rule(
            family=rtm.family,
            dst_len=rtm.dst_len,
            src_len=rtm.src_len,
            tos=rtm.tos,
            table=rtm.table,
            protocol=rtm.protocol,
            scope=rtm.scope,
            rtm_type=rtm.rtm_type,
            flags=rtm.flags,
            priority=priority,
            iif_name=iif_name,
            oif_name=oif_name,
            dst=dst,
            src=src,
            fwmark=fwmark,
            fwmask=fwmask,
        )

    @classmethod
    def rtm_get(cls) -> NetlinkRequest:
        return get_rule_request()

    def friendly_str(
        self,
        table_id_to_name: Callable[[int], str | None] = lambda _: None,
        proto_id_to_name: Callable[[int], str | None] = lambda _: None,
        scope_id_to_name: Callable[[int], str | None] = lambda _: None,
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

        if self.src:
            if self.src_len == self.src.max_prefixlen:
                parts.extend(["from", str(self.src)])
            else:
                parts.extend(
                    ["from", str(ipaddress.ip_interface((self.src, self.src_len)))]
                )
        elif self.src_len > 0:
            parts.extend(["from", f"0/{self.src_len}"])
        else:
            parts.extend(["from", "all"])

        if self.iif_name:
            parts.extend(["iif", self.iif_name])

        if self.oif_name:
            parts.extend(["oif", self.oif_name])

        if self.tos:
            parts.extend(["tos", str(self.tos)])

        if self.protocol:
            proto = proto_id_to_name(self.protocol) or str(self.protocol)
            parts.extend(["proto", proto])

        if self.scope:
            scope = scope_id_to_name(self.scope) or str(self.scope)
            parts.extend(["scope", scope])

        table = table_id_to_name(self.table) or str(self.table)
        parts.extend(["lookup", table])

        return f"{f"{self.priority}: ":<8}{" ".join(parts)}"
