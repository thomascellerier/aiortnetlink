"""
See https://docs.kernel.org/networking/netlink_spec/rt_route.html
"""

import os
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Final, Literal, NamedTuple

from aiortnetlink.netlink import NLM_F_DUMP, NLM_F_REQUEST, NetlinkGetRequest, NLMsg
from aiortnetlink.rtm import RTM_GETROUTE, RTM_NEWROUTE

__all__ = ["RTMsg", "get_route_request", "Route", "parse_rt_tables"]

_RTMSG_FMT = b"BBBBBBBBI"
_RTMSG_SIZE = struct.calcsize(_RTMSG_FMT)


class RTAType(IntEnum):
    RTA_UNSPEC: Final = 0
    RTA_DST: Final = 1
    RTA_SRC: Final = 2
    RTA_IIF: Final = 3
    RTA_OIF: Final = 4
    RTA_GATEWAY: Final = 5
    RTA_PRIORITY: Final = 6
    RTA_PREFSRC: Final = 7
    RTA_METRICS: Final = 8
    RTA_MULTIPATH: Final = 9
    RTA_PROTOINFO: Final = 10  # no longer used
    RTA_FLOW: Final = 11
    RTA_CACHEINFO: Final = 12
    RTA_SESSION: Final = 13  # no longer used
    RTA_MP_ALGO: Final = 14  # no longer used
    RTA_TABLE: Final = 15
    RTA_MARK: Final = 16
    RTA_MFC_STATS: Final = 17
    RTA_VIA: Final = 18
    RTA_NEWDST: Final = 19
    RTA_PREF: Final = 20
    RTA_ENCAP_TYPE: Final = 21
    RTA_ENCAP: Final = 22
    RTA_EXPIRES: Final = 23
    RTA_PAD: Final = 24
    RTA_UID: Final = 25
    RTA_TTL_PROPAGATE: Final = 26
    RTA_IP_PROTO: Final = 27
    RTA_SPORT: Final = 28
    RTA_DPORT: Final = 29
    RTA_NH_ID: Final = 30


class RTMsg(NamedTuple):
    """
    struct rtmsg {
        unsigned char rtm_family;   /* Address family of route */
        unsigned char rtm_dst_len;  /* Length of destination */
        unsigned char rtm_src_len;  /* Length of source */
        unsigned char rtm_tos;      /* TOS filter */
        unsigned char rtm_table;    /* Routing table ID;
                                     see RTA_TABLE below */
        unsigned char rtm_protocol; /* Routing protocol; see below */
        unsigned char rtm_scope;    /* See below */
        unsigned char rtm_type;     /* See below */

        unsigned int  rtm_flags;
    };
    """

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
        return RTMsg(*struct.unpack(_RTMSG_FMT, data[:_RTMSG_SIZE])), _RTMSG_SIZE

    def encode(self) -> bytes:
        return struct.pack(_RTMSG_FMT, *self)


def get_route_request() -> NetlinkGetRequest:
    parts = [RTMsg().encode()]
    flags = NLM_F_REQUEST | NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkGetRequest(RTM_GETROUTE, flags, data, RTM_NEWROUTE)


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
    prefsrc: IPv4Address | IPv6Address | None = None
    iif: int | None = None
    oif: int | None = None
    pref: int | None = None

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

        # If RTA_TABLE is set, rtm.table is ignored
        table = rtm.table
        iif: int | None = None
        oif: int | None = None
        dst: IPv4Address | IPv6Address | None = None
        gateway: IPv4Address | IPv6Address | None = None
        prefsrc: IPv4Address | IPv6Address | None = None
        priority: int | None = None
        pref: int | None = None

        for nlattr in msg.attrs(rtm_size):
            match nlattr.attr_type:
                case RTAType.RTA_TABLE:
                    table = nlattr.as_int()
                case RTAType.RTA_OIF:
                    oif = nlattr.as_int()
                case RTAType.RTA_IIF:
                    iif = nlattr.as_int()
                case RTAType.RTA_DST:
                    dst = nlattr.as_ipaddress()
                case RTAType.RTA_GATEWAY:
                    gateway = nlattr.as_ipaddress()
                case RTAType.RTA_PRIORITY:
                    priority = nlattr.as_int()
                case RTAType.RTA_PREF:
                    pref = nlattr.as_int()
                case RTAType.RTA_PREFSRC:
                    prefsrc = nlattr.as_ipaddress()
                case _:
                    # TODO: Handle remaining attributes, e.g. RTA_UNSPEC and RTA_CACHEINFO
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
            gateway=gateway,
            priority=priority,
            pref=pref,
            prefsrc=prefsrc,
        )

    @classmethod
    def rtm_get(cls) -> NetlinkGetRequest:
        return get_route_request()


def parse_rt_tables(
    rt_tables_path: str | os.PathLike[str] = "/etc/iproute2/rt_tables",
) -> dict[int, str]:
    """
    Parse routing table id to routing table name mapping file.
    """
    table_id_to_name = {}
    with open(rt_tables_path, "rb") as f:
        for lineno, line in enumerate(f, start=1):
            if line.startswith(b"#"):
                continue
            match line.split():
                case table_id_bytes, table_name_bytes:
                    try:
                        table_id = int(table_id_bytes)
                    except ValueError:
                        raise ValueError(
                            f"Invalid table id to name mapping at line {lineno} in {rt_tables_path}, "
                            f"table id should be an integer but got {table_id_bytes!r}"
                        ) from None
                    try:
                        table_name = table_name_bytes.decode("ascii")
                    except ValueError:
                        raise ValueError(
                            f"Invalid table id to name mapping at line {lineno} in {rt_tables_path}, "
                            f"table name should be an ascii string but got {table_name_bytes!r}"
                        ) from None
                    table_id_to_name[table_id] = table_name
                case _:
                    raise ValueError(
                        f"Invalid table id to name mapping at line {lineno} in {rt_tables_path}, "
                        "line should have two parts separated by whitespace, table id and table name, "
                        f"but got {line.rstrip()!r}"
                    )
    return table_id_to_name
