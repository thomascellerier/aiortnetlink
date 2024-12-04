import os
import socket
import struct
from dataclasses import dataclass
from typing import Final, Literal

from aiortnetlink.netlink import NLM_F_DUMP, NLM_F_REQUEST, NetlinkGetRequest, NLMsg

__all__ = ["rtmsg", "get_route_request", "Route", "parse_rt_tables"]

RTM_NEWROUTE: Final = 24
RTM_DELROUTE: Final = 25
RTM_GETROUTE: Final = 26

_RTMSG_FMT = b"BBBBBBBBI"
_RTMSG_SIZE = struct.calcsize(_RTMSG_FMT)


def rtmsg(
    family: int = 0,
    dst_len: int = 0,
    src_len: int = 0,
    tos: int = 0,
    table: int = 0,
    protocol: int = 0,
    scope: int = 0,
    rtm_type: int = 0,
    flags: int = 0,
) -> bytes:
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
    return struct.pack(
        _RTMSG_FMT,
        family,
        dst_len,
        src_len,
        tos,
        table,
        protocol,
        scope,
        rtm_type,
        flags,
    )


def get_route_request() -> NetlinkGetRequest:
    parts = [rtmsg()]
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
        (
            rtm_family,
            rtm_dst_len,
            rtm_src_len,
            rtm_tos,
            rtm_table,
            rtm_protocol,
            rtm_scope,
            rtm_type,
            flags,
        ) = struct.unpack(_RTMSG_FMT, data[:_RTMSG_SIZE])

        for nlattr in msg.attrs(_RTMSG_SIZE):
            # TODO: Parse nlattrs
            pass

        return Route(
            family=rtm_family,
            dst_len=rtm_dst_len,
            src_len=rtm_src_len,
            tos=rtm_tos,
            table=rtm_table,
            protocol=rtm_protocol,
            scope=rtm_scope,
            rtm_type=rtm_type,
            flags=flags,
        )

    @classmethod
    def rtm_request_get(cls) -> NetlinkGetRequest:
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
