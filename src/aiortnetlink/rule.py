import socket
from dataclasses import dataclass
from typing import Final, Literal

from aiortnetlink.netlink import NLM_F_DUMP, NLM_F_REQUEST, NetlinkGetRequest, NLMsg
from aiortnetlink.route import RTMsg
from aiortnetlink.rtm import RTM_GETRULE, RTM_NEWRULE

__all__ = ["Rule"]

# See <uapi/linux/rtnetlink.h>
# rtnetlink families. Values up to 127 are reserved for real address
# families, values above 128 may be used arbitrarily.
RTNL_FAMILY_IPMR: Final = 128
RTNL_FAMILY_IP6MR: Final = 129


def get_rule_request() -> NetlinkGetRequest:
    parts = [RTMsg().encode()]
    flags = NLM_F_REQUEST | NLM_F_DUMP
    data = b"".join(parts)
    return NetlinkGetRequest(RTM_GETRULE, flags, data, RTM_NEWRULE)


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

        for nlattr in msg.attrs(rtm_size):
            # TODO: Parse nlattrs
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
        )

    @classmethod
    def rtm_get(cls) -> NetlinkGetRequest:
        return get_rule_request()
