from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from aiortnetlink.constants.rtmtype import RTMType
from aiortnetlink.constants.rtnlgroup import RTNLGroup
from aiortnetlink.lazy import ifaddr_type, iflink_type, route_type, rule_type

if TYPE_CHECKING:
    from aiortnetlink.address import IFAddr
    from aiortnetlink.link import IFLink
    from aiortnetlink.netlink import NLMsg
    from aiortnetlink.route import Route
    from aiortnetlink.rule import Rule


__all__ = [
    "NetlinkNotification",
    "UnhandledNetlinkNotification",
    "NewLinkNotification",
    "DelLinkNotification",
    "NewAddrNotification",
    "DelAddrNotification",
    "NewRouteNotification",
    "DelRouteNotification",
    "decode_notification",
]


@dataclass(slots=True)
class _NetlinkNotificationBase:
    pass


@dataclass(slots=True)
class UnhandledNetlinkNotification:
    msg: NLMsg
    group: int


@dataclass(slots=True)
class NewLinkNotification:
    link: IFLink


@dataclass(slots=True)
class DelLinkNotification:
    link: IFLink


@dataclass(slots=True)
class NewAddrNotification:
    link: IFAddr


@dataclass(slots=True)
class DelAddrNotification:
    link: IFAddr


@dataclass(slots=True)
class NewRouteNotification:
    link: Route


@dataclass(slots=True)
class DelRouteNotification:
    link: Route


@dataclass(slots=True)
class NewRuleNotification:
    link: Rule


@dataclass(slots=True)
class DelRuleNotification:
    link: Rule


NetlinkNotification = (
    UnhandledNetlinkNotification
    | NewLinkNotification
    | DelLinkNotification
    | NewAddrNotification
    | DelAddrNotification
    | NewRouteNotification
    | DelRouteNotification
    | NewRuleNotification
    | DelRuleNotification
)


def decode_notification(msg: NLMsg, group: int) -> NetlinkNotification:
    # Get the group value from the group mask by getting position of the highest bit,
    # This assumes that netlink notifications only every set one group bit.
    group_value = group.bit_length()
    match msg.msg_type:
        case RTMType.NEWLINK:
            assert group_value == RTNLGroup.LINK
            return NewLinkNotification(iflink_type().from_nlmsg(msg))
        case RTMType.DELLINK:
            assert group_value == RTNLGroup.LINK
            return DelLinkNotification(iflink_type().from_nlmsg(msg))
        case RTMType.NEWADDR:
            assert group_value in (RTNLGroup.IPV4_IFADDR, RTNLGroup.IPV6_IFADDR)
            return NewAddrNotification(ifaddr_type().from_nlmsg(msg))
        case RTMType.DELADDR:
            assert group_value in (RTNLGroup.IPV4_IFADDR, RTNLGroup.IPV6_IFADDR)
            return DelAddrNotification(ifaddr_type().from_nlmsg(msg))
        case RTMType.NEWROUTE:
            assert group_value in (RTNLGroup.IPV4_ROUTE, RTNLGroup.IPV6_ROUTE)
            return NewRouteNotification(route_type().from_nlmsg(msg))
        case RTMType.DELROUTE:
            assert group_value in (RTNLGroup.IPV4_ROUTE, RTNLGroup.IPV6_ROUTE)
            return DelRouteNotification(route_type().from_nlmsg(msg))
        case RTMType.NEWRULE:
            assert group_value in (RTNLGroup.IPV4_RULE, RTNLGroup.IPV6_RULE)
            return NewRuleNotification(rule_type().from_nlmsg(msg))
        case RTMType.DELRULE:
            assert group_value in (RTNLGroup.IPV4_RULE, RTNLGroup.IPV6_RULE)
            return DelRuleNotification(rule_type().from_nlmsg(msg))
        case _:
            return UnhandledNetlinkNotification(msg, group)
