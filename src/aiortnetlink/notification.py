from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from aiortnetlink import rtm
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
        case rtm.RTM_NEWLINK:
            assert group_value == rtm.RTNLGRP_LINK
            return NewLinkNotification(iflink_type().from_nlmsg(msg))
        case rtm.RTM_DELLINK:
            assert group_value == rtm.RTNLGRP_LINK
            return DelLinkNotification(iflink_type().from_nlmsg(msg))
        case rtm.RTM_NEWADDR:
            assert group_value in (rtm.RTNLGRP_IPV4_IFADDR, rtm.RTNLGRP_IPV6_IFADDR)
            return NewAddrNotification(ifaddr_type().from_nlmsg(msg))
        case rtm.RTM_DELADDR:
            assert group_value in (rtm.RTNLGRP_IPV4_IFADDR, rtm.RTNLGRP_IPV6_IFADDR)
            return DelAddrNotification(ifaddr_type().from_nlmsg(msg))
        case rtm.RTM_NEWROUTE:
            assert group_value in (rtm.RTNLGRP_IPV4_ROUTE, rtm.RTNLGRP_IPV6_ROUTE)
            return NewRouteNotification(route_type().from_nlmsg(msg))
        case rtm.RTM_DELROUTE:
            assert group_value in (rtm.RTNLGRP_IPV4_ROUTE, rtm.RTNLGRP_IPV6_ROUTE)
            return DelRouteNotification(route_type().from_nlmsg(msg))
        case rtm.RTM_NEWRULE:
            assert group_value in (rtm.RTNLGRP_IPV4_RULE, rtm.RTNLGRP_IPV6_RULE)
            return NewRuleNotification(rule_type().from_nlmsg(msg))
        case rtm.RTM_DELRULE:
            assert group_value in (rtm.RTNLGRP_IPV4_RULE, rtm.RTNLGRP_IPV6_RULE)
            return DelRuleNotification(rule_type().from_nlmsg(msg))
        case _:
            return UnhandledNetlinkNotification(msg, group)
