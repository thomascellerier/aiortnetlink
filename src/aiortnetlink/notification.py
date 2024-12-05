from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from aiortnetlink import rtm
from aiortnetlink.lazy import ifaddr_type, iflink_type

if TYPE_CHECKING:
    from aiortnetlink.address import IFAddr
    from aiortnetlink.link import IFLink
    from aiortnetlink.netlink import NLMsg

__all__ = [
    "NetlinkNotification",
    "UnhandledNetlinkNotification",
    "NewLinkNotification",
    "DelLinkNotification",
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


NetlinkNotification = (
    UnhandledNetlinkNotification
    | NewLinkNotification
    | DelLinkNotification
    | NewAddrNotification
    | DelAddrNotification
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
        case _:
            return UnhandledNetlinkNotification(msg, group)
