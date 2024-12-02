from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from aiortnetlink.address import IFAddr
    from aiortnetlink.link import IFLink
    from aiortnetlink.netlink import NLMsg
    from aiortnetlink.notification import NetlinkNotification
    from aiortnetlink.route import Route
    from aiortnetlink.rule import Rule

__all__ = [
    "LazyValue",
    "iflink_type",
    "ifaddr_type",
    "route_type",
    "rule_type",
    "decode_notification_fn",
]


class LazyValue[T]:
    """
    Lazy value loader.
    """

    def __init__(self, load_value: Callable[[], T]) -> None:
        self._value: T | None = None
        self._load_value = load_value

    def __call__(self) -> T:
        if (value := self._value) is None:
            value = self._load_value()
            self._value = value

        return value


def iflink_type() -> type[IFLink]:
    from aiortnetlink.link import IFLink

    return IFLink


def ifaddr_type() -> type[IFAddr]:
    from aiortnetlink.address import IFAddr

    return IFAddr


def route_type() -> type[Route]:
    from aiortnetlink.route import Route

    return Route


def rule_type() -> type[Rule]:
    from aiortnetlink.rule import Rule

    return Rule


def decode_notification_fn() -> Callable[[NLMsg, int], NetlinkNotification]:
    from aiortnetlink.notification import decode_notification

    return decode_notification
