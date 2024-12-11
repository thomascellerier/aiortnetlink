from __future__ import annotations

import asyncio
import collections
import os
from ipaddress import IPv4Interface, IPv6Interface
from typing import TYPE_CHECKING, Iterable

from aiortnetlink.lazy import (
    decode_notification_fn,
    ifaddr_type,
    iflink_type,
    route_type,
    rule_type,
)
from aiortnetlink.netlink import (
    NLM_F_DUMP_INTR,
    NLM_F_MULTI,
    NLM_F_REQUEST,
    NLMSG_DONE,
    NLMSG_ERROR,
    NetlinkDumpInterruptedError,
    NetlinkError,
    NetlinkOSError,
    NetlinkProtocol,
    NetlinkRequest,
    NetlinkValueError,
    NLMsg,
    create_netlink_endpoint,
    decode_nlmsg_error,
    encode_nlmsg,
)

if TYPE_CHECKING:
    from types import TracebackType
    from typing import TYPE_CHECKING, AsyncIterator, Self

    # NOTE: These modules should only be imported at type checking time!
    # We want the actual import to happen lazily to keep the module fast when
    # using only a subset of the functionality.
    from aiortnetlink.address import IFAddr
    from aiortnetlink.link import IFLink
    from aiortnetlink.notification import NetlinkNotification
    from aiortnetlink.route import Route
    from aiortnetlink.rule import Rule


__all__ = ["NetlinkClient"]


class NetlinkClient:
    def __init__(
        self, pid: int = 0, groups: Iterable[int] = (), rcvbuf_size: int | None = None
    ) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: NetlinkProtocol | None = None
        self._seqno = 0
        self._recvbuf_size: int | None = rcvbuf_size
        self._pid = pid

        # Calculate group mask used for netlink notifications, 0 means do not listen for notifications.
        group_mask = 0
        for group in groups:
            group_mask |= 1 << (group - 1)
        self._groups = group_mask

        # Buffered notifications, this allows receiving notifications while processing a response on the same socket.
        self._notifications: collections.deque[tuple[NLMsg, int]] = collections.deque()

    async def __aenter__(self) -> Self:
        transport, protocol = await create_netlink_endpoint(
            pid=self._pid,
            groups=self._groups,
            rcvbuf_size=self._recvbuf_size,
        )
        self._transport = transport
        self._protocol = protocol
        return self

    async def __aexit__(
        self, exc_type: type[Exception], exc_value: Exception, traceback: TracebackType
    ) -> None:
        assert self._transport is not None
        self._transport.close()

    async def _recv_msg(self) -> tuple[NLMsg, int]:
        protocol = self._protocol
        assert protocol is not None
        msg, group = await protocol.get()

        if msg.msg_type == NLMSG_ERROR:
            nl_errno = decode_nlmsg_error(msg.data)
            if nl_errno != 0:
                # A netlink acknowledgment is an NLMSG_ERROR packet with the error field set to 0.
                raise NetlinkOSError(-nl_errno, os.strerror(-nl_errno))

        return msg, group

    async def _recv_notification(self) -> tuple[NLMsg, int]:
        """
        Receive netlink asynchronous notification message.

        Pop first for the internal notifications queue, notifications might have been added there while processing
        another netlink request using the same netlink socket.
        """
        if self._notifications:
            msg, group = self._notifications.pop()
        else:
            msg, group = await self._recv_msg()

        if group == 0:
            raise NetlinkError(f"Not a netlink notification {msg=} {group=}")

        return msg, group

    async def recv_notification(self) -> NetlinkNotification:
        msg, group = await self._recv_notification()
        decode_notification = decode_notification_fn()
        return decode_notification(msg, group)

    def _send_nlmsg(self, msg_type: int, flags: int, data: bytes) -> int:
        """
        Send a netlink message and return its sequence number.
        """
        assert self._transport is not None

        seqno = self._seqno
        self._seqno += 1

        msg = encode_nlmsg(
            msg_type=msg_type,
            flags=flags,
            data=data,
            seqno=seqno,
        )
        self._transport.sendto(msg, (0, 0))
        return seqno

    async def _recv_response(
        self, msg_type: int, seqno: int | None = None
    ) -> AsyncIterator[tuple[NLMsg, int]]:
        interrupted = False
        while True:
            msg, group = await self._recv_msg()

            if group != 0:
                # This is a notification, put it in queue
                self._notifications.append((msg, group))
                continue

            if seqno is not None and msg.seq != seqno:
                raise NetlinkError(f"Invalid seqno, expected {seqno} but got {msg.seq}")

            if bool(msg.flags & NLM_F_DUMP_INTR):
                # Defer the interrupted error to yield as much data as possible.
                # The application can then decide whether to use the partial dump or not.
                interrupted = True

            if msg.msg_type == msg_type:
                yield msg, group

            elif msg.msg_type == NLMSG_ERROR:
                # A netlink acknowledgment is an NLMSG_ERROR packet with the error field set to 0.
                # Here we rely on the fact that self._recv_msg already handled non-zero errors.
                break

            elif msg.msg_type == NLMSG_DONE:
                break

            else:
                raise NetlinkError(f"Unhandled netlink type {msg.msg_type}")

            if not bool(msg.flags & NLM_F_MULTI):
                break

        if interrupted:
            # TODO: Pass msg type
            raise NetlinkDumpInterruptedError("Netlink dump interrupted")

    async def _send_request(self, request: NetlinkRequest) -> AsyncIterator[NLMsg]:
        if not request.flags & NLM_F_REQUEST:
            raise NetlinkValueError(
                f"Netlink request should have request flag set {bin(NLM_F_REQUEST)}, "
                f"but got {bin(request.flags)}"
            )
        seqno = self._send_nlmsg(request.msg_type, request.flags, request.data)
        async for msg, group in self._recv_response(request.response_type, seqno):
            assert group == 0
            yield msg

    async def get_links(
        self, ifi_index: int = 0, ifi_name: str | None = None
    ) -> AsyncIterator[IFLink]:
        iflink_type_ = iflink_type()
        request = iflink_type_.rtm_get(ifi_index=ifi_index, ifi_name=ifi_name)
        async for msg in self._send_request(request):
            yield iflink_type_.from_nlmsg(msg)

    async def get_link(
        self, ifi_index: int = 0, ifi_name: str | None = None
    ) -> IFLink | None:
        if ifi_index == 0 and ifi_name is None:
            raise ValueError("Link index or name is required")
        found_link: IFLink | None = None
        try:
            async for link in self.get_links(ifi_index=ifi_index, ifi_name=ifi_name):
                found_link = link
        except NetlinkOSError as e:
            if e.errno == 19:
                # [Errno 19] No such device
                return None
        assert found_link is not None
        return found_link

    async def get_addrs(
        self, ifi_index: int = 0, ifi_name: str | None = None
    ) -> AsyncIterator[IFAddr]:
        ifaddr_type_ = ifaddr_type()
        request = ifaddr_type_.rtm_get(ifi_index=ifi_index, ifi_name=ifi_name)
        async for msg in self._send_request(request):
            yield ifaddr_type_.from_nlmsg(msg)

    async def add_addr(
        self, addr: IPv4Interface | IPv6Interface, ifi_index: int
    ) -> None:
        ifaddr_type_ = ifaddr_type()
        request = ifaddr_type_.rtm_add(addr, ifi_index=ifi_index)
        async for _ in self._send_request(request):
            pass

    async def del_addr(
        self, addr: IPv4Interface | IPv6Interface, ifi_index: int
    ) -> None:
        ifaddr_type_ = ifaddr_type()
        request = ifaddr_type_.rtm_del(addr, ifi_index=ifi_index)
        async for _ in self._send_request(request):
            pass

    async def get_routes(self) -> AsyncIterator[Route]:
        route_type_ = route_type()
        request = route_type_.rtm_get()
        async for msg in self._send_request(request):
            yield route_type_.from_nlmsg(msg)

    async def get_rules(self) -> AsyncIterator[Rule]:
        rule_type_ = rule_type()
        request = rule_type_.rtm_get()
        async for msg in self._send_request(request):
            yield rule_type_.from_nlmsg(msg)

    async def get_family(self, family: str) -> None:
        # TODO: Make it work!
        from aiortnetlink.gennl import get_family_request

        request = get_family_request(family)
        async for msg in self._send_request(request):
            print(f"{msg=}")
