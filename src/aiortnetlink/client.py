import asyncio
import os
from types import TracebackType
from typing import AsyncIterator, Self

from aiortnetlink.link import IFLA_IFNAME, RTM_GETLINK, RTM_NEWLINK, IFLink, ifinfomsg
from aiortnetlink.netlink import (
    NLM_F_DUMP,
    NLM_F_DUMP_INTR,
    NLM_F_MULTI,
    NLM_F_REQUEST,
    NLMSG_DONE,
    NLMSG_ERROR,
    NetlinkDumpInterruptedError,
    NetlinkError,
    NetlinkOSError,
    NetlinkProtocol,
    NLMsg,
    create_netlink_endpoint,
    decode_nlmsg_error,
    encode_nlattr_str,
    encode_nlmsg,
)

__all__ = ["NetlinkClient"]


class NetlinkClient:
    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: NetlinkProtocol | None = None
        self._seqno = 0
        self._recvbuf_actual_size: int | None = None

    async def __aenter__(self) -> Self:
        transport, protocol = await create_netlink_endpoint()
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
        item = await protocol.get()
        match item:
            case Exception() as exc:
                raise exc
            case NLMsg() as msg, int(group):
                return msg, group
            case _:
                assert False, "unreachable"

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

    async def _recv(
        self, msg_type: int, seqno: int | None = None
    ) -> AsyncIterator[tuple[NLMsg, int]]:
        interrupted = False
        while True:
            msg, group = await self._recv_msg()

            if seqno is not None and msg.seq != seqno:
                print(f"Invalid seqno, expected {seqno} but got {msg.seq}")

            if bool(msg.flags & NLM_F_DUMP_INTR):
                # Defer the interrupted error to yield as much data as possible.
                # The application can then decide whether to use the partial dump or not.
                interrupted = True

            if msg.msg_type == msg_type:
                yield msg, group

            elif msg.msg_type == NLMSG_ERROR:
                nl_errno = decode_nlmsg_error(msg.data)
                if nl_errno == 0:
                    # A netlink acknowledgment is an NLMSG_ERROR packet with the error field set to 0.
                    break

                raise NetlinkOSError(-nl_errno, os.strerror(-nl_errno))

            elif msg.msg_type == NLMSG_DONE:
                break

            else:
                raise NetlinkError(f"Unhandled netlink type {msg.msg_type}")

            if not bool(msg.flags & NLM_F_MULTI):
                break

        if interrupted:
            # TODO: Pass msg type
            raise NetlinkDumpInterruptedError("Netlink dump interrupted")

    async def get_links(
        self, ifi_index: int = 0, ifi_name: str | None = None
    ) -> AsyncIterator[IFLink]:
        data = [ifinfomsg(index=ifi_index)]
        flags = NLM_F_REQUEST
        if ifi_name is not None:
            data.append(encode_nlattr_str(IFLA_IFNAME, ifi_name))
        elif ifi_index == 0:
            flags |= NLM_F_DUMP
        seqno = self._send_nlmsg(RTM_GETLINK, flags, b"".join(data))
        async for msg, group in self._recv(RTM_NEWLINK, seqno):
            assert group == 0
            yield IFLink.from_nlmsg(msg)

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
