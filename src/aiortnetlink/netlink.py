"""
See:
- https://docs.kernel.org/userspace-api/netlink/intro.html
- https://wiki.linuxfoundation.org/networking/generic_netlink_howto
"""

import asyncio
from dataclasses import dataclass
import os
import socket
import struct
from types import TracebackType
from typing import Iterator, AsyncIterator, Final, Self, NamedTuple, Any

__all__ = [
    "NetlinkProtocol",
]


# See <uapi/linux/netlink.h>
NETLINK_ROUTE: Final = 0
NETLINK_GENERIC: Final = 16

NLMSG_NOOP: Final = 0x1
NLMSG_ERROR: Final = 0x2
NLMSG_DONE: Final = 0x3
NLMSG_OVERRUN: Final = 0x4
NLMSG_MIN_TYPE: Final = 0x10

# Flags values
NLM_F_REQUEST: Final = 0x01  # It is request message.
NLM_F_MULTI: Final = 0x02  # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK: Final = 0x04  # Reply with ack, with zero or error code
NLM_F_ECHO: Final = 0x08  # Receive resulting notifications
NLM_F_DUMP_INTR: Final = 0x10  # Dump was inconsistent due to sequence change
NLM_F_DUMP_FILTERED: Final = 0x20  # Dump was filtered as requested

# Modifiers to GET request
NLM_F_ROOT: Final = 0x100
NLM_F_MATCH: Final = 0x200
NLM_F_ATOMIC: Final = 0x400
NLM_F_DUMP: Final = NLM_F_ROOT | NLM_F_MATCH

# See <uapi/linux/genetlink.h>
GENL_ID_CTRL: Final = NLMSG_MIN_TYPE

CTRL_CMD_UNSPEC: Final = 0
CTRL_CMD_NEWFAMILY: Final = 1
CTRL_CMD_DELFAMILY: Final = 2
CTRL_CMD_GETFAMILY: Final = 3
CTRL_CMD_NEWOPS: Final = 4
CTRL_CMD_DELOPS: Final = 5
CTRL_CMD_GETOPS: Final = 6
CTRL_CMD_NEWMCAST_GRP: Final = 7
CTRL_CMD_DELMCAST_GRP: Final = 8
CTRL_CMD_GETMCAST_GRP: Final = 9  # unused

CTRL_ATTR_UNSPEC: Final = 0
CTRL_ATTR_FAMILY_ID: Final = 1
CTRL_ATTR_FAMILY_NAME: Final = 2
CTRL_ATTR_VERSION: Final = 3
CTRL_ATTR_HDRSIZE: Final = 4
CTRL_ATTR_MAXATTR: Final = 5
CTRL_ATTR_OPS: Final = 6
CTRL_ATTR_MCAST_GROUPS: Final = 7

# NL structs
_NLMSGHDR_FMT: Final = "IHHII"
_NLMSGHDR_SIZE: Final = struct.calcsize(_NLMSGHDR_FMT)
_GENMSGHDR_FMT: Final = "BBI"
_GENMSGHDR_SIZE: Final = struct.calcsize(_GENMSGHDR_FMT)
_NLA_FMT: Final = "HH"
_NLA_SIZE: Final = struct.calcsize(_NLA_FMT)

# See <linux/socket.h>
SOL_NETLINK: Final = 270
NETLINK_EXT_ACK: Final = 11

# See <linux/if_arp.h>
ARPHRD_LOOPBACK: Final = 772
ARPHRD_ETHER: Final = 1


def _nlmsghdr(
    msg_len: int,
    msg_type: int,
    flags: int,
    seq: int,
    pid: int = 0,
) -> bytes:
    """
    struct nlmsghdr {
      __u32   nlmsg_len;      /* Length of message including headers */
      __u16   nlmsg_type;     /* Generic Netlink Family (subsystem) ID */
      __u16   nlmsg_flags;    /* Flags - request or dump */
      __u32   nlmsg_seq;      /* Sequence number */
      __u32   nlmsg_pid;      /* Port ID, set to 0 */
    };
    """
    return struct.pack(_NLMSGHDR_FMT, msg_len, msg_type, flags, seq, pid)


class NLMsg(NamedTuple):
    msg_len: int
    msg_type: int
    flags: int
    seq: int
    pid: int
    data: memoryview


def _genmsghdr(
    cmd: int,
    version: int = 1,
    reserved: int = 0,
) -> bytes:
    """
    struct genlmsghdr {
      __u8    cmd;            /* Command, as defined by the Family */
      __u8    version;        /* Irrelevant, set to 1 */
      __u16   reserved;       /* Reserved, set to 0 */
    };
    """
    return struct.pack(_GENMSGHDR_FMT, cmd, version, reserved)


RTM_NEWLINK: Final = 16
RTM_DELLINK: Final = 17
RTM_GETLINK: Final = 18

_IFINFOMSG_FMT: Final = "BxHiII"
_IFINFOMSG_SIZE: Final = struct.calcsize(_IFINFOMSG_FMT)


def _ifinfomsg(
    family: int = socket.AF_NETLINK,
    ifi_type: int = 0,
    index: int = 0,
    flags: int = 0,
    change: int = 0,
) -> bytes:
    """

    struct ifinfomsg {
        unsigned char  ifi_family; /* AF_UNSPEC */
        unsigned char  __ifi_pad;
        unsigned short ifi_type;   /* Device type */
        int            ifi_index;  /* Interface index */
        unsigned int   ifi_flags;  /* Device flags  */
        unsigned int   ifi_change; /* change mask */
    };
    """
    return struct.pack(_IFINFOMSG_FMT, family, ifi_type, index, flags, change)


def _nlattr(
    nla_type: int,
    nla_data: bytes,
) -> bytes:
    nla_len = _NLA_SIZE + len(nla_data)
    padding_size = (4 - (nla_len % 4)) % 4
    return struct.pack(_NLA_FMT, nla_len, nla_type) + nla_data + b"\x00" * padding_size


@dataclass(slots=True)
class IFLink:
    family: int
    if_type: int
    index: int
    flags: int
    change: int
    _nlattrs: dict[int, memoryview]

    @property
    def name(self) -> str:
        return self._nlattrs[3].tobytes().rstrip(b"\x00").decode("ascii")


class NetlinkError(Exception):
    pass


class NetlinkConnectionClosedError(Exception):
    pass


class NetlinkOSError(NetlinkError, OSError):
    pass


class NetlinkDumpInterruptedError(NetlinkError):
    pass


class NetlinkProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        pid: int = 0,
        groups: int = 0,
        max_queue_size: int = 1024 * 1024,
    ) -> None:
        self._pid = pid
        self._groups = groups
        self._transport: asyncio.DatagramTransport | None = None
        self._recv_q: asyncio.Queue[tuple[NLMsg, int] | Exception] = asyncio.Queue(
            maxsize=max_queue_size
        )
        # Future to be able to set an error in case the queue is full.
        self._closed: asyncio.Future[None] = asyncio.Future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            self._closed.set_exception(exc)
        else:
            self._closed.set_result(None)

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self._closed.done():
            return

        pid, group = addr
        assert pid == 0, f"netlink pid shoudl be 0 but got {pid}"
        assert type(group) is int
        if group != 0:
            assert group & self._groups > 0

        pos = 0
        data_view = memoryview(data)
        size = len(data_view)
        while pos < size:
            msg_len, msg_type, flags, seqno, pid = struct.unpack(
                _NLMSGHDR_FMT,
                data_view[pos : pos + _NLMSGHDR_SIZE],
            )
            msg_data = data_view[pos + _NLMSGHDR_SIZE : pos + _NLMSGHDR_SIZE + msg_len]

            nlmsg = NLMsg(
                msg_len,
                msg_type,
                flags,
                seqno,
                pid,
                msg_data,
            )

            pos += msg_len
            try:
                self._recv_q.put_nowait((nlmsg, group))
            except asyncio.QueueFull:
                assert self._transport is not None
                self._transport.close()
                self._closed.set_exception(NetlinkError("Receive queue full"))
                return

        if pos != size:
            self._closed.set_exception(
                NetlinkError(
                    "Netlink protocol parsing error, "
                    "processed {pos}/{size} bytes from datagram"
                )
            )

    def error_received(self, exc: Exception) -> None:
        assert self._transport is not None
        self._transport.close()
        self._closed.set_exception(exc)

    async def get(self) -> tuple[NLMsg, int]:
        """
        Get netlink message.

        Raises an exception if there was a netlink socket error or the receive queue is full.
        """
        if self._closed.done():
            # Protocol closed, get remaining messages from queue
            try:
                match self._recv_q.get_nowait():
                    case NLMsg() as msg, int() as group:
                        return msg, group
                    case Exception() as exc:
                        raise exc
                    case _:
                        assert False, "unreachable"
            except asyncio.QueueEmpty:
                _ = self._closed.result()
                raise NetlinkConnectionClosedError("Connection closed")

        get_task = asyncio.create_task(self._recv_q.get())
        futures: set[asyncio.Future[Any]] = {get_task, self._closed}
        done, _ = await asyncio.wait(
            futures,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            if task == get_task:
                match get_task.result():
                    case NLMsg() as msg, int() as group:
                        return msg, group
                    case Exception() as exc:
                        raise exc
                    case _:
                        assert False, "unreachable"
            elif task == self._closed:
                try:
                    _ = self._closed.result()
                    raise NetlinkConnectionClosedError("Connection closed")
                finally:
                    # Make sure to cancel the receive task!
                    get_task.cancel()
                    try:
                        await get_task
                    except asyncio.CancelledError:
                        current_task = asyncio.current_task()
                        assert current_task is not None
                        if current_task.cancelling() > 0:
                            raise
            else:
                assert False, "unreachable"
        assert False, "unreachable"


def _parse_nlmsg_error(data: bytes) -> int:
    (nl_errno,) = struct.unpack("i", data[:4])
    assert type(nl_errno) is int
    return nl_errno


def _parse_nlattrs(data: memoryview) -> Iterator[tuple[int, memoryview]]:
    pos = 0
    size = len(data)
    while pos < size:
        attr_len, attr_type = struct.unpack("HH", data[pos : pos + 4])
        yield attr_type, data[pos + 4 : pos + attr_len]

        # nlattrs are 4 byte ligend
        attr_len_aligned = attr_len + ((4 - (attr_len % 4)) % 4)
        pos += attr_len_aligned


class NetlinkClient:
    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: NetlinkProtocol | None = None
        self._seqno = 0

    async def __aenter__(self) -> Self:
        loop = asyncio.get_running_loop()
        sock = socket.socket(
            type=socket.SOCK_DGRAM, family=socket.AF_NETLINK, proto=NETLINK_ROUTE
        )
        sock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: NetlinkProtocol(), sock=sock
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

        msg_len = _NLMSGHDR_SIZE + len(data)
        header = _nlmsghdr(
            msg_len=msg_len,
            msg_type=msg_type,
            flags=flags,
            seq=seqno,
            pid=0,
        )
        msg = header + data
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
                nl_errno = _parse_nlmsg_error(msg.data)
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

    async def get_links(self) -> AsyncIterator[IFLink]:
        data = _ifinfomsg()
        seqno = self._send_nlmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, data)
        async for msg, group in self._recv(RTM_NEWLINK, seqno):
            assert group == 0
            data = memoryview(msg.data)
            ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack(
                _IFINFOMSG_FMT, data[:_IFINFOMSG_SIZE]
            )
            pos = _IFINFOMSG_SIZE
            nlattrs_data = data[pos : msg.msg_len]
            yield IFLink(
                family=ifi_family,
                index=ifi_index,
                if_type=ifi_type,
                flags=ifi_flags,
                change=ifi_change,
                _nlattrs=dict(_parse_nlattrs(nlattrs_data)),
            )


async def main() -> None:
    async with NetlinkClient() as nl:
        async for link in nl.get_links():
            print(f"{link.index}: {link.name}")


if __name__ == "__main__":
    asyncio.run(main())
