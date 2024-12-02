import asyncio
import binascii
import ipaddress
import socket
import struct
import sys
from asyncio import DatagramTransport
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final, Iterator, NamedTuple

__all__ = [
    "NetlinkOSError",
    "NetlinkValueError",
    "NLM_F_DUMP",
    "NLM_F_REQUEST",
    "NetlinkDumpInterruptedError",
    "NLM_F_DUMP_INTR",
    "NLMSG_ERROR",
    "decode_nlmsg_error",
    "NLMSG_DONE",
    "NetlinkError",
    "NLM_F_MULTI",
    "NLM_F_CREATE",
    "NLM_F_REPLACE",
    "NLM_F_EXCL",
    "NLM_F_APPEND",
    "NLM_F_ACK",
    "NLMSG_MIN_TYPE",
    "NetlinkProtocol",
    "create_netlink_endpoint",
    "decode_nlattr_int",
    "decode_nlattr_str",
    "NLMsg",
    "NLAttr",
    "encode_nlmsg",
    "encode_nlattr_int",
    "encode_nlattr_str",
    "NetlinkRequest",
]


NETLINK_ROUTE: Final = 0
NETLINK_GENERIC: Final = 16

NLMSG_NOOP: Final = 0x1
NLMSG_ERROR: Final = 0x2
NLMSG_DONE: Final = 0x3
NLMSG_OVERRUN: Final = 0x4
NLMSG_MIN_TYPE: Final = 0x10


# Netlink flags
NLM_F_REQUEST: Final = 0x01
NLM_F_MULTI: Final = 0x02
NLM_F_ACK: Final = 0x04
NLM_F_ECHO: Final = 0x08
NLM_F_DUMP_INTR: Final = 0x10
NLM_F_DUMP_FILTERED: Final = 0x20

# Flags for get requests
NLM_F_ROOT: Final = 0x100
NLM_F_MATCH: Final = 0x200
NLM_F_ATOMIC: Final = 0x400
NLM_F_DUMP: Final = NLM_F_ROOT | NLM_F_MATCH

# Flags for new requests
NLM_F_REPLACE: Final = 0x100
NLM_F_EXCL: Final = 0x200
NLM_F_CREATE: Final = 0x400
NLM_F_APPEND: Final = 0x800

# Netlink socket options
SOL_NETLINK: Final = 270
NETLINK_EXT_ACK: Final = 11

# Netlink socket option to enable strict mode
NETLINK_GET_STRICT_CHK: Final = 12

# Set socket receive buffer size above limits imposed via sysctl,
# requires CAP_NET_ADMIN.
SO_RCVBUF_FORCE: Final = 33


_NLMsgHdrStruct = struct.Struct(
    b"I"  # Length of message, including header
    b"H"  # Netlink type
    b"H"  # Flags
    b"I"  # Sequence number
    b"I"  # Port id, traditionally the process id, 0 to auto-assign
)

_NLAStruct = struct.Struct(
    b"H"  # Netlink attribute type
    b"H"  # Netlink attribute size
)


class _NLMsgHdr(NamedTuple):
    msg_len: int
    msg_type: int
    flags: int
    seq: int
    pid: int = 0

    def pack(self) -> bytes:
        return _NLMsgHdrStruct.pack(*self)


class NLAttr(NamedTuple):
    attr_type: int
    data: memoryview

    def as_string(self) -> str:
        return decode_nlattr_str(self.data)

    def as_int(self) -> int:
        return decode_nlattr_int(self.data)

    def as_ipaddress(self) -> IPv4Address | IPv6Address:
        return ipaddress.ip_address(self.data.tobytes())

    def as_macaddress(self) -> str:
        return self.data.hex(sep=":", bytes_per_sep=1)

    @staticmethod
    def from_string(attr_type: int, value: str) -> bytes:
        return encode_nlattr_str(attr_type, value)

    @staticmethod
    def from_int(attr_type: int, value: int) -> bytes:
        return encode_nlattr_int(attr_type, value)

    @staticmethod
    def from_ipaddress(
        attr_type: int, value: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bytes:
        return encode_nlattr_ipaddress(attr_type, value)

    @staticmethod
    def from_macaddress(attr_type: int, value: str) -> bytes:
        return _nlattr(attr_type, binascii.unhexlify(value.replace(":", "")))


class NLMsg(NamedTuple):
    msg_len: int
    msg_type: int
    flags: int
    seq: int
    pid: int
    data: memoryview

    def attrs(self, type_header_size: int) -> Iterator[NLAttr]:
        yield from _parse_nlattrs(self.data[type_header_size : self.msg_len])


def encode_nlmsg(
    msg_type: int, flags: int, data: bytes, seqno: int, pid: int = 0
) -> bytes:
    msg_len = _NLMsgHdrStruct.size + len(data)
    header = _NLMsgHdr(
        msg_len=msg_len,
        msg_type=msg_type,
        flags=flags,
        seq=seqno,
        pid=pid,
    ).pack()
    return header + data


def _nlattr(
    nla_type: int,
    nla_data: bytes,
) -> bytes:
    nla_len = _NLAStruct.size + len(nla_data)
    padding_size = (4 - (nla_len % 4)) % 4
    return _NLAStruct.pack(nla_len, nla_type) + nla_data + b"\x00" * padding_size


def decode_nlattr_str(data: memoryview) -> str:
    """
    Netlink attribute strings are c-style nul-byte terminated ascii strings.
    We know their size in advance thanks to the nl attr length.
    """
    return data.tobytes().rstrip(b"\x00").decode("ascii")


def encode_nlattr_str(nla_type: int, value: str) -> bytes:
    return _nlattr(nla_type, value.encode("ascii") + b"\x00")


def decode_nlattr_int(data: memoryview) -> int:
    return int.from_bytes(data, sys.byteorder)


def encode_nlattr_int(nla_type: int, value: int) -> bytes:
    return _nlattr(nla_type, value.to_bytes(4, sys.byteorder))


def encode_nlattr_ipaddress(
    nla_type: int, value: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bytes:
    return _nlattr(nla_type, value.packed)


class NetlinkError(Exception):
    pass


class NetlinkConnectionClosedError(Exception):
    pass


class NetlinkOSError(NetlinkError, OSError):
    pass


class NetlinkDumpInterruptedError(NetlinkError):
    pass


class NetlinkValueError(NetlinkError, ValueError):
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
        assert pid == 0, f"netlink pid should be 0 but got {pid}"
        assert type(group) is int
        if group != 0:
            assert group & self._groups > 0

        pos = 0
        data_view = memoryview(data)
        size = len(data_view)
        while pos < size:
            msg_len, msg_type, flags, seqno, pid = _NLMsgHdrStruct.unpack_from(
                data_view,
                pos,
            )
            msg_data = data_view[
                pos + _NLMsgHdrStruct.size : pos + _NLMsgHdrStruct.size + msg_len
            ]

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


def decode_nlmsg_error(data: memoryview) -> int:
    (nl_errno,) = struct.unpack("i", data[:4])
    assert type(nl_errno) is int
    return nl_errno


def _parse_nlattrs(data: memoryview) -> Iterator[NLAttr]:
    pos = 0
    size = len(data)
    while pos < size:
        attr_len, attr_type = _NLAStruct.unpack_from(data, pos)
        yield NLAttr(attr_type, data[pos + 4 : pos + attr_len])

        # nlattrs are 4 byte aligned
        attr_len_aligned = attr_len + ((4 - (attr_len % 4)) % 4)
        pos += attr_len_aligned


def _netlink_socket(
    pid: int = 0, groups: int = 0, rcvbuf_size: int | None = None
) -> socket.socket:
    sock = socket.socket(
        type=socket.SOCK_DGRAM, family=socket.AF_NETLINK, proto=NETLINK_ROUTE
    )
    sock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
    # Tell the kernel not to ignore invalid options.
    sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)

    if rcvbuf_size is not None:
        if rcvbuf_size < 128:
            # The minimum (doubled) value for this option is 256.
            raise NetlinkValueError(
                f"Netlink socket receive buffer size should be greater or equal to 128 but got {rcvbuf_size}"
            )

        # Sets or gets the maximum socket receive buffer in bytes.
        # The kernel doubles this value (to allow space for bookkeeping overhead)
        # when it is set using setsockopt(2), and this doubled value is returned by getsockopt(2).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_size)
        actual_rcvbuf_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if actual_rcvbuf_size < rcvbuf_size * 2:
            # Using this socket option, a privileged (CAP_NET_ADMIN)
            # process can perform the same task as SO_RCVBUF, but the rmem_max limit can be overridden.
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUF_FORCE, rcvbuf_size)
            except PermissionError:
                raise NetlinkError(
                    f"Failed to set netlink socket receive buffer size to {rcvbuf_size}, "
                    f"actual receive buffer size is {actual_rcvbuf_size} but expected {rcvbuf_size * 2} "
                    "(value doubled by kernel).",
                ) from None

    if groups != 0:
        # Bind to indicate we are interested in notifications
        sock.bind((pid, groups))
    return sock


async def create_netlink_endpoint(
    pid: int = 0,
    groups: int = 0,
    rcvbuf_size: int | None = None,
) -> tuple[DatagramTransport, NetlinkProtocol]:
    sock = _netlink_socket(pid, groups, rcvbuf_size)
    return await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: NetlinkProtocol(pid, groups), sock=sock
    )


class NetlinkRequest(NamedTuple):
    msg_type: int
    flags: int
    data: bytes
    response_type: int
