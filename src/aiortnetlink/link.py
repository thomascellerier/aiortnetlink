import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Final

from aiortnetlink.constants.arphrdtype import ARPHRDType
from aiortnetlink.constants.ifflag import IFFlag
from aiortnetlink.constants.iflatype import IFLAType
from aiortnetlink.constants.nlflag import NLFlag
from aiortnetlink.constants.rtmtype import RTMType
from aiortnetlink.netlink import (
    NetlinkRequest,
    NLMsg,
    encode_nlattr_str,
)

__all__ = ["IFLink", "ifinfomsg"]


class IFOper(IntEnum):
    # TODO: GENERATE
    UNKNOWN: Final = 0
    NOTPRESENT: Final = 1
    DOWN: Final = 2
    LOWERLAYERDOWN: Final = 3
    TESTING: Final = 4
    DORMANT: Final = 5
    UP: Final = 6


class IFLinkMode(IntEnum):
    # TODO: GENERATE
    DEFAULT: Final = 0
    DORMANT: Final = 1
    TESTING: Final = 2


IFInfoMsg: Final = struct.Struct(
    b"B"  # Family
    b"x"  # Padding
    b"H"  # Type
    b"i"  # Index
    b"I"  # Flags
    b"I"  # Change
)


def ifinfomsg(
    family: int = 0,
    ifi_type: int = 0,
    index: int = 0,
    flags: int = 0,
    change: int = 0,
) -> bytes:
    return IFInfoMsg.pack(family, ifi_type, index, flags, change)


@dataclass(slots=True)
class IFLink:
    family: int
    if_type: int
    index: int
    flags: int
    # For a new link the change mask will be set to 0xFFFF_FFFF.
    # For a notification the mask will be set to what actually changed, e.g. 0x1 for operstate changed.
    # For a request the change mask should be set to 0x0.
    change: int
    name: str
    address: str | None
    mtu: int | None
    qdisc: str | None
    operstate: IFOper | None = None
    linkmode: IFLinkMode = IFLinkMode.DEFAULT
    group: int | None = None
    txqlen: int | None = None
    broadcast: str | None = None

    @classmethod
    def from_nlmsg(cls, msg: NLMsg) -> "IFLink":
        data = memoryview(msg.data)
        ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = IFInfoMsg.unpack_from(
            data
        )

        name: str | None = None
        address: str | None = None
        mtu: int | None = None
        qdisc: str | None = None
        operstate: IFOper | None = None
        linkmode: IFLinkMode | None = None
        group: int | None = None
        txqlen: int | None = None
        broadcast: str | None = None

        for nlattr in msg.attrs(IFInfoMsg.size):
            match nlattr.attr_type:
                case IFLAType.IFNAME:
                    name = nlattr.as_string()
                case IFLAType.ADDRESS:
                    address = nlattr.as_macaddress()
                case IFLAType.MTU:
                    mtu = nlattr.as_int()
                case IFLAType.QDISC:
                    qdisc = nlattr.as_string()
                case IFLAType.OPERSTATE:
                    operstate = IFOper(nlattr.as_int())
                case IFLAType.LINKMODE:
                    linkmode = IFLinkMode(nlattr.as_int())
                case IFLAType.GROUP:
                    group = nlattr.as_int()
                case IFLAType.TXQLEN:
                    txqlen = nlattr.as_int()
                case IFLAType.BROADCAST:
                    broadcast = nlattr.as_macaddress()

        assert name is not None
        assert linkmode is not None

        return IFLink(
            family=ifi_family,
            index=ifi_index,
            if_type=ifi_type,
            flags=ifi_flags,
            change=ifi_change,
            name=name,
            address=address,
            mtu=mtu,
            qdisc=qdisc,
            operstate=operstate,
            linkmode=linkmode,
            group=group,
            txqlen=txqlen,
            broadcast=broadcast,
        )

    @classmethod
    def rtm_get(cls, ifi_index: int = 0, ifi_name: str | None = None) -> NetlinkRequest:
        return get_link_request(ifi_index, ifi_name)

    def friendly_footer_str(self) -> str:
        try:
            link_type = ARPHRDType(self.if_type).name.lower()
        except ValueError:
            link_type = str(self.if_type)
        parts = [f"link/{link_type}"]

        if self.address is not None:
            parts.append(self.address)

        if self.broadcast is not None:
            parts.extend(["brd", self.broadcast])

        return "\n    " + " ".join(parts)

    def friendly_str(
        self,
        group_id_to_name: Callable[[int], str | None] = lambda _: None,
        show_mode: bool = True,
    ) -> str:
        flags = []

        if self.flags & IFFlag.UP and not self.flags & IFFlag.RUNNING:
            flags.append("NO-CARRIER")

        for flag in IFFlag:
            if self.flags & flag:
                if flag == IFFlag.RUNNING:
                    continue
                flags.append(flag.name)

        parts = [f"{self.index}:", f"{self.name}:", f"<{','.join(flags)}>"]

        if self.mtu:
            parts.extend(["mtu", str(self.mtu)])

        if self.qdisc:
            parts.extend(["qdisc", str(self.qdisc)])

        if self.operstate:
            parts.extend(["state", IFOper(self.operstate).name])
        else:
            parts.extend(["state", "UNKNOWN"])

        if show_mode:
            parts.extend(["mode", IFLinkMode(self.linkmode).name])

        if self.group is not None:
            parts.extend(["group", group_id_to_name(self.group) or str(self.group)])

        if self.txqlen is not None:
            parts.extend(["qlen", str(self.txqlen)])

        return " ".join(parts) + self.friendly_footer_str()


def get_link_request(ifi_index: int = 0, ifi_name: str | None = None) -> NetlinkRequest:
    parts = [ifinfomsg(index=ifi_index)]
    flags = NLFlag.REQUEST.value
    if ifi_name is not None:
        parts.append(encode_nlattr_str(IFLAType.IFNAME, ifi_name))
    elif ifi_index == 0:
        flags |= NLFlag.DUMP
    data = b"".join(parts)
    return NetlinkRequest(RTMType.GETLINK, flags, data, RTMType.NEWLINK)
