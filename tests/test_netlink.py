from aiortnetlink.netlink import _nlmsghdr


def test_nlmsghdr() -> None:
    assert (
        _nlmsghdr(msg_len=12, msg_type=1, flags=6, seq=123)
        == b"\x0c\x00\x00\x00\x01\x00\x06\x00{\x00\x00\x00\x00\x00\x00\x00"
    )
