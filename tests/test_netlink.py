from aiortnetlink.netlink import encode_nlmsg


def test_encode_nlmsg() -> None:
    assert (
        encode_nlmsg(msg_type=1, flags=6, data=b"\x01\x02\x03\x04\x05", seqno=123)
        == b"\x15\x00\x00\x00\x01\x00\x06\x00{\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05"
    )
