"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["NLFamily"]


class NLFamily(IntEnum):
    ROUTE = 0
    USERSOCK = 2
    FIREWALL = 3
    SOCK_DIAG = 4
    INET_DIAG = 4
    NFLOG = 5
    XFRM = 6
    SELINUX = 7
    ISCSI = 8
    AUDIT = 9
    FIB_LOOKUP = 10
    CONNECTOR = 11
    NETFILTER = 12
    IP6_FW = 13
    DNRTMSG = 14
    KOBJECT_UEVENT = 15
    GENERIC = 16
    CRYPTO = 21

    @property
    def constant_name(self) -> str:
        return f"NETLINK_{self.name}"
