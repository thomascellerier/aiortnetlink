#!/usr/bin/env python3
"""
Generate python enums from C constants.
"""

import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

netlink_families = [
    "NETLINK_ROUTE",
    "NETLINK_W1",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_INET_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_CRYPTO",
]

netlink_flags = [
    "NLM_F_REQUEST",
    "NLM_F_MULTI",
    "NLM_F_ACK",
    "NLM_F_ECHO",
    "NLM_F_ROOT",
    "NLM_F_MATCH",
    "NLM_F_ATOMIC",
    "NLM_F_DUMP",
    "NLM_F_REPLACE",
    "NLM_F_EXCL",
    "NLM_F_CREATE",
    "NLM_F_APPEND",
]

route_types = [
    "RTN_UNSPEC",
    "RTN_UNICAST",
    "RTN_LOCAL",
    "RTN_BROADCAST",
    "RTN_ANYCAST",
    "RTN_MULTICAST",
    "RTN_BLACKHOLE",
    "RTN_UNREACHABLE",
    "RTN_PROHIBIT",
    "RTN_THROW",
    "RTN_NAT",
    "RTN_XRESOLVE",
]

ifla_types = [
    "IFLA_UNSPEC",
    "IFLA_ADDRESS",
    "IFLA_BROADCAST",
    "IFLA_IFNAME",
    "IFLA_MTU",
    "IFLA_LINK",
    "IFLA_QDISC",
    "IFLA_STATS",
    "IFLA_COST",
    "IFLA_PRIORITY",
    "IFLA_MASTER",
    "IFLA_WIRELESS",
    "IFLA_PROTINFO",
    "IFLA_TXQLEN",
    "IFLA_MAP",
    "IFLA_WEIGHT",
    "IFLA_OPERSTATE",
    "IFLA_LINKMODE",
    "IFLA_LINKINFO",
    "IFLA_NET_NS_PID",
    "IFLA_IFALIAS",
    "IFLA_NUM_VF",
    "IFLA_VFINFO_LIST",
    "IFLA_STATS64",
    "IFLA_VF_PORTS",
    "IFLA_PORT_SELF",
    "IFLA_AF_SPEC",
    "IFLA_GROUP",
    "IFLA_NET_NS_FD",
    "IFLA_EXT_MASK",
    "IFLA_PROMISCUITY",
    "IFLA_NUM_TX_QUEUES",
    "IFLA_NUM_RX_QUEUES",
    "IFLA_CARRIER",
    "IFLA_PHYS_PORT_ID",
    "IFLA_CARRIER_CHANGES",
    "IFLA_PHYS_SWITCH_ID",
    "IFLA_LINK_NETNSID",
    "IFLA_PHYS_PORT_NAME",
    "IFLA_PROTO_DOWN",
]

if_flags = [
    "IFF_UP",
    "IFF_BROADCAST",
    "IFF_DEBUG",
    "IFF_LOOPBACK",
    "IFF_POINTOPOINT",
    "IFF_NOTRAILERS",
    "IFF_RUNNING",
    "IFF_NOARP",
    "IFF_PROMISC",
    "IFF_ALLMULTI",
    "IFF_MASTER",
    "IFF_SLAVE",
    "IFF_MULTICAST",
    "IFF_PORTSEL",
    "IFF_AUTOMEDIA",
    "IFF_DYNAMIC",
    "IFF_LOWER_UP",
    "IFF_DORMANT",
    "IFF_ECHO",
]

ifa_types = [
    "IFA_UNSPEC",
    "IFA_ADDRESS",
    "IFA_LOCAL",
    "IFA_LABEL",
    "IFA_BROADCAST",
    "IFA_ANYCAST",
    "IFA_CACHEINFO",
    "IFA_MULTICAST",
    "IFA_FLAGS",
    "IFA_RT_PRIORITY",
    "IFA_TARGET_NETNSID",
    "IFA_PROTO",
]

ifa_flags = [
    "IFA_F_SECONDARY",
    "IFA_F_NODAD",
    "IFA_F_OPTIMISTIC",
    "IFA_F_DADFAILED",
    "IFA_F_HOMEADDRESS",
    "IFA_F_DEPRECATED",
    "IFA_F_TENTATIVE",
    "IFA_F_PERMANENT",
    "IFA_F_MANAGETEMPADDR",
    "IFA_F_NOPREFIXROUTE",
    "IFA_F_MCAUTOJOIN",
    "IFA_F_STABLE_PRIVACY",
]


icmpv6_router_prefs = [
    "ICMPV6_ROUTER_PREF_LOW",
    "ICMPV6_ROUTER_PREF_MEDIUM",
    "ICMPV6_ROUTER_PREF_HIGH",
    "ICMPV6_ROUTER_PREF_INVALID",
]

gen_cmds = [
    "CTRL_CMD_UNSPEC",
    "CTRL_CMD_NEWFAMILY",
    "CTRL_CMD_DELFAMILY",
    "CTRL_CMD_GETFAMILY",
    "CTRL_CMD_NEWOPS",
    "CTRL_CMD_DELOPS",
    "CTRL_CMD_GETOPS",
    "CTRL_CMD_NEWMCAST_GRP",
    "CTRL_CMD_DELMCAST_GRP",
    "CTRL_CMD_GETMCAST_GRP",

]


@dataclass
class TypeSpec:
    name: str
    prefix: str
    constants: list[str]
    is_macro: bool = False
    flag: bool = False


constants = [
    TypeSpec("NLFamily", "NETLINK_", netlink_families, is_macro=True),
    TypeSpec("NLFlag", "NLM_F_", netlink_flags, is_macro=True, flag=True),
    TypeSpec("RTNType", "RTN_", route_types),
    TypeSpec("IFLAType", "IFLA_", ifla_types),
    TypeSpec("IFFlag", "IFF_", if_flags, flag=True),
    TypeSpec("IFAType", "IFA_", ifa_types),
    TypeSpec("IFAFlag", "IFA_F_", ifa_flags, flag=True),
    TypeSpec(
        "ICMPv6RouterPref",
        "ICMPV6_ROUTER_PREF_",
        icmpv6_router_prefs,
        flag=True,
    ),
    TypeSpec("CtrlCmd", "CTRL_CMD_", gen_cmds),
]


def generate_program(name: str = "gen_constants") -> Path:
    """
    Generate program that prints out linux user API constant names with their matching value.
    The generated program is subject to the license of these headers.

    Note that linux user API header files are subject to the Linux-syscall-note exception, such that a program
    can use the includes without it having to be subject to the GPL itself.
    See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/LICENSES/exceptions/Linux-syscall-note
    """
    program = (Path(__file__).parent.resolve() / name).with_suffix(".c")
    with open(program, "wt") as f:
        f.write("""\
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/icmpv6.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
""")
        for type_spec in constants:
            f.write(f"    // {type_spec.name}\n")
            for constant in type_spec.constants:
                if type_spec.is_macro:
                    f.write(f"#ifdef {constant}\n")
                f.write(
                    f'    printf("{type_spec.name} {constant} %d\\n", {constant});\n'
                )
                if type_spec.is_macro:
                    f.write("#endif\n")
            f.write("\n")
        f.write("    return 0;\n")
        f.write("}\n")
    return program


def compile_binary(program: Path) -> Path:
    binary = program.with_suffix("")
    subprocess.run(["gcc", str(program), "-o", str(binary)], check=True)
    return binary


def run_binary(binary: Path) -> dict[str, dict[str, int]]:
    """
    Run the generated binary and capture its output into a dictionary.

    Note that it is important that the generated binary be run as a standalone program to respect the licensing
    of the generated program using linux include headers.
    """
    p = subprocess.run([str(binary.absolute())], check=True, capture_output=True)
    assert p.stdout

    values: dict[str, dict[str, int]] = defaultdict(dict)
    for line in p.stdout.splitlines(keepends=False):
        match line.split():
            case family, name, value:
                values[family.decode("ascii")][name.decode("ascii")] = int(value)
            case _:
                raise Exception(f"Invalid output: {line!r}")
    return values


def main() -> None:
    program = generate_program()
    binary = compile_binary(program)
    constant_values = run_binary(binary)

    # Print values, here we could generate enum types directly!
    print("""\
from enum import IntEnum
from typing import Final

""")
    type_spec_by_name = {type_spec.name: type_spec for type_spec in constants}
    for name, values in constant_values.items():
        type_spec = type_spec_by_name[name]
        print(f"class {name}(IntEnum):")
        for constant_name, constant_value in values.items():
            if type_spec.flag:
                bit_shift = constant_value.bit_length() - 1
                if constant_value > 0 and constant_value == (1 << bit_shift):
                    # If the flag can be represented a bit shift do so
                    value_str = f"1 << {bit_shift}"
                else:
                    # Not a bit shift, could be a combination of other flags.
                    value_str = hex(constant_value)
            else:
                value_str = str(constant_value)
            print(
                f"    {constant_name.removeprefix(type_spec.prefix)}: Final = {value_str}"
            )
        print(f"""\

    @property
    def constant_name(self) -> str:
        return f"{type_spec.prefix}{{self.name}}"
""")
        print("\n")


if __name__ == "__main__":
    main()
