#!/usr/bin/env python3
"""
Generate python enums from C constants.
"""

import argparse
import io
import subprocess
import textwrap
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
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

netlink_msg_types = [
    "NLMSG_NOOP",
    "NLMSG_ERROR",
    "NLMSG_DONE",
    "NLMSG_OVERRUN",
    "NLMSG_MIN_TYPE",
]

netlink_flags = [
    "NLM_F_REQUEST",
    "NLM_F_MULTI",
    "NLM_F_ACK",
    "NLM_F_ECHO",
    "NLM_F_DUMP_INTR",
    "NLM_F_DUMP_FILTERED",
    "NLM_F_ROOT",
    "NLM_F_MATCH",
    "NLM_F_ATOMIC",
    "NLM_F_DUMP",
    "NLM_F_REPLACE",
    "NLM_F_EXCL",
    "NLM_F_CREATE",
    "NLM_F_APPEND",
]

rtm_types = [
    "RTM_NEWLINK",
    "RTM_DELLINK",
    "RTM_GETLINK",
    "RTM_SETLINK",
    "RTM_NEWADDR",
    "RTM_DELADDR",
    "RTM_GETADDR",
    "RTM_NEWROUTE",
    "RTM_DELROUTE",
    "RTM_GETROUTE",
    "RTM_NEWNEIGH",
    "RTM_DELNEIGH",
    "RTM_GETNEIGH",
    "RTM_NEWRULE",
    "RTM_DELRULE",
    "RTM_GETRULE",
    "RTM_NEWQDISC",
    "RTM_DELQDISC",
    "RTM_GETQDISC",
    "RTM_NEWTCLASS",
    "RTM_DELTCLASS",
    "RTM_GETTCLASS",
    "RTM_NEWTFILTER",
    "RTM_DELTFILTER",
    "RTM_GETTFILTER",
    "RTM_NEWACTION",
    "RTM_DELACTION",
    "RTM_GETACTION",
    "RTM_NEWPREFIX",
    "RTM_GETMULTICAST",
    "RTM_GETANYCAST",
    "RTM_NEWNEIGHTBL",
    "RTM_GETNEIGHTBL",
    "RTM_SETNEIGHTBL",
    "RTM_NEWNDUSEROPT",
    "RTM_NEWADDRLABEL",
    "RTM_DELADDRLABEL",
    "RTM_GETADDRLABEL",
    "RTM_GETDCB",
    "RTM_SETDCB",
]

rtnl_groups = [
    "RTNLGRP_NONE",
    "RTNLGRP_LINK",
    "RTNLGRP_NOTIFY",
    "RTNLGRP_NEIGH",
    "RTNLGRP_TC",
    "RTNLGRP_IPV4_IFADDR",
    "RTNLGRP_IPV4_MROUTE",
    "RTNLGRP_IPV4_ROUTE",
    "RTNLGRP_IPV4_RULE",
    "RTNLGRP_IPV6_IFADDR",
    "RTNLGRP_IPV6_MROUTE",
    "RTNLGRP_IPV6_ROUTE",
    "RTNLGRP_IPV6_IFINFO",
    "RTNLGRP_DECnet_IFADDR",
    "RTNLGRP_NOP2",
    "RTNLGRP_DECnet_ROUTE",
    "RTNLGRP_DECnet_RULE",
    "RTNLGRP_NOP4",
    "RTNLGRP_IPV6_PREFIX",
    "RTNLGRP_IPV6_RULE",
    "RTNLGRP_ND_USEROPT",
    "RTNLGRP_PHONET_IFADDR",
    "RTNLGRP_PHONET_ROUTE",
]

rtnl_family = [
    "RTNL_FAMILY_IPMR",
    "RTNL_FAMILY_IP6MR",
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


rta_types = [
    "RTA_UNSPEC",
    "RTA_DST",
    "RTA_SRC",
    "RTA_IIF",
    "RTA_OIF",
    "RTA_GATEWAY",
    "RTA_PRIORITY",
    "RTA_PREFSRC",
    "RTA_METRICS",
    "RTA_MULTIPATH",
    "RTA_PROTOINFO",
    "RTA_FLOW",
    "RTA_CACHEINFO",
    "RTA_SESSION",
    "RTA_MP_ALGO",
    "RTA_TABLE",
    "RTA_MARK",
    "RTA_MFC_STATS",
    "RTA_VIA",
    "RTA_NEWDST",
    "RTA_PREF",
    "RTA_ENCAP_TYPE",
    "RTA_ENCAP",
    "RTA_EXPIRES",
    "RTA_PAD",
    "RTA_UID",
    "RTA_TTL_PROPAGATE",
    "RTA_IP_PROTO",
    "RTA_SPORT",
    "RTA_DPORT",
    "RTA_NH_ID",
]

arphrd_types = [
    "ARPHRD_ETHER",
    "ARPHRD_NONE",
    "ARPHRD_LOOPBACK",
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

if_oper_states = [
    "IF_OPER_UNKNOWN",
    "IF_OPER_NOTPRESENT",
    "IF_OPER_DOWN",
    "IF_OPER_LOWERLAYERDOWN",
    "IF_OPER_TESTING",
    "IF_OPER_DORMANT",
    "IF_OPER_UP",
]

if_link_modes = [
    "IF_LINK_MODE_DEFAULT",
    "IF_LINK_MODE_DORMANT",
    "IF_LINK_MODE_TESTING",
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

fra_types = [
    "FRA_UNSPEC",
    "FRA_DST",
    "FRA_SRC",
    "FRA_IIFNAME",
    "FRA_GOTO",
    "FRA_UNUSED2",
    "FRA_PRIORITY",
    "FRA_UNUSED3",
    "FRA_UNUSED4",
    "FRA_UNUSED5",
    "FRA_FWMARK",
    "FRA_FLOW",
    "FRA_TUN_ID",
    "FRA_SUPPRESS_IFGROUP",
    "FRA_SUPPRESS_PREFIXLEN",
    "FRA_TABLE",
    "FRA_FWMASK",
    "FRA_OIFNAME",
    "FRA_PAD",
    "FRA_L3MDEV",
    "FRA_UID_RANGE",
    "FRA_PROTOCOL",
    "FRA_IP_PROTO",
    "FRA_SPORT_RANGE",
    "FRA_DPORT_RANGE",
    # TODO: Truncate list based on value of FRA_MAX
    # "FRA_DSCP",
]


ctrl_cmds = [
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


ctrl_attrs = [
    "CTRL_ATTR_UNSPEC",
    "CTRL_ATTR_FAMILY_ID",
    "CTRL_ATTR_FAMILY_NAME",
    "CTRL_ATTR_VERSION",
    "CTRL_ATTR_HDRSIZE",
    "CTRL_ATTR_MAXATTR",
    "CTRL_ATTR_OPS",
    "CTRL_ATTR_MCAST_GROUPS",
]

tun_ioctls = [
    "TUNSETNOCSUM",
    "TUNSETDEBUG",
    "TUNSETIFF",
    "TUNSETPERSIST",
    "TUNSETOWNER",
    "TUNSETLINK",
    "TUNSETGROUP",
    "TUNGETFEATURES",
    "TUNSETOFFLOAD",
    "TUNSETTXFILTER",
    "TUNGETIFF",
    "TUNGETSNDBUF",
    "TUNSETSNDBUF",
    "TUNATTACHFILTER",
    "TUNDETACHFILTER",
    "TUNGETVNETHDRSZ",
    "TUNSETVNETHDRSZ",
    "TUNSETVNETBE",
    "TUNGETVNETBE",
    "TUNSETSTEERINGEBPF",
    "TUNSETFILTEREBPF",
    "TUNSETCARRIER",
    "TUNGETDEVNETNS",
]

tun_iff_flags = [
    "IFF_TUN",
    "IFF_TAP",
    "IFF_NO_PI",
    "IFF_ONE_QUEUE",
    "IFF_VNET_HDR",
    "IFF_TUN_EXCL",
]

# Misc constants, not an actual enum
misc_constants = [
    "IFNAMSIZ",
]


@dataclass
class TypeSpec:
    name: str
    prefix: str
    constants: list[str]
    is_macro: bool = False
    flag: bool = False
    hex: bool = False
    includes: list[str] = field(default_factory=list)
    printf_specifier: Callable[[str], str] = lambda _: "%d"

    def __post_init__(self) -> None:
        for constant in self.constants:
            if not constant.startswith(self.prefix):
                raise ValueError(
                    f"Invalid constant {constant} to type spec {self.name}, "
                    f"constant does not start with prefix {self.prefix}"
                )


constants = [
    TypeSpec(
        "NLFamily",
        "NETLINK_",
        netlink_families,
        is_macro=True,
        includes=["<linux/netlink.h>"],
    ),
    TypeSpec(
        "NLMsgType",
        "NLMSG_",
        netlink_msg_types,
        is_macro=True,
        includes=["<linux/netlink.h>"],
    ),
    TypeSpec(
        "NLFlag",
        "NLM_F_",
        netlink_flags,
        is_macro=True,
        flag=True,
        includes=["<linux/netlink.h>"],
    ),
    TypeSpec(
        "RTNLFamily", "RTNL_FAMILY_", rtnl_family, includes=["<linux/rtnetlink.h>"]
    ),
    TypeSpec("RTMType", "RTM_", rtm_types, includes=["<linux/rtnetlink.h>"]),
    TypeSpec("RTNLGroup", "RTNLGRP_", rtnl_groups, includes=["<linux/rtnetlink.h>"]),
    TypeSpec("RTNType", "RTN_", route_types, includes=["<linux/rtnetlink.h>"]),
    TypeSpec("RTAType", "RTA_", rta_types, includes=["<linux/rtnetlink.h>"]),
    TypeSpec("ARPHRDType", "ARPHRD_", arphrd_types, includes=["<linux/if_arp.h>"]),
    TypeSpec("IFLAType", "IFLA_", ifla_types, includes=["<linux/if.h>"]),
    TypeSpec("IFFlag", "IFF_", if_flags, flag=True, includes=["<linux/if.h>"]),
    TypeSpec(
        "IFOper", "IF_OPER_", if_oper_states, flag=True, includes=["<linux/if.h>"]
    ),
    TypeSpec(
        "IFLinkMode",
        "IF_LINK_MODE_",
        if_link_modes,
        flag=True,
        includes=["<linux/if.h>"],
    ),
    TypeSpec("IFAType", "IFA_", ifa_types, includes=["<linux/if.h>"]),
    TypeSpec("IFAFlag", "IFA_F_", ifa_flags, flag=True, includes=["<linux/if.h>"]),
    TypeSpec(
        "ICMPv6RouterPref",
        "ICMPV6_ROUTER_PREF_",
        icmpv6_router_prefs,
        includes=["<linux/icmpv6.h>"],
    ),
    TypeSpec("FRAType", "FRA_", fra_types, includes=["<linux/fib_rules.h>"]),
    TypeSpec("CtrlCmd", "CTRL_CMD_", ctrl_cmds, includes=["<linux/genetlink.h>"]),
    TypeSpec("CtrlAttr", "CTRL_ATTR_", ctrl_attrs, includes=["<linux/genetlink.h>"]),
    TypeSpec(
        "TunIoctl",
        "TUN",
        tun_ioctls,
        hex=True,
        # TODO: Is there a better way to do this?
        # Is it possible to find the printf specifier based on the type using a C macro?
        printf_specifier=lambda name: "%u" if name == "TUNGETDEVNETNS" else "%ld",
        includes=["<sys/ioctl.h>", "<linux/if_tun.h>"],
    ),
    TypeSpec(
        "TunIffFlag",
        "IFF_",
        tun_iff_flags,
        flag=True,
        includes=["<linux/if_tun.h>"],
    ),
    TypeSpec(
        "MiscConstants",
        "",
        misc_constants,
        includes=["<linux/if.h>"],
    ),
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
        includes = {
            "<stdio.h>",
        }
        includes |= {include for ts in constants for include in ts.includes}
        for include in sorted(includes):
            f.write(f"#include {include}\n")
        # TODO: Should each typespec define it's includes?
        f.write("""\

int main(int argc, char *argv[]) {
""")
        for type_spec in constants:
            f.write(f"    // {type_spec.name}\n")
            for constant in type_spec.constants:
                if type_spec.is_macro:
                    f.write(f"#ifdef {constant}\n")
                f.write(
                    f'    printf("{type_spec.name} {constant} {type_spec.printf_specifier(constant)}\\n", {constant});\n'
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
    assert p.stdout is not None

    values: dict[str, dict[str, int]] = defaultdict(dict)
    for line in p.stdout.splitlines(keepends=False):
        match line.split():
            case family, name, value:
                values[family.decode("ascii")][name.decode("ascii")] = int(value)
            case _:
                raise Exception(f"Invalid output: {line!r}")
    return values


def _hex(value: int) -> str:
    """
    Format hex the same way that ruff format would.
    """
    value_str = hex(value)
    return f"0x{value_str[2:].upper()}"


def print_result(
    constant_values: dict[str, dict[str, int]],
    filter_fn: Callable[[TypeSpec], bool],
    output_dir: Path,
    dry_run: bool,
) -> None:
    """
    Print values as python source code representing IntEnum types
    """
    type_spec_by_name = {type_spec.name: type_spec for type_spec in constants}
    for name, values in constant_values.items():
        type_spec = type_spec_by_name[name]
        if not filter_fn(type_spec):
            continue

        f = io.StringIO()
        print(
            textwrap.dedent(f"""\
            \"\"\"
            This file was generated by {Path(__file__).name}
            \"\"\"

            from enum import IntEnum
            from typing import Final
    
            __all__ = ["{name}"]
    

            class {name}(IntEnum):"""),
            file=f,
        )
        for constant_name, constant_value in values.items():
            if type_spec.flag:
                bit_shift = constant_value.bit_length() - 1
                if constant_value > 0 and constant_value == (1 << bit_shift):
                    # If the flag can be represented a bit shift do so
                    value_str = f"1 << {bit_shift}"
                else:
                    # Not a bit shift, could be a combination of other flags.
                    value_str = _hex(constant_value)
            elif type_spec.hex:
                value_str = _hex(constant_value)
            else:
                value_str = str(constant_value)
            print(
                f"    {constant_name.removeprefix(type_spec.prefix)}: Final = {value_str}",
                file=f,
            )
        print(
            textwrap.indent(
                textwrap.dedent(
                    f"""\

                    @property
                    def constant_name(self) -> str:
                        return f"{type_spec.prefix}{{self.name}}"
                """
                ),
                prefix=" " * 4,
            ),
            file=f,
            end="",
        )

        file_name = f"{type_spec.name.lower()}.py"
        if dry_run:
            print(f"\n\n# -- Dry run! File would have been written to {file_name} --")
            print(f.getvalue().rstrip())
        else:
            file_path = output_dir / file_name
            print(f"Wrote {name} to {file_path.relative_to(Path.cwd())}")
            file_path.write_text(f.getvalue())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--type-name",
        default=None,
        help="Type name to match, supports glob patterns",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=str(
            (
                Path(__file__).parent.parent / "src" / "aiortnetlink" / "constants"
            ).resolve()
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Output to stdout but do not write to file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    dry_run: bool = args.dry_run

    if type_name := args.type_name:
        import fnmatch

        filter_fn = lambda ts: fnmatch.fnmatch(ts.name, type_name)
    else:
        filter_fn = lambda _: True

    program = generate_program()
    binary = compile_binary(program)
    constant_values = run_binary(binary)
    print_result(constant_values, filter_fn, output_dir, dry_run)


if __name__ == "__main__":
    main()
