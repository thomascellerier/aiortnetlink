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


@dataclass
class TypeSpec:
    name: str
    constants: list[str]
    is_macro: bool = False


constants = [
    TypeSpec("NLFamily", netlink_families, is_macro=True),
    TypeSpec("NLFlag", netlink_flags, is_macro=True),
    TypeSpec("RTNType", route_types, False),
]


def generate_program(name: str = "gen_constants") -> Path:
    program = (Path(__file__).parent.resolve() / name).with_suffix(".c")
    with open(program, "wt") as f:
        f.write("""\
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
""")
        for type_spec in constants:
            for constant in type_spec.constants:
                if type_spec.is_macro:
                    f.write(f"#ifdef {constant}\n")
                f.write(
                    f'    printf("{type_spec.name} {constant} %d\\n", {constant});\n'
                )
                if type_spec.is_macro:
                    f.write("#endif\n")
        f.write("}\n")
    return program


def compile_binary(program: Path) -> Path:
    binary = program.with_suffix("")
    subprocess.run(["gcc", str(program), "-o", str(binary)], check=True)
    return binary


def run_binary(binary: Path) -> dict[str, dict[str, int]]:
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
    for family, values in constant_values.items():
        print(f"class {family}(IntEnum):")
        for name, value in values.items():
            print(f"    {name}: Final = {value}")
        print("\n")


if __name__ == "__main__":
    main()
