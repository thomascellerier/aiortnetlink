import argparse
import sys

from aiortnetlink import NetlinkClient

__all__ = ["run", "main"]


async def run() -> None:
    parser = argparse.ArgumentParser("aiortnetlink")
    parser.add_argument(
        "--rcvbuf-size", type=int, help="Set netlink socket receive buffer size"
    )
    subparsers = parser.add_subparsers(title="object", dest="object", required=True)

    # link
    link_parser = subparsers.add_parser("link", aliases=["l"])
    link_subparsers = link_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # link show
    link_show_parser = link_subparsers.add_parser("show", aliases=["s"])
    link_show_parser.add_argument("DEV", default=None, nargs="?")

    # addr
    addr_parser = subparsers.add_parser("address", aliases=["addr", "a"])
    addr_subparsers = addr_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # addr show
    addr_show_parser = addr_subparsers.add_parser("show", aliases=["s"])
    addr_show_parser.add_argument("DEV", default=None, nargs="?")

    # route
    route_parser = subparsers.add_parser("route", aliases=["ro", "r"])
    route_subparsers = route_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # route show
    route_show_parser = route_subparsers.add_parser("show", aliases=["s"])
    route_show_parser.add_argument(
        "-t", "--table", help="routing table id", type=int, default=None
    )
    route_show_parser.add_argument(
        "-n",
        "--numeric",
        help="don't map table id to table name",
        action="store_true",
    )
    route_show_ip_version_group = route_show_parser.add_mutually_exclusive_group()
    route_show_ip_version_group.add_argument("-4", "--ipv4", action="store_true")
    route_show_ip_version_group.add_argument("-6", "--ipv6", action="store_true")

    # rule
    rule_parser = subparsers.add_parser("rule", aliases=["ru"])
    rule_subparsers = rule_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # rule show
    rule_show_parser = rule_subparsers.add_parser("show", aliases=["s"])
    rule_show_ip_version_group = rule_show_parser.add_mutually_exclusive_group()
    rule_show_ip_version_group.add_argument("-4", "--ipv4", action="store_true")
    rule_show_ip_version_group.add_argument("-6", "--ipv6", action="store_true")

    # watch
    watch_parser = subparsers.add_parser("watch", aliases=["w"])
    watch_parser.add_argument("-4", "--ipv4", action="store_true")
    watch_parser.add_argument("-6", "--ipv6", action="store_true")
    watch_parser.add_argument("-l", "--link", action="store_true", help="Watch links")
    watch_parser.add_argument(
        "-a", "--address", action="store_true", help="Watch addresses"
    )
    watch_parser.add_argument("-r", "--route", action="store_true", help="Watch routes")
    watch_parser.add_argument("--rule", action="store_true", help="Watch rules")

    args = parser.parse_args()

    match args:
        case argparse.Namespace(object="link" | "l", command="show" | "s", DEV=dev):
            ifi_index: int = 0
            ifi_name: str | None = None
            if dev is not None:
                try:
                    ifi_index = int(dev)
                except ValueError:
                    ifi_name = dev

            async with NetlinkClient(rcvbuf_size=args.rcvbuf_size) as nl:
                if ifi_index != 0:
                    link = await nl.get_link(ifi_index=ifi_index)
                    if link:
                        links = [link]
                    else:
                        print(f"Device with index {ifi_index} does not exist")
                        sys.exit(1)
                elif ifi_name is not None:
                    link = await nl.get_link(ifi_name=ifi_name)
                    if link:
                        links = [link]
                    else:
                        print(f"Device {ifi_name!r} does not exist")
                        sys.exit(1)
                else:
                    links = [link async for link in nl.get_links()]

            for link in links:
                print(f"{link.index}: {link.name}")

        case argparse.Namespace(object="address" | "addr" | "a", command="show" | "s"):
            from collections import defaultdict

            addrs_by_if_index = defaultdict(list)
            async with NetlinkClient(rcvbuf_size=args.rcvbuf_size) as nl:
                async for addr in nl.get_addrs():
                    addrs_by_if_index[addr.if_index].append(addr)

                link_by_if_index = {link.index: link async for link in nl.get_links()}

            for if_index in sorted(addrs_by_if_index):
                addrs = addrs_by_if_index[if_index]
                link = link_by_if_index[if_index]
                print(f"{if_index}: {link.name}")
                for addr in addrs:
                    print(
                        f"    {'inet' if addr.ip_version == 4 else 'inet6'} {addr.interface}"
                    )

        case argparse.Namespace(
            object="route" | "ro" | "r", command="show" | "s", table=table
        ):
            if not args.numeric:
                from aiortnetlink.route import parse_rt_tables

                table_id_to_name = parse_rt_tables()
            else:
                table_id_to_name = {}

            if args.ipv4:
                ip_versions: tuple[int, ...] = (4,)
            elif args.ipv6:
                ip_versions = (6,)
            else:
                ip_versions = (4, 6)

            async with NetlinkClient(rcvbuf_size=args.rcvbuf_size) as nl:
                async for route in nl.get_routes():
                    if table and table != route.table:
                        continue
                    if route.ip_version not in ip_versions:
                        continue
                    print(f"{table_id_to_name.get(route.table, route.table)}: {route=}")

        case argparse.Namespace(object="rule" | "ru", command="show" | "s"):
            if args.ipv4:
                ip_versions = (4,)
            elif args.ipv6:
                ip_versions = (6,)
            else:
                ip_versions = (4, 6)

            async with NetlinkClient(rcvbuf_size=args.rcvbuf_size) as nl:
                async for rule in nl.get_rules():
                    if rule.family > 127:
                        # Values up to 127 are reserved for real address
                        # families, values above 128 may be used arbitrarily.
                        continue
                    if rule.ip_version not in ip_versions:
                        continue
                    print(f"{rule=}")

        case argparse.Namespace(object="watch" | "w"):
            from aiortnetlink import rtm

            groups: set[int] = set()

            def link_groups() -> tuple[int, ...]:
                return (rtm.RTNLGRP_LINK,)

            if args.link:
                link_groups()

            def address_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (rtm.RTNLGRP_IPV4_IFADDR,)
                elif args.ipv6:
                    return (rtm.RTNLGRP_IPV6_IFADDR,)
                else:
                    return rtm.RTNLGRP_IPV4_IFADDR, rtm.RTNLGRP_IPV6_IFADDR

            if args.address:
                groups.update(address_groups())

            def route_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (rtm.RTNLGRP_IPV4_ROUTE,)
                elif args.ipv6:
                    return (rtm.RTNLGRP_IPV6_ROUTE,)
                else:
                    return rtm.RTNLGRP_IPV4_ROUTE, rtm.RTNLGRP_IPV6_ROUTE

            if args.route:
                groups.update(route_groups())

            def rule_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (rtm.RTNLGRP_IPV4_RULE,)
                elif args.ipv6:
                    return (rtm.RTNLGRP_IPV6_RULE,)
                else:
                    return rtm.RTNLGRP_IPV4_RULE, rtm.RTNLGRP_IPV6_RULE

            # No groups specified, listen to everything supported!
            if not groups:
                groups.update(
                    group
                    for type_groups in (
                        link_groups(),
                        address_groups(),
                        route_groups(),
                        rule_groups(),
                    )
                    for group in type_groups
                )

            async with NetlinkClient(groups=groups, rcvbuf_size=args.rcvbuf_size) as nl:
                while notification := await nl.recv_notification():
                    print(f"{notification=}")

        case _:
            assert False, ""


def main() -> None:
    import asyncio

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        sys.exit(1)
