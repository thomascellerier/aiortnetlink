import argparse
import sys

from aiortnetlink import NetlinkClient
from aiortnetlink.netlink import NetlinkError

__all__ = ["run", "main"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("aiortnetlink")
    parser.add_argument(
        "--rcvbuf-size", type=int, help="Set netlink socket receive buffer size"
    )
    parser.add_argument(
        "-n",
        "--netns",
        help="Set network namespace",
        default=None,
    )
    subparsers = parser.add_subparsers(title="object", dest="object", required=True)

    # link
    link_parser = subparsers.add_parser("link", aliases=["l"])
    link_subparsers = link_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # link show
    link_show_parser = link_subparsers.add_parser("show", aliases=["s"])
    link_show_parser.add_argument(
        "-n",
        "--numeric",
        help="don't map group id to group name",
        action="store_true",
    )
    link_show_parser.add_argument("DEV", default=None, nargs="?")

    # addr
    addr_parser = subparsers.add_parser("address", aliases=["addr", "a"])
    addr_subparsers = addr_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    # addr show
    addr_show_parser = addr_subparsers.add_parser("show", aliases=["s"])
    addr_show_parser.add_argument("-4", "--ipv4", action="store_true")
    addr_show_parser.add_argument("-6", "--ipv6", action="store_true")
    addr_show_parser.add_argument(
        "-n",
        "--numeric",
        help="don't map id to name",
        action="store_true",
    )
    addr_show_parser.add_argument("DEV", default=None, nargs="?")

    # addr add
    addr_add_parser = addr_subparsers.add_parser("add", aliases=["a"])
    addr_add_parser.add_argument("ADDR", help="Address to add to the given device")
    addr_add_parser.add_argument("DEV", help="Device name or index")

    # addr del
    addr_del_parser = addr_subparsers.add_parser("del", aliases=["d"])
    addr_del_parser.add_argument("ADDR", help="Address to delete from the given device")
    addr_del_parser.add_argument("DEV", help="Device name or index")

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
    rule_show_parser.add_argument(
        "-n",
        "--numeric",
        help="don't map table id to table name",
        action="store_true",
    )
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

    # tuntap
    tuntap_parser = subparsers.add_parser("tuntap")
    tuntap_subparsers = tuntap_parser.add_subparsers(dest="command", required=True)

    # tuntap add
    tuntap_add_parser = tuntap_subparsers.add_parser("add")
    tuntap_add_parser.add_argument("NAME")
    tuntap_add_parser.add_argument("MODE", choices=("tun", "tap"))
    tuntap_add_parser.add_argument("--user")
    tuntap_add_parser.add_argument("--group")

    # tuntap del
    tuntap_del_parser = tuntap_subparsers.add_parser("del")
    tuntap_del_parser.add_argument("NAME")
    tuntap_del_parser.add_argument("MODE", choices=("tun", "tap"))

    # gen
    _ = subparsers.add_parser("gen")

    return parser.parse_args()


def _parse_dev(dev: str | None) -> tuple[int, str | None]:
    """
    Parse dev specifier to interface index and name tuple.
    """
    ifi_index = 0
    ifi_name: str | None = None
    if dev is not None:
        try:
            ifi_index = int(dev)
        except ValueError:
            ifi_name = dev
    return ifi_index, ifi_name


async def run(args: argparse.Namespace) -> None:
    client_args = dict(
        rcvbuf_size=args.rcvbuf_size,
        netns_name=args.netns,
    )
    match args:
        case argparse.Namespace(object="link" | "l", command="show" | "s", DEV=dev):
            ifi_index, ifi_name = _parse_dev(dev)

            async with NetlinkClient(**client_args) as nl:
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

            if not args.numeric:
                from aiortnetlink.rtfile import parse_rt_groups

                group_id_to_name = parse_rt_groups()
            else:
                group_id_to_name = {}

            for link in links:
                print(link.friendly_str(group_id_to_name=group_id_to_name.get))

        case argparse.Namespace(object="address" | "addr" | "a", command="show" | "s"):
            from collections import defaultdict

            addrs_by_if_index = defaultdict(list)
            async with NetlinkClient(**client_args) as nl:
                async for addr in nl.get_addrs():
                    addrs_by_if_index[addr.if_index].append(addr)

                link_by_if_index = {link.index: link async for link in nl.get_links()}

            if not args.numeric:
                from aiortnetlink.rtfile import parse_rt_scopes

                scope_id_to_name = parse_rt_scopes()
            else:
                scope_id_to_name = {}

            if args.ipv4:
                ip_versions: tuple[int, ...] = (4,)
            elif args.ipv6:
                ip_versions = (6,)
            else:
                ip_versions = (4, 6)

            for if_index in sorted(link_by_if_index):
                addrs = addrs_by_if_index[if_index]
                link = link_by_if_index[if_index]
                print(link.friendly_str(show_mode=False))
                for addr in addrs:
                    if addr.ip_version not in ip_versions:
                        continue
                    print(addr.friendly_str(scope_id_to_name=scope_id_to_name.get))

        case argparse.Namespace(
            object="address" | "addr" | "a", command="add" | "a", ADDR=addr, DEV=dev
        ):
            import ipaddress

            address = ipaddress.ip_interface(addr)
            ifi_index, ifi_name = _parse_dev(dev)

            async with NetlinkClient(**client_args) as nl:
                if ifi_name is not None:
                    link = await nl.get_link(ifi_name=ifi_name)
                    if link is None:
                        raise NetlinkError(f"No such device: {ifi_name}")
                    ifi_index = link.index
                await nl.add_addr(address, ifi_index=ifi_index)

        case argparse.Namespace(
            object="address" | "addr" | "a", command="del" | "d", ADDR=addr, DEV=dev
        ):
            import ipaddress

            address = ipaddress.ip_interface(addr)
            ifi_index, ifi_name = _parse_dev(dev)

            async with NetlinkClient(**client_args) as nl:
                if ifi_name is not None:
                    link = await nl.get_link(ifi_name=ifi_name)
                    if link is None:
                        raise NetlinkError(f"No such device: {ifi_name}")
                    ifi_index = link.index
                await nl.del_addr(address, ifi_index=ifi_index)

        case argparse.Namespace(
            object="route" | "ro" | "r", command="show" | "s", table=table
        ):
            if not args.numeric:
                from aiortnetlink.rtfile import (
                    parse_rt_protos,
                    parse_rt_scopes,
                    parse_rt_tables,
                )

                table_id_to_name = parse_rt_tables()
                proto_id_to_name = parse_rt_protos()
                scope_id_to_name = parse_rt_scopes()
            else:
                table_id_to_name = {}
                proto_id_to_name = {}
                scope_id_to_name = {}

            if args.ipv4:
                ip_versions = (4,)
            elif args.ipv6:
                ip_versions = (6,)
            else:
                ip_versions = (4, 6)

            async with NetlinkClient(**client_args) as nl:
                if args.numeric:
                    link_index_to_name = {
                        link.index: link.name async for link in nl.get_links()
                    }
                else:
                    link_index_to_name = {}

                async for route in nl.get_routes():
                    if table and table != route.table:
                        continue
                    if route.ip_version not in ip_versions:
                        continue
                    print(
                        route.friendly_str(
                            show_table=table is None,
                            table_id_to_name=table_id_to_name.get,
                            proto_id_to_name=proto_id_to_name.get,
                            scope_id_to_name=scope_id_to_name.get,
                            link_index_to_name=link_index_to_name.get,
                        )
                    )

        case argparse.Namespace(object="rule" | "ru", command="show" | "s"):
            if not args.numeric:
                from aiortnetlink.rtfile import parse_rt_tables

                table_id_to_name = parse_rt_tables()
            else:
                table_id_to_name = {}

            if args.ipv4:
                ip_versions = (4,)
            elif args.ipv6:
                ip_versions = (6,)
            else:
                ip_versions = (4, 6)

            async with NetlinkClient(**client_args) as nl:
                async for rule in nl.get_rules():
                    if rule.family > 127:
                        # Values up to 127 are reserved for real address
                        # families, values above 128 may be used arbitrarily.
                        continue
                    if rule.ip_version not in ip_versions:
                        continue
                    print(
                        rule.friendly_str(
                            table_id_to_name=table_id_to_name.get,
                        )
                    )

        case argparse.Namespace(object="watch" | "w"):
            from aiortnetlink.constants.rtnlgroup import RTNLGroup

            groups: set[int] = set()

            def link_groups() -> tuple[int, ...]:
                return (RTNLGroup.LINK,)

            if args.link:
                link_groups()

            def address_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (RTNLGroup.IPV4_IFADDR,)
                elif args.ipv6:
                    return (RTNLGroup.IPV6_IFADDR,)
                else:
                    return RTNLGroup.IPV4_IFADDR, RTNLGroup.IPV6_IFADDR

            if args.address:
                groups.update(address_groups())

            def route_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (RTNLGroup.IPV4_ROUTE,)
                elif args.ipv6:
                    return (RTNLGroup.IPV6_ROUTE,)
                else:
                    return RTNLGroup.IPV4_ROUTE, RTNLGroup.IPV6_ROUTE

            if args.route:
                groups.update(route_groups())

            def rule_groups() -> tuple[int, ...]:
                if args.ipv4:
                    return (RTNLGroup.IPV4_RULE,)
                elif args.ipv6:
                    return (RTNLGroup.IPV6_RULE,)
                else:
                    return RTNLGroup.IPV4_RULE, RTNLGroup.IPV6_RULE

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

            async with NetlinkClient(groups=groups, **client_args) as nl:
                while notification := await nl.recv_notification():
                    print(f"{notification=}")

        case argparse.Namespace(object="tuntap", command="add", user=user, group=group):
            uid: int | None
            match user:
                case str():
                    try:
                        uid = int(user)
                    except ValueError:
                        import pwd

                        uid = pwd.getpwnam(user).pw_uid
                case _:
                    uid = None

            gid: int | None
            match group:
                case str():
                    try:
                        gid = int(group)
                    except ValueError:
                        import grp

                        gid = grp.getgrnam(group).gr_gid
                case _:
                    gid = None

            from aiortnetlink.tuntap import create_tuntap

            create_tuntap(args.NAME, args.MODE, uid=uid, gid=gid)

        case argparse.Namespace(object="tuntap", command="del"):
            from aiortnetlink.tuntap import delete_tuntap

            delete_tuntap(args.NAME, args.MODE)

        case argparse.Namespace(object="gen"):
            async with NetlinkClient(**client_args) as nl:
                await nl.get_family("nlctrl")

        case _:
            assert False, f"Invalid command: {args}"


def main() -> None:
    args = parse_args()

    import asyncio

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        sys.exit(1)
