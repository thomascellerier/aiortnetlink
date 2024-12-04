import argparse
import sys

from aiortnetlink import NetlinkClient

__all__ = ["run"]

from aiortnetlink.route import parse_rt_tables


async def run() -> None:
    parser = argparse.ArgumentParser("aiortnetlink")
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
    route_show_parser.add_argument("DEV", default=None, nargs="?")
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

    args = parser.parse_args()

    async with NetlinkClient() as nl:
        match args:
            case argparse.Namespace(object="link" | "l", command="show" | "s", DEV=dev):
                ifi_index: int = 0
                ifi_name: str | None = None
                if dev is not None:
                    try:
                        ifi_index = int(dev)
                    except ValueError:
                        ifi_name = dev

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

            case argparse.Namespace(
                object="address" | "addr" | "a", command="show" | "s"
            ):
                from collections import defaultdict

                addrs_by_if_index = defaultdict(list)
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
                    table_id_to_name = parse_rt_tables()
                else:
                    table_id_to_name = {}

                if args.ipv4:
                    ip_versions: tuple[int, ...] = (4,)
                elif args.ipv6:
                    ip_versions = (6,)
                else:
                    ip_versions = (4, 6)

                async for route in nl.get_routes():
                    if table and table != route.table:
                        continue
                    if route.ip_version not in ip_versions:
                        continue
                    print(f"{table_id_to_name.get(route.table, route.table)}: {route=}")

            case _:
                assert False, ""
