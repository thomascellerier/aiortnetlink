import argparse
import sys

from aiortnetlink import NetlinkClient

__all__ = ["run"]


async def run() -> None:
    parser = argparse.ArgumentParser("aiortnetlink")
    subparsers = parser.add_subparsers(title="object", dest="object", required=True)

    link_parser = subparsers.add_parser("link")
    link_subparsers = link_parser.add_subparsers(
        title="command", dest="command", required=True
    )

    link_show_parser = link_subparsers.add_parser("show")
    link_show_parser.add_argument("DEV", default=None, nargs="?")

    args = parser.parse_args()

    async with NetlinkClient() as nl:
        match args:
            case argparse.Namespace(object="link", command="show", DEV=dev):
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

            case _:
                assert False, ""
