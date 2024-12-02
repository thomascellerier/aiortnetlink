import asyncio

from aiortnetlink import NetlinkClient

__all__ = []


async def main() -> None:
    import sys

    ifi_index: int = 0
    ifi_name: str | None = None
    match sys.argv:
        case [_, str(arg)]:
            try:
                ifi_index = int(arg)
            except ValueError:
                ifi_name = arg

    async with NetlinkClient() as nl:
        if ifi_index != 0:
            link = await nl.get_link(ifi_index=ifi_index, ifi_name=ifi_name)
            if link:
                links = [link]
            else:
                links = []
        else:
            links = [link async for link in nl.get_links()]
        for link in links:
            print(f"{link.index}: {link.name}")


asyncio.run(main())
