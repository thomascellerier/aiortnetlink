import asyncio

from aiortnetlink import cli


async def main() -> None:
    await cli.run()


asyncio.run(main())
