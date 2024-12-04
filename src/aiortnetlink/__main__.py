import asyncio
import sys

from aiortnetlink import cli


async def main() -> None:
    await cli.run()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Interrupted by user.", file=sys.stderr)
    sys.exit(1)
