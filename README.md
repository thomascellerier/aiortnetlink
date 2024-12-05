# aiortnetlink

Pure-python asyncio rtnetlink client.

See https://docs.kernel.org/userspace-api/netlink/intro.html

## Getting started

Install:
```
pip install aiortnetlink
```

Or, adding to your uv project:
```
uv add aiortnetlink
```

Example:
```Python
from aiortnetlink import NetlinkClient

async with NetlinkClient() as nl:
    async for link in nl.get_links():
        print(f"{link.index}: {link.name}")
```

The module ships with a CLI, for example if running from the repository root:
```
uv run --directory src python -m aiortnetlink addr show
```

## Supported features

### Links
- `get_links`: List all links.
- `get_link`: Lookup link by index or name.

### Addresses
- `get_links`: List all addresses.

### Routes
- `get_routes`: List all routes.

### Rules
- `get_rules`: List all rules.

### Notifications
- `recv_notification`: Receive netlink notification. Notification subscription is done by passing the revelant rtnetlink groups to the netlink client.

## Development

This project uses [uv](https://docs.astral.sh/uv/) for project management and [poe the poet](https://poethepoet.natn.io) to run development tasks.
Linting and code formatting is done using [ruff](https://docs.astral.sh/ruff/), type checking using [mypy](https://mypy.readthedocs.io/en/stable/)
and tests using [pytest](https://docs.pytest.org/en/stable/).

For example to run all checks locally:
```bash
uvx --from poethepoet poe lint
```

To format code using ruff:
```bash
uvx --from poethepoet poe fmt
```
