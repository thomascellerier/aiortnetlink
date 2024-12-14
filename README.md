# aiortnetlink

Pure-python asyncio [rtnetlink](https://docs.kernel.org/userspace-api/netlink/intro.html) client.

## Getting started

Install from [PyPI](https://pypi.org/project/aiortnetlink/):
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
uv run aiortnetlink addr show
```

## Supported features

### Links
- `get_links`: List all links.
- `get_link`: Lookup link by index or name.

### Addresses
- `get_links`: List all addresses.
- `add_addr`: Add IP address to link.
- `del_addr`: Remove IP address from link.

### Routes
- `get_routes`: List all routes.
- `get_route`: Get route for the given address.

### Rules
- `get_rules`: List all rules.

### Notifications
- `recv_notification`: Receive netlink notification. Notification subscription is done by passing the revelant rtnetlink groups to the netlink client.

### Tun/Tap
- `create_tuntap`: Create tun or tap device.
- `delete_tuntap`: Delete tun or tap device.

### Network namespaces

All network operations can be performed in a network namesapce by passing the `netns_name` argument to the `NetlinkClient`.

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

## Constants generator

Linux user API constants are exposed to C programs as symbols.
In order to extract their values for use in a pure-Python module without violating the [license](https://spdx.org/licenses/Linux-syscall-note.html) we
need to write a C program that will import the appropriate linux uapi headers and print their values.

To facilitate development of this library we generate a C program and use its output to generate python source code representing the various constants.
The constants are grouped into types using [IntEnum](https://docs.python.org/3/library/enum.html#enum.IntEnum).

This is handled by the [constants generator](tools/gen_constants.py).
The files in the [constants](src/aiortnetlink/constants) directory and generated in this way and should not be edited manually.
