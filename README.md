# aiortnetlink

Pure-python asyncio rtnetlink client.

See https://docs.kernel.org/userspace-api/netlink/intro.html

Example:
```Python
from aiortnetlink import NetlinkClient

async with NetlinkClient() as nl:
    async for link in nl.get_links():
        print(f"{link.index}: {link.name}")
```

## Table of contents

- [Supported features](#supported-features)
- [Development](#development)

## Supported features

### Links
- `get_links`

### Addresses
- TODO

### Routes
- TODO

### Rules
- TODO

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
