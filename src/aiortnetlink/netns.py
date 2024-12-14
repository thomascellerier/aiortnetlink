import contextlib
import os
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "proc_netns_path",
    "proc_netns_id",
    "named_netns_path",
    "named_netns_id",
    "named_netns_context",
]


def proc_netns_path(pid: int | None = None) -> Path:
    return Path("/proc", str(pid or os.getpid()), "ns", "net")


def named_netns_path(name: str) -> Path:
    return Path("/run/netns", name)


def proc_netns_id(pid: int | None = None) -> int:
    stat = proc_netns_path(pid).stat(follow_symlinks=True)
    return stat.st_ino


def named_netns_id(netns_name: str) -> int:
    stat = named_netns_path(netns_name).stat()
    return stat.st_ino


@contextlib.contextmanager
def named_netns_context(netns_name: str) -> Iterator[tuple[int, int]]:
    host_netns_fd = os.open(proc_netns_path(), os.O_RDONLY)
    host_netns_id = os.stat(host_netns_fd).st_ino
    try:
        guest_netns_fd = os.open(named_netns_path(netns_name), os.O_RDONLY)
        guest_netns_id = os.stat(guest_netns_fd).st_ino
        os.setns(guest_netns_fd, os.CLONE_NEWNET)
        os.close(guest_netns_fd)

        yield host_netns_id, guest_netns_id
    finally:
        os.setns(host_netns_fd, os.CLONE_NEWNET)
        os.close(host_netns_fd)


def example() -> None:
    import subprocess

    with named_netns_context("foo") as (host_netns_id, guest_netns_id):
        print(f"Running in guest netns {guest_netns_id}")
        subprocess.run(["ip", "link", "show"])

    print(f"Running in host netns {host_netns_id}")
    subprocess.run(["ip", "link", "show"])


if __name__ == "__main__":
    example()
