"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["NLFlag"]


class NLFlag(IntEnum):
    REQUEST = 1 << 0
    MULTI = 1 << 1
    ACK = 1 << 2
    ECHO = 1 << 3
    DUMP_INTR = 1 << 4
    DUMP_FILTERED = 1 << 5
    ROOT = 1 << 8
    MATCH = 1 << 9
    ATOMIC = 1 << 10
    DUMP = 0x300
    REPLACE = 1 << 8
    EXCL = 1 << 9
    CREATE = 1 << 10
    APPEND = 1 << 11

    @property
    def constant_name(self) -> str:
        return f"NLM_F_{self.name}"
