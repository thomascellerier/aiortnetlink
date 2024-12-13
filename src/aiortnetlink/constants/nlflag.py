# This file was generated by gen_constants.py
from enum import IntEnum
from typing import Final

__all__ = ["NLFlag"]


class NLFlag(IntEnum):
    REQUEST: Final = 1 << 0
    MULTI: Final = 1 << 1
    ACK: Final = 1 << 2
    ECHO: Final = 1 << 3
    DUMP_INTR: Final = 1 << 4
    DUMP_FILTERED: Final = 1 << 5
    ROOT: Final = 1 << 8
    MATCH: Final = 1 << 9
    ATOMIC: Final = 1 << 10
    DUMP: Final = 0x300
    REPLACE: Final = 1 << 8
    EXCL: Final = 1 << 9
    CREATE: Final = 1 << 10
    APPEND: Final = 1 << 11

    @property
    def constant_name(self) -> str:
        return f"NLM_F_{self.name}"
