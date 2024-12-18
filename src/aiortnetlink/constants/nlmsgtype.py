"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["NLMsgType"]


class NLMsgType(IntEnum):
    NOOP: Final = 1
    ERROR: Final = 2
    DONE: Final = 3
    OVERRUN: Final = 4
    MIN_TYPE: Final = 16

    @property
    def constant_name(self) -> str:
        return f"NLMSG_{self.name}"
