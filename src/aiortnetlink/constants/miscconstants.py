"""
This file was generated by gen_constants.py
"""

from enum import IntEnum
from typing import Final

__all__ = ["MiscConstants"]


class MiscConstants(IntEnum):
    IFNAMSIZ: Final = 16

    @property
    def constant_name(self) -> str:
        return f"{self.name}"
