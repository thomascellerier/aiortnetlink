"""
This file was generated by gen_constants.py
"""

from enum import IntEnum

__all__ = ["MiscConstants"]


class MiscConstants(IntEnum):
    IFNAMSIZ = 16

    @property
    def constant_name(self) -> str:
        return f"{self.name}"
