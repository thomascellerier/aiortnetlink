import os

__all__ = ["parse_rt_mapping"]


def parse_rt_mapping(path: str | os.PathLike[str]) -> dict[int, str]:
    """
    Parse rt int to str mapping file.
    """
    entry_id_to_name = {}
    with open(path, "rb") as f:
        for lineno, line in enumerate(f, start=1):
            if line.startswith(b"#"):
                continue
            match line.split():
                case entry_id_bytes, entry_name_bytes:
                    try:
                        entry_id = int(entry_id_bytes)
                    except ValueError:
                        raise ValueError(
                            f"Invalid entry id to name mapping at line {lineno} in {path}, "
                            f"id should be an integer but got {entry_id_bytes!r}"
                        ) from None
                    try:
                        entry_name = entry_name_bytes.decode("ascii")
                    except ValueError:
                        raise ValueError(
                            f"Invalid table id to name mapping at line {lineno} in {path}, "
                            f"table name should be an ascii string but got {entry_name_bytes!r}"
                        ) from None
                    entry_id_to_name[entry_id] = entry_name
                case _:
                    raise ValueError(
                        f"Invalid table id to name mapping at line {lineno} in {path}, "
                        "line should have two parts separated by whitespace, entry id and name, "
                        f"but got {line.rstrip()!r}"
                    )
    return entry_id_to_name
