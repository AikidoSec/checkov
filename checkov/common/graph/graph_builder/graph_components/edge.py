from typing import Any, Dict


class Edge:
    # _str is the formatted form used by __eq__/__hash__. It is built once per label assignment,
    # instead of on every comparison, because graph building hashes edges constantly. The value is
    # kept byte for byte identical to the old f-string, since edges live in sets and their hashes
    # decide the order variable rendering visits them in.
    __slots__ = ("dest", "origin", "_label", "_str")

    def __init__(self, origin: int, dest: int, label: str) -> None:
        self.origin = origin
        self.dest = dest
        self._label = label
        self._str = f"[{origin} -({label})-> {dest}]"

    @property
    def label(self) -> str:
        return self._label

    @label.setter
    def label(self, value: str) -> None:
        self._label = value
        self._str = f"[{self.origin} -({value})-> {self.dest}]"

    def __str__(self) -> str:
        return self._str

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Edge) and self._str == other._str

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._str)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'origin': self.origin,
            'dest': self.dest,
            'label': self.label
        }
