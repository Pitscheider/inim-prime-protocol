"""
Packet filtering with dot-notation expressions.

Supported fields:
  source              Packet source IP address
  destination         Packet destination IP address
  frame.size          Total frame size in bytes
  frame.operation     FrameOperation type: "read" or "command"
  frame.valid         OuterFrame validity: "true" or "false"
  frame.payload_size  Encrypted payload size in bytes

Supported operators:   =  !=  <  >  <=  >=  contains
Logical combiners:     AND  OR  (case-insensitive)
Negation:              NOT <expr>  or  !<expr>

Examples:
  source=192.168.1.1
  frame.size>100
  frame.operation=command
  source=192.168.1.1 AND frame.size>100
  frame.operation=read OR frame.operation=command
  NOT frame.valid=false
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from tools.packets import Packet
from inim.prime.native.const import FrameOperation


# ---------------------------------------------------------------------------
# Field resolvers
# ---------------------------------------------------------------------------

def _frame_size(packet: Packet) -> int:
    """Total wire size of the frame in bytes."""
    return packet.frame.length


def _frame_operation(packet: Packet) -> str:
    op = packet.frame.operation
    if op == FrameOperation.READ:
        return "read"
    if op == FrameOperation.COMMAND:
        return "command"
    return op.hex()


def _frame_valid(packet: Packet) -> str:
    return "true" if packet.frame.is_valid else "false"


def _frame_payload_size(packet: Packet) -> int:
    return packet.frame.encrypted_payload_length


_FIELD_RESOLVERS: dict[str, Callable[[Packet], int | str]] = {
    "source":             lambda p: p.source,
    "destination":        lambda p: p.destination,
    "frame.size":         _frame_size,
    "frame.operation":    _frame_operation,
    "frame.valid":        _frame_valid,
    "frame.payload_size": _frame_payload_size,
}

KNOWN_FIELDS = list(_FIELD_RESOLVERS.keys())


# ---------------------------------------------------------------------------
# Single expression
# ---------------------------------------------------------------------------

_OPERATORS = ["!=", "<=", ">=", "=", "<", ">", "contains"]
_OP_RE = re.compile(r"(!=|<=|>=|contains|=|<|>)")


@dataclass
class FilterExpression:
    field: str
    operator: str
    value: str

    @classmethod
    def parse(cls, text: str) -> "FilterExpression":
        text = text.strip()
        m = _OP_RE.search(text)
        if not m:
            raise ValueError(
                f"No operator found in expression: {text!r}\n"
                f"Supported operators: {', '.join(_OPERATORS)}"
            )
        field = text[: m.start()].strip().lower()
        operator = m.group(0)
        value = text[m.end() :].strip()

        if field not in _FIELD_RESOLVERS:
            raise ValueError(
                f"Unknown field: {field!r}\n"
                f"Known fields: {', '.join(KNOWN_FIELDS)}"
            )
        return cls(field=field, operator=operator, value=value)

    def matches(self, packet: Packet) -> bool:
        resolver = _FIELD_RESOLVERS[self.field]
        actual = resolver(packet)
        expected = self.value

        # Numeric comparisons when both sides look like numbers
        if isinstance(actual, int) or (isinstance(actual, str) and actual.isdigit()):
            try:
                a_int = int(actual)
                e_int = int(expected)
                if self.operator == "=":       return a_int == e_int
                if self.operator == "!=":      return a_int != e_int
                if self.operator == "<":       return a_int < e_int
                if self.operator == ">":       return a_int > e_int
                if self.operator == "<=":      return a_int <= e_int
                if self.operator == ">=":      return a_int >= e_int
                if self.operator == "contains":
                    return expected.lower() in str(actual).lower()
            except ValueError:
                pass  # fall through to string comparison

        # String comparisons
        a_str = str(actual).lower()
        e_str = expected.lower()
        if self.operator == "=":        return a_str == e_str
        if self.operator == "!=":       return a_str != e_str
        if self.operator == "contains": return e_str in a_str
        if self.operator in ("<", ">", "<=", ">="):
            raise ValueError(
                f"Operator {self.operator!r} is not valid for string field {self.field!r}"
            )
        return False

    def __str__(self) -> str:
        return f"{self.field} {self.operator} {self.value}"


# ---------------------------------------------------------------------------
# Composite filter (AND / OR chains, NOT prefix)
# ---------------------------------------------------------------------------

class PacketFilter:
    """
    Parses and evaluates a filter string against a list of packets.

    The grammar (simplified):
        filter  = term (("AND"|"OR") term)*
        term    = ["NOT"|"!"] expr
        expr    = FIELD OP VALUE
    """

    def __init__(self, filter_string: str):
        self._raw = filter_string.strip()
        self._tokens = self._tokenize(self._raw)
        self._predicate = self._parse_tokens(self._tokens)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def apply(self, packets: list[Packet]) -> list[Packet]:
        return [p for p in packets if self._predicate(p)]

    def __str__(self) -> str:
        return self._raw

    # ------------------------------------------------------------------
    # Tokeniser — splits on AND/OR boundaries, respects NOT/!
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Split a filter string into logical tokens (AND/OR/NOT/expressions)."""
        # Normalise AND / OR to uppercase
        text = re.sub(r"\bAND\b", "AND", text, flags=re.IGNORECASE)
        text = re.sub(r"\bOR\b",  "OR",  text, flags=re.IGNORECASE)
        text = re.sub(r"\bNOT\b", "NOT", text, flags=re.IGNORECASE)

        tokens: list[str] = []
        for part in re.split(r"\s+(AND|OR)\s+", text):
            tokens.append(part.strip())
        return tokens

    # ------------------------------------------------------------------
    # Parser — builds a single callable predicate
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tokens(tokens: list[str]) -> Callable[[Packet], bool]:
        """
        Tokens are the parts of the expression split on AND/OR.
        AND/OR connectors were re-inserted by the split as separate tokens.
        Build a chain of predicates accordingly.
        """
        # Reconstruct the expression list with connectors
        # re.split(r"\s+(AND|OR)\s+") captures the delimiter, so tokens
        # alternate: expr, AND/OR, expr, AND/OR, expr, ...
        predicates: list[Callable[[Packet], bool]] = []
        connectors: list[str] = []

        for i, token in enumerate(tokens):
            if token in ("AND", "OR"):
                connectors.append(token)
            else:
                predicates.append(PacketFilter._parse_term(token))

        def evaluate(packet: Packet) -> bool:
            result = predicates[0](packet)
            for connector, pred in zip(connectors, predicates[1:]):
                if connector == "AND":
                    result = result and pred(packet)
                else:
                    result = result or pred(packet)
            return result

        return evaluate

    @staticmethod
    def _parse_term(term: str) -> Callable[[Packet], bool]:
        """Parse a single term, stripping an optional NOT/! prefix."""
        negate = False
        t = term.strip()
        if t.upper().startswith("NOT "):
            negate = True
            t = t[4:].strip()
        elif t.startswith("!"):
            negate = True
            t = t[1:].strip()

        expr = FilterExpression.parse(t)
        if negate:
            return lambda p, e=expr: not e.matches(p)
        return expr.matches

    # ------------------------------------------------------------------
    # Help / field listing
    # ------------------------------------------------------------------

    @staticmethod
    def help() -> str:
        lines = [
            "Filter syntax:  <field> <op> <value>  [AND|OR ...]",
            "",
            "Fields:",
        ]
        descriptions = {
            "source":             "sender IP address",
            "destination":        "receiver IP address",
            "frame.size":         "total frame size in bytes  (numeric ops: < > <= >= = !=)",
            "frame.operation":    "operation type: read | command",
            "frame.valid":        "frame passes all validation: true | false",
            "frame.payload_size": "encrypted payload size in bytes  (numeric ops allowed)",
        }
        for field, desc in descriptions.items():
            lines.append(f"  {field:<22} {desc}")
        lines += [
            "",
            "Operators:  =  !=  <  >  <=  >=  contains",
            "Combiners:  AND  OR  (chain multiple expressions)",
            "Negation:   NOT <expr>  or  !<expr>",
            "",
        ]
        return "\n".join(lines)