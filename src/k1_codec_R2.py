"""Bishop K1 byte-format codec — SOURCE-ONLY CANDIDATE, NOT TESTED.

Specification: Integrated_Protected_Write_v0.3_Candidate.md plus
Integrated_Protected_Write_v0.4.3_Amendment_and_Appendix_Candidate.md,
section 3.1 (K1). The receiving application MUST separately enforce the
closed object schemas, allowed field types and domain values.

This module does not frame packets, verify Ed25519 signatures, decide authority,
write protected targets, or execute any Bishop runtime operation. An iterative
JSON parser and renderer avoid Python's nesting-dependent RecursionError for
well-formed data; application schemas must reject forbidden container shapes.
No claim of interoperability, correctness or test PASS is made by this source file.

Important boundary: K1 has no defined canonical FLOAT representation. A
received syntactically valid JSON floating-point token is retained lexically as
an opaque _ReceivedDecimal for downstream schema rejection; retaining the
lexeme is NOT proof of canonical decimal representation. It must not be used
as an admitted value or in a trusted digest. Reject such tokens under the
applicable application schema (not solely as a byte-encoding failure because
of type). No binary float is generated or decoded. A schema permitting floats
would require additional explicit rules; this module does not supply them.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


MAX_K1_UINT = (1 << 53) - 1
_JSON_FLOAT = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z"
)
_JSON_NUMBER_PREFIX = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
)


class K1EncodingError(ValueError):
    """Malformed or noncanonical K1 representation (encoding-stage error)."""


class _ReceivedDecimal:
    """Private, byte-preserving JSON decimal token for downstream schema denial.

    Do not treat this as a Python number or as a legitimate K1 field value.
    The source contract does not specify float normalisation rules.
    """

    __slots__ = ("lexeme",)

    def __init__(self, lexeme: str) -> None:
        if not _JSON_FLOAT.fullmatch(lexeme) or "." not in lexeme and "e" not in lexeme.lower():
            raise K1EncodingError("Invalid JSON decimal token")
        self.lexeme = lexeme

    def __repr__(self) -> str:
        return "_ReceivedDecimal(<schema-invalid token>)"


def _k1_string(value: str) -> str:
    """Encode printable ASCII with exactly the two permitted JSON escapes."""
    if not isinstance(value, str):
        raise K1EncodingError("Expected a string")
    chunks = ['"']
    for character in value:
        cp = ord(character)
        if cp < 0x20 or cp > 0x7E:
            raise K1EncodingError("K1 string contains a non-printable or non-ASCII character")
        if character == '"':
            chunks.append('\\"')
        elif character == "\\":
            chunks.append("\\\\")
        else:
            chunks.append(character)
    chunks.append('"')
    return "".join(chunks)


def _render_k1(value: Any, *, received_decimals: bool) -> str:
    """Canonical K1 rendering with an explicit stack, not Python recursion.

    Track active container identities to reject cycles on the outbound path.
    A deep, acyclic list/dict can be rendered without interpreter recursion.
    """
    chunks: list[str] = []
    tasks: list[tuple[str, Any]] = [("value", value)]
    active: set[int] = set()
    while tasks:
        kind, current = tasks.pop()
        if kind == "text":
            chunks.append(current)
            continue
        if kind == "leave":
            active.remove(current)
            continue

        if current is None:
            chunks.append("null")
        elif current is True:
            chunks.append("true")
        elif current is False:
            chunks.append("false")
        elif isinstance(current, str):
            chunks.append(_k1_string(current))
        elif type(current) is int:  # Exact built-in int, never custom __str__.
            if current < 0 or current > MAX_K1_UINT:
                raise K1EncodingError("K1 integer outside unsigned 53-bit-safe range")
            chunks.append(str(current))
        elif isinstance(current, _ReceivedDecimal):
            if not received_decimals:
                raise K1EncodingError("Decoded decimal tokens are not outbound K1 field values")
            chunks.append(current.lexeme)  # Only for encoding/schema split.
        elif isinstance(current, float):
            raise K1EncodingError("K1 has no contract-defined outbound float form")
        elif isinstance(current, (list, tuple, dict)):
            identity = id(current)
            if identity in active:
                raise K1EncodingError("Cyclic K1 container is not representable")
            active.add(identity)
            tasks.append(("leave", identity))
            if isinstance(current, (list, tuple)):
                tasks.append(("text", "]"))
                for pos in range(len(current) - 1, -1, -1):
                    tasks.append(("value", current[pos]))
                    if pos:
                        tasks.append(("text", ","))
                tasks.append(("text", "["))
            else:
                if not all(isinstance(key, str) for key in current):
                    raise K1EncodingError("All K1 object keys must be strings")
                if any(any(ord(c) < 0x20 or ord(c) > 0x7E for c in key)
                       for key in current):
                    raise K1EncodingError("K1 object key is outside printable ASCII")
                keys = sorted(current, key=lambda key: key.encode("ascii"))
                tasks.append(("text", "}"))
                for pos in range(len(keys) - 1, -1, -1):
                    key = keys[pos]
                    tasks.append(("value", current[key]))
                    tasks.append(("text", ":"))
                    tasks.append(("text", _k1_string(key)))
                    if pos:
                        tasks.append(("text", ","))
                tasks.append(("text", "{"))
        else:
            raise K1EncodingError("Unsupported K1 value type: " + type(current).__name__)
    return "".join(chunks)


def encode_k1(value: Any) -> bytes:
    """Encode an application-supplied value into K1-shaped ASCII bytes.

    The caller must independently validate its exact object schema and domain.
    Only exact built-in int values are accepted as integers (not int subclasses).
    Floats are not supported for outbound generation. The ability to render
    JSON null/bool is only for separating encoding rules from schema rules.
    """
    try:
        return _render_k1(value, received_decimals=False).encode("ascii")
    except (RecursionError, UnicodeError) as exc:
        raise K1EncodingError("K1 encoding recursion/character failure") from exc


def _read_k1_string(text: str, start: int) -> tuple[str, int]:
    """Read one string without recursive parsing or non-K1 escape forms."""
    if start >= len(text) or text[start] != '"':
        raise K1EncodingError("Expected JSON string")
    index = start + 1
    characters: list[str] = []
    while index < len(text):
        character = text[index]
        index += 1
        if character == '"':
            return "".join(characters), index
        if character == "\\":
            if index == len(text) or text[index] not in ('"', "\\"):
                raise K1EncodingError("Noncanonical or incomplete K1 string escape")
            characters.append(text[index])
            index += 1
        elif 0x20 <= ord(character) <= 0x7E:
            characters.append(character)
        else:
            raise K1EncodingError("K1 string contains a non-printable character")
    raise K1EncodingError("Unterminated K1 string")


def _read_k1_value(text: str, index: int) -> tuple[Any, int, dict[str, Any] | None]:
    """Read one JSON value; return a new frame when it opens a container."""
    if index >= len(text):
        raise K1EncodingError("Missing K1 JSON value")
    character = text[index]
    if character == "[":
        value: list[Any] = []
        return value, index + 1, {"kind": "array", "value": value, "state": "first"}
    if character == "{":
        value_obj: dict[str, Any] = {}
        return value_obj, index + 1, {"kind": "object", "value": value_obj, "state": "first"}
    if character == '"':
        value_str, end = _read_k1_string(text, index)
        return value_str, end, None
    for word, value in (("true", True), ("false", False), ("null", None)):
        if text.startswith(word, index):
            return value, index + len(word), None
    if character in "-0123456789":
        match = _JSON_NUMBER_PREFIX.match(text, index)
        if match is None:
            raise K1EncodingError("Malformed K1 JSON number")
        token = match.group(0)
        if "." in token or "e" in token.lower():
            return _ReceivedDecimal(token), match.end(), None
        # Integers have a contract-defined unsigned byte form; decimals do not.
        # A 17-digit unsigned integer cannot fit into the permitted range.
        if token.startswith("-") and token != "-0":
            raise K1EncodingError("K1 integer outside unsigned 53-bit-safe range")
        if len(token.lstrip("-")) > 16:
            raise K1EncodingError("K1 integer outside unsigned 53-bit-safe range")
        number = int(token)
        if number > MAX_K1_UINT:
            raise K1EncodingError("K1 integer outside unsigned 53-bit-safe range")
        return number, match.end(), None
    raise K1EncodingError("Invalid K1 JSON value")


def _parse_k1_iterative(text: str) -> Any:
    """Decode JSON grammar with an explicit container stack at any frame depth.

    Reject malformed syntax, forbidden escapes and duplicates at encoding stage.
    Do not decide application field types or permitted container shapes here.
    """
    root, index, opened = _read_k1_value(text, 0)
    stack: list[dict[str, Any]] = [opened] if opened is not None else []
    while stack:
        frame = stack[-1]
        kind, state = frame["kind"], frame["state"]
        next_char = text[index] if index < len(text) else None
        if kind == "array":
            if state in ("first", "item"):
                if state == "first" and next_char == "]":
                    index += 1
                    stack.pop()
                    continue
                item, index, child = _read_k1_value(text, index)
                frame["value"].append(item)
                frame["state"] = "separator"
                if child is not None:
                    stack.append(child)
            elif next_char == ",":
                index += 1
                frame["state"] = "item"  # A trailing comma cannot close.
            elif next_char == "]":
                index += 1
                stack.pop()
            else:
                raise K1EncodingError("Expected K1 array comma or closing bracket")
        elif state in ("first", "key"):
            if state == "first" and next_char == "}":
                index += 1
                stack.pop()
                continue
            key, index = _read_k1_string(text, index)
            if key in frame["value"]:
                raise K1EncodingError("Duplicate K1 object key")
            frame["key"] = key
            frame["state"] = "colon"
        elif state == "colon":
            if next_char != ":":
                raise K1EncodingError("Expected colon after K1 object key")
            index += 1
            frame["state"] = "item"
        elif state == "item":
            item, index, child = _read_k1_value(text, index)
            frame["value"][frame.pop("key")] = item
            frame["state"] = "separator"
            if child is not None:
                stack.append(child)
        elif next_char == ",":
            index += 1
            frame["state"] = "key"  # A trailing comma cannot close.
        elif next_char == "}":
            index += 1
            stack.pop()
        else:
            raise K1EncodingError("Expected K1 object comma or closing brace")
    if index != len(text):
        raise K1EncodingError("Trailing bytes outside one K1 JSON value")
    return root


def decode_k1(raw: bytes) -> Any:
    """Decode K1 byte canonicality without Python's recursive JSON decoder.

    Deep but lexically canonical arrays/objects remain available for schema
    rejection under the correct application error code. Exact object shape,
    field types, float/decimal restrictions and the service-frame size limit
    belong to the consuming application, not this raw K1 byte codec.

    Decimal lexemes are opaque _ReceivedDecimal markers, never canonical
    numeric values. The consuming schema MUST reject them before trusting a
    decoded object or digest; no float normalisation is established here.
    """
    if not isinstance(raw, bytes):
        raise K1EncodingError("Input must be bytes")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise K1EncodingError("K1 requires ASCII bytes") from exc
    try:
        obj = _parse_k1_iterative(text)
        canonical = _render_k1(obj, received_decimals=True).encode("ascii")
    except K1EncodingError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise K1EncodingError("Invalid or unsupported K1 JSON representation") from exc
    if canonical != raw:
        raise K1EncodingError("Received bytes are not in K1 canonical form")
    return obj


def k1_sha256_hex(value: Any) -> str:
    """SHA-256 hex of exact K1-encoded bytes, without schema validation."""
    return hashlib.sha256(encode_k1(value)).hexdigest()
