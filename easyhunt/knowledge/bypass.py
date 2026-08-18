"""Generic WAF-regex bypass payload generator.

Ported from HuntProxy's ``PayloadGenerator::RegexBypass`` (Apache-2.0,
BehiSecc). The idea: instead of a hardcoded list of bypass payloads, *generate*
variants of any input at four positions — start, around punctuation separators,
end, and around regex metacharacters — under four encodings (URL ``%xx``,
Unicode ``\\uXXXX``, raw byte, double-URL ``%25xx``). A WAF rule written as a
regex (``block .*<script>.*``, ``block ['\"]\\s+(OR|AND)``) is beaten when the
byte that breaks its match is not the byte the backend decodes.

This is the generic engine behind the vendor tables in :mod:`easyhunt.knowledge.waf`
— those name *known* working payloads per vendor; this *derives* a bounded set
of regex-breaking variants for any input, so a class with no curated table still
gets bypass depth. Consumers feed the result to validators behind the tier-B
gate (the exploit-mode approval), never as a discovery wordlist.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

__all__ = [
    "BypassEncoding",
    "BypassMode",
    "DEFAULT_MAX_PAYLOADS",
    "generate_regex_bypass",
]

#: Where the injected byte goes: before the string, around punctuation
#: separators, after the string, or replacing a regex metacharacter.
BypassMode = Literal["start", "separator", "end", "regex_metachar"]
#: How the injected byte is written on the wire.
BypassEncoding = Literal["url", "unicode", "raw", "double_url"]

DEFAULT_MAX_PAYLOADS = 2_000
MAX_INPUT_BYTES = 4 * 1024

_ASCII_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
_REGEX_METACHARS = ".^$*+-?()[]{}|"
_MODES = ("start", "separator", "end", "regex_metachar")
_ENCODINGS = ("url", "unicode", "raw", "double_url")


class BypassError(ValueError):
    """The generator was asked for something it cannot produce."""


def _encode_byte(byte: int, encoding: BypassEncoding) -> str:
    if encoding == "url":
        return f"%{byte:02x}"
    if encoding == "unicode":
        return f"\\u{byte:04x}"
    if encoding == "raw":
        # Recollapse semantics: LF/VT/FF and ESC are skipped in raw mode (their
        # replacement deletes the metacharacter rather than inserting a byte).
        if byte in (10, 11, 12, 27):
            return ""
        return chr(byte)
    return f"%25{byte:02x}"


def generate_regex_bypass(
    input_text: str,
    *,
    modes: Iterable[BypassMode] = _MODES,
    encoding: BypassEncoding = "url",
    byte_from: int = 0,
    byte_to: int = 255,
    include_alphanumeric: bool = False,
    bytes: Iterable[int] | None = None,
    max_payloads: int = DEFAULT_MAX_PAYLOADS,
) -> list[str]:
    """Generate regex-breaking variants of ``input_text``, deduplicated.

    Each variant inserts one byte (in ``encoding``) at one position (in
    ``modes``):

    * ``start`` — before the first character.
    * ``separator`` — either side of each ASCII punctuation character.
    * ``end`` — after the last character.
    * ``regex_metachar`` — *replacing* each regex metacharacter (``. ^ $ * + - ?``
      ``( ) [ ] { } |``) with the encoded byte.

    ``byte_from``/``byte_to`` bound the byte value range (0–255); with
    ``include_alphanumeric=False`` (default) alphanumerics are excluded, keeping
    the output to the bytes that actually break a regex match. The result is a
    deduplicated list bounded by ``max_payloads`` — the bound is enforced, an
    over-run raises :class:`BypassError` rather than silently truncating, so a
    consumer can never receive a partial generation it mistakes for complete.

    >>> generate_regex_bypass("<script>", modes=["start"], encoding="url", max_payloads=5)
    ['%00<script>', '%01<script>', '%02<script>', '%03<script>', '%04<script>']
    """
    if not input_text:
        raise BypassError("input must not be empty")
    if len(input_text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise BypassError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    if byte_from < 0 or byte_to > 255 or byte_from > byte_to:
        raise BypassError("byte range must satisfy 0 <= byte_from <= byte_to <= 255")
    unique_modes = list(dict.fromkeys(m for m in modes if m in _MODES))
    if not unique_modes:
        raise BypassError("at least one of start/separator/end/regex_metachar required")
    if max_payloads < 1:
        raise BypassError("max_payloads must be greater than zero")

    if bytes is not None:
        bytes_used = sorted({int(b) for b in bytes if 0 <= int(b) <= 255})
    else:
        bytes_used = [
            byte
            for byte in range(byte_from, byte_to + 1)
            if include_alphanumeric or not (48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122)
        ]
    if not bytes_used:
        raise BypassError("byte range contains no bytes after excluding alphanumerics")

    char_positions: list[tuple[int, int, str]] = []
    index = 0
    for character in input_text:
        char_positions.append((index, index + len(character), character))
        index += len(character)

    output: list[str] = []
    seen: set[str] = set()

    def add_at(start: int, end: int) -> None:
        for byte in bytes_used:
            encoded = _encode_byte(byte, encoding)
            candidate = f"{input_text[:start]}{encoded}{input_text[end:]}"
            if candidate == input_text or candidate in seen:
                continue
            if len(output) >= max_payloads:
                raise BypassError(
                    f"generation exceeds the payload limit of {max_payloads}; "
                    "narrow the byte range or modes, or raise max_payloads"
                )
            seen.add(candidate)
            output.append(candidate)

    if "start" in unique_modes:
        add_at(0, 0)
    if "separator" in unique_modes:
        for start, end, character in char_positions:
            if character in _ASCII_PUNCTUATION:
                add_at(start, start)
                add_at(end, end)
    if "end" in unique_modes:
        add_at(len(input_text), len(input_text))
    if "regex_metachar" in unique_modes:
        for start, end, character in char_positions:
            if character in _REGEX_METACHARS:
                add_at(start, end)

    if not output:
        raise BypassError("modes produced no payloads for this input")
    return output
