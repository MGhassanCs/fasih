"""Bidirectional-text helpers.

When an LTR run (a number, a Latin word, a URL, an order id) is dropped into
Arabic RTL text, the Unicode bidi algorithm can place it in the wrong visual
position -- "order ABC-12" inside an Arabic sentence can render as "12-ABC" or
jump to the wrong edge. Wrapping the LTR run in isolate marks fixes it.

The isolate characters (U+2066..U+2069) are invisible, so they are built with
``chr()`` from their code points rather than pasted into the source.
"""

from __future__ import annotations

_LRI = chr(0x2066)  # left-to-right isolate
_FSI = chr(0x2068)  # first-strong isolate
_PDI = chr(0x2069)  # pop directional isolate


def wrap_ltr(text) -> str:
    """Wrap an LTR run (number, Latin word, URL) in left-to-right isolates so it
    keeps its position inside surrounding RTL Arabic text."""
    return _LRI + str(text) + _PDI


def isolate(text) -> str:
    """Wrap a run of unknown direction in a first-strong isolate."""
    return _FSI + str(text) + _PDI
