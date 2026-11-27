# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Read the cron values under 'schedule:' in a GitHub Actions workflow.

scorecard_slots.py imports this module. It is a line-based reader, not
a YAML parser: it needs only the standard library, so the audit runs on
a bare interpreter, and it keeps the source line of each cron key, which
the audit looks up in the file's blame. It reads only the 'schedule'
key of the top-level 'on:' mapping, so a dispatch input or a 'run:'
script that mentions 'schedule:' is not read. Keys may be plain or
quoted, in block or flow style, with an anchor or tag on their value,
and cron values plain or quoted, over one line or several, or block
scalars; a double-quoted value has its escapes decoded. A plain alias,
'cron: *name' or 'schedule: *name', reads the value its anchor marks,
whole over however many lines it takes; a quoted '*name' is a string,
and an '&name' in a block scalar's text is not an anchor.
"""

from __future__ import annotations

import re
from itertools import accumulate

# Node properties, an anchor '&name' or a tag '!tag', before a value.
PROPS = r"(?:[&!][^\s,\[\]{}]*(?:\s+|$))*"
# The workflow's top-level 'on:' key, plain or quoted, and a 'schedule:'
# key inside it; only the trigger mapping's own 'schedule' is read.
ON = re.compile(rf"""^(?P<q>["']?)on(?P=q)\s*:\s*{PROPS}(?P<rest>.*)$""")
SCHEDULE = re.compile(rf"""(?P<q>["']?)schedule(?P=q)\s*:\s*{PROPS}""")
CRON = re.compile(rf"""(?<![\w-])(?P<q>["']?)cron(?P=q)\s*:\s*{PROPS}""")
# A block scalar header, '|' or '>' with optional chomping and indentation.
BLOCK = re.compile(r"[|>][-+0-9]*")
# Where a block value opens, after 'key: ' or '- ', and a line whose value
# is a block scalar header; 'LEAD' is the '- ' markers before a line's key.
VALUE = re.compile(rf"(?:(?:^|(?<=\s))-|:)\s+{PROPS}")
BLOCK_HEAD = re.compile(rf"(?:(?:^|(?<=\s))(?P<dash>-)|:)\s+{PROPS}[|>][-+0-9]*\s*$")
LEAD = re.compile(r"\s*(?:-\s+)*")
FLOW_END = re.compile(r"[,}\]]")
# A quoted scalar, which can only open after a separator, or a comment.
COMMENT = re.compile(
    r"""(?:^|[\s\[{,:-])(?P<quoted>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'(?!'))|(?:^|(?<=\s))#"""
)
QUOTED = re.compile(r""""(?:[^"\\]|\\.)*"|'(?:[^']|'')*'(?!')""", re.DOTALL)
# An anchor '&name' on a node, and a plain value that is an alias '*name'.
ANCHOR = re.compile(rf"(?:^|(?<=[\s\[{{,:-]))&(?P<name>[^\s,\[\]{{}}]+)\s*{PROPS}")
ALIAS = re.compile(r"\*(?P<name>[^\s,\[\]{}]+)\s*(?=[,}\]]|$)")
# A double-quoted escape, and what each single-character one stands for.
ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", re.DOTALL)
ESCAPES = dict(
    zip(
        '0abt\tnvfre "/\\N_LP',
        '\0\a\b\t\t\n\v\f\r\x1b "/\\\x85\xa0\u2028\u2029',
        strict=True,
    )
)


def indent_of(line: str) -> int:
    """Return the number of leading spaces on a line."""
    return len(line) - len(line.lstrip(" "))


def strip_comment(line: str) -> str:
    """Return line without its YAML comment; a quoted '#' stays."""
    for match in COMMENT.finditer(line):
        if match.group("quoted") is None:
            return line[: match.start()]
    return line


def fold_at(lines: list[str], number: int, pos: int) -> str:
    """Fold a quoted value opening at lines[number][pos] onto that line.

    The lines the value took become blank, so the key keeps its line
    number for the blame. Return the line as it now stands.
    """
    line = lines[number]
    if line[pos : pos + 1] not in {'"', "'"} or QUOTED.match(line, pos):
        return line
    text = line[pos:]
    for last in range(number + 1, len(lines)):
        below = lines[last]
        if below.strip() and indent_of(below) <= indent_of(line):
            break
        text += "\n" + below
        if (quoted := QUOTED.match(text)) is not None:
            value = ""
            for part in filter(None, (p.strip() for p in quoted.group().split("\n"))):
                # In double quotes a '\' that ends a line joins it to the next.
                escaped = (len(value) - len(value.rstrip("\\"))) % 2 and text[0] == '"'
                value = value[:-1] + part if escaped else f"{value} {part}".lstrip()
            lines[number] = line[:pos] + value + text[quoted.end() :]
            lines[number + 1 : last + 1] = [""] * (last - number)
            break
    return lines[number]


def blank_quoted(line: str) -> str:
    """Return line with each quoted scalar on it blanked out."""
    return QUOTED.sub(lambda m: "\0" * len(m.group()), line)


def prepare(raw: list[str]) -> tuple[list[str], set[int]]:
    """Return lines without comments, quoted values folded, and block scalar text.

    The second item holds the indices of block scalar text lines. A
    quoted value is folded where a value opens: after 'key: ', '- ',
    'cron:' or an anchor. A block scalar's text is data, not YAML, so it
    keeps any '#' it holds and is neither folded nor searched for anchors.
    """
    lines, content, parent = [strip_comment(line) for line in raw], set[int](), -1
    for number, line in enumerate(raw):
        if parent >= 0 and (not line.strip() or indent_of(line) > parent):
            content.add(number)
            lines[number] = line
            continue
        parent, pos, current = -1, 0, lines[number]
        while True:
            plain = blank_quoted(current)
            ends = [m.end() for r in (VALUE, CRON, ANCHOR) for m in r.finditer(plain)]
            if not (later := [end for end in ends if end > pos]):
                break
            pos = min(later)
            current = fold_at(lines, number, pos)
        if (head := BLOCK_HEAD.search(blank_quoted(current))) is not None:
            # The text must sit deeper than the key, or the '- ' it follows.
            lead = len(current) - len(LEAD.sub("", current, count=1))
            parent = head.start() if head["dash"] else lead
    return lines, content


def flow_depth(line: str) -> int:
    """Return the change in flow-collection nesting across a line."""
    plain = QUOTED.sub("", line)
    return sum(plain.count(c) for c in "[{") - sum(plain.count(c) for c in "]}")


def decode(match: re.Match[str]) -> str:
    """Return the character a double-quoted escape stands for."""
    code = match.group(1)
    if len(code) > 1:
        return chr(int(code[1:], 16))
    return ESCAPES.get(code, match.group())


def unquote(text: str) -> str:
    """Return a scalar's value: unquoted, with its escapes decoded."""
    if not QUOTED.fullmatch(text):
        return text.strip()
    if text[0] == "'":
        return text[1:-1].replace("''", "'").strip()
    return ESCAPE.sub(decode, text[1:-1]).strip()


def crons_on(line: str) -> list[tuple[int, str, bool]]:
    """Return (key column, value, plain block) for each cron key on a line.

    The line is comment-free, and starts outside any flow collection. A
    plain value ends at ',', '}' or ']' only in a flow collection, so a
    block '0,1' stays whole; plain block is true for a plain value
    outside one, which may go on below its key.
    """
    values: list[tuple[int, str, bool]] = []
    for match in CRON.finditer(line):
        rest = line[match.end() :]
        quoted = QUOTED.match(rest)
        if quoted is not None:
            # Kept quoted, so a quoted '*name' is not read as an alias.
            values.append((match.start(), quoted.group(), False))
            continue
        flow = flow_depth(line[: match.start()]) > 0
        stop = FLOW_END.search(rest) if flow else None
        value = (rest[: stop.start()] if stop else rest).strip()
        values.append((match.start(), value, not flow))
    return values


def flow_crons(pieces: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Return (line number, cron) for a flow value given as (line number, text).

    The lines are joined first, as YAML folds a line break in a flow
    collection, so a plain value spread over lines is read whole.
    """
    starts = list(accumulate((len(text) + 1 for _, text in pieces), initial=0))
    joined = " ".join(text for _, text in pieces)
    found: list[tuple[int, str]] = []
    for col, cron, _ in crons_on(joined):
        piece = next(i for i in range(len(pieces)) if col < starts[i + 1])
        found.append((pieces[piece][0], cron))
    return found


def continuation(lines: list[str], index: int, column: int) -> str:
    """Return the value on the lines after index indented past column.

    This reads a block scalar ('cron: >-'), a value on the lines below
    its key, or the rest of a plain value; a cron value reads the same
    folded or literal. A quoted value keeps its quotes.
    """
    parts: list[str] = []
    for line in lines[index + 1 :]:
        if line.strip() and indent_of(line) <= column:
            break
        parts.append(line.strip())
    return " ".join(p for p in parts if p)


def literal(text: str) -> str:
    """Return text single-quoted, so it reads back as itself, never an alias."""
    return "'" + text.replace("'", "''") + "'"


def flow_value(lines: list[str], index: int, start: int) -> list[tuple[int, str]]:
    """Return (line number, text) for each line of the value at lines[index][start:].

    The value ends where its brackets close, or at a ',', '}' or ']' that
    ends it inside the enclosing flow mapping, so a sibling key such as
    'workflow_dispatch: {inputs: {cron: ...}}' is not part of it.
    """
    pieces: list[tuple[int, str]] = []
    depth = 0
    for number in range(index, len(lines)):
        line = lines[number]
        begin = pos = start if number == index else 0
        while pos < len(line):
            quoted = QUOTED.match(line, pos)
            if quoted is not None:
                pos = quoted.end()
                continue
            char = line[pos]
            depth += (char in "[{") - (char in "]}")
            if depth < 0 or (depth == 0 and char in ",]}"):
                end = pos + 1 if char != "," and depth == 0 else pos
                pieces.append((number + 1, line[begin:end]))
                return pieces
            pos += 1
        pieces.append((number + 1, line[begin:]))
        if depth == 0 and line[begin:].strip():
            break
    return pieces


def flow_key(lines: list[str], index: int, start: int) -> tuple[int, int] | None:
    """Return (line index, value column) of 'schedule' in the flow mapping at start.

    Only a key of that mapping itself counts: a 'schedule' key nested in
    a sibling's value, such as a dispatch input, does not.
    """
    depth, expect = 0, False
    for number in range(index, len(lines)):
        line = lines[number]
        pos = start if number == index else 0
        while pos < len(line):
            char = line[pos]
            if char.isspace():
                pos += 1
                continue
            if depth == 0 and char != "{":
                return None
            match = SCHEDULE.match(line, pos) if expect and depth == 1 else None
            if match is not None:
                return number, match.end()
            expect = False
            quoted = QUOTED.match(line, pos)
            if quoted is not None:
                pos = quoted.end()
                continue
            depth += (char in "[{") - (char in "]}")
            if depth <= 0:
                return None
            expect = char in "{,"
            pos += 1
    return None


def block_key(lines: list[str], index: int) -> tuple[int, int] | None:
    """Return (line index, value column) of 'schedule' in the block below index.

    Only a line at the mapping's own indentation is one of its keys; a
    deeper line, a block scalar's text included, belongs to a child.
    """
    child = None
    for number in range(index + 1, len(lines)):
        line = lines[number]
        if not line.strip():
            continue
        indent = indent_of(line)
        if indent == 0:
            return None
        if child is None:
            child = indent
            if line[indent] == "{":
                return flow_key(lines, number, indent)
        match = SCHEDULE.match(line, indent) if indent == child else None
        if match is not None:
            return number, match.end()
    return None


def schedule_crons(text: str) -> list[tuple[int, str]]:
    """Return (line number, cron value) for each cron under 'on.schedule'."""
    lines, content = prepare(text.splitlines())
    key = None
    for number, line in enumerate(lines):
        match = ON.match(line)
        if match is not None:
            rest = match.start("rest")
            flow = line[rest:].strip()
            key = flow_key(lines, number, rest) if flow else block_key(lines, number)
            break
    if key is None:
        return []
    index, column = key
    anchors = anchors_in(lines, content)
    alias = ALIAS.match(lines[index][column:].strip())
    if alias is not None:
        # 'schedule: *name' reads the node the anchor marks, at its lines.
        index, column = next(
            (
                (n, c)
                for n, c, name in reversed(anchors)
                if n <= index and name == alias["name"]
            ),
            (index, len(lines[index])),
        )
    line = lines[index]
    if line[column:].strip() or flow_depth(line[:column]) > 0:
        # A flow value may run over several lines; read it alone.
        found = flow_crons(flow_value(lines, index, column))
    else:
        found = block_crons(lines, index, content)
    return [(number, resolve(lines, anchors, number, cron)) for number, cron in found]


def anchors_in(lines: list[str], content: set[int]) -> list[tuple[int, int, str]]:
    """Return (line index, value column, name) for each anchor, in order.

    Quoted text is blanked first and block scalar text is skipped, so an
    '&' in a string is not one.
    """
    found: list[tuple[int, int, str]] = []
    for number, line in enumerate(lines):
        if number not in content:
            plain = blank_quoted(line)
            found.extend((number, m.end(), m["name"]) for m in ANCHOR.finditer(plain))
    return found


def resolve(
    lines: list[str], anchors: list[tuple[int, int, str]], number: int, cron: str
) -> str:
    """Return a cron value as read, or the scalar its alias '*name' stands for.

    Only a plain value can be an alias; a quoted one is unquoted. An
    alias names the last anchor of that name at or above its line, as
    YAML defines it; the value is read as a cron value is, and an alias
    with no anchor is left as written.
    """
    alias = ALIAS.fullmatch(cron)
    if alias is None:
        return unquote(cron)
    for index, column, name in reversed(anchors):
        if index < number and name == alias["name"]:
            line = lines[index]
            rest = line[column:]
            if (quoted := QUOTED.match(rest)) is not None:
                return unquote(quoted.group())
            if flow_depth(line[:column]) > 0:
                # A plain flow value runs on over lines to its ',', '}' or ']'.
                following = iter(lines[index + 1 :])
                while (
                    FLOW_END.search(rest) is None
                    and (more := next(following, None)) is not None
                ):
                    rest += " " + more
                stop = FLOW_END.search(rest)
                return " ".join((rest[: stop.start()] if stop else rest).split())
            below = continuation(lines, index, indent_of(line))
            if BLOCK.fullmatch(rest.strip()):
                return below
            return unquote(f"{rest.strip()} {below}")
    return unquote(cron)


def block_crons(
    lines: list[str], index: int, content: set[int]
) -> list[tuple[int, str]]:
    """Return (line number, cron) for each cron in the block below lines[index].

    Block scalar text, the indices in content, is read with its key only.
    """
    found: list[tuple[int, str]] = []
    depth = indent_of(lines[index])
    number = index + 1
    while number < len(lines):
        if number in content:
            number += 1
            continue
        child = lines[number]
        stripped = child.strip()
        indent = indent_of(child)
        # YAML lets a block sequence sit at its key's own indentation,
        # so a '- ' item there still belongs to 'schedule:'.
        item = stripped == "-" or stripped.startswith("- ")
        if stripped and (indent < depth or (indent == depth and not item)):
            break
        if flow_depth(child) > 0:
            # A flow collection left open runs on; read its lines joined.
            pieces, level = [(number + 1, child)], flow_depth(child)
            while level > 0 and number + 1 < len(lines):
                number += 1
                pieces.append((number + 1, lines[number]))
                level += flow_depth(lines[number])
            found.extend(flow_crons(pieces))
        else:
            for col, cron, plain in crons_on(child):
                # A block scalar header or a plain value goes on below.
                below = continuation(lines, number, col) if plain else ""
                if plain and BLOCK.fullmatch(cron):
                    found.append((number + 1, literal(below)))
                else:
                    found.append((number + 1, f"{cron} {below}".strip()))
        number += 1
    return found
