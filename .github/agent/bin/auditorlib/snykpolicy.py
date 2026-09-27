"""A strict reader for the `.snyk` ignore policy the auditor writes (auditor-run.py
_ignores_from_statements) — the one production reader of that file, so the auditor needs no YAML
library at runtime.

It accepts ONLY the writer's canonical output, byte for byte:

    version: v1.5.0
    ignore:
      <ID>:
        - '<selector>':
            <key>: '<text>'            (or, for a timestamp, <key>: 2026-10-22T00:00:00.000Z)

After parsing, the policy is re-serialised in exactly that form and must reproduce the input
byte for byte — so the accepted language IS the writer's language, a subset of YAML that YAML
reads identically (verified against PyYAML in the tests). No YAML feature is interpreted: a
comment, a blank line, an anchor/alias/tag, a flow collection, a duplicate key, a null value,
another quoting or plain form, a control/line-separator character, or a key over YAML's
1024-character implicit-key limit all raise ValueError. The caller treats an unreadable policy
as a failed check (fail closed), never as "no ignores".
"""
import re

_VERSION = r"v\d+(?:\.\d+)*"
_TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"
# quoted text: printable, no quote, no C0/C1 control, no DEL, no Unicode line/paragraph
# separator or BOM — characters YAML treats specially or forbids
_TEXT = r"[^'\x00-\x1f\x7f-\x9f  ﻿]*"
_QUOTED = "'" + _TEXT + "'"
_MAX_KEY = 1000                      # YAML: an implicit key is at most 1024 characters
_ID = re.compile(r"^  (?P<id>[A-Za-z0-9][A-Za-z0-9._-]*):$")
_SEL = re.compile(r"^    - (?P<sel>" + _QUOTED + r"):$")
_KV = re.compile(r"^        (?P<k>[A-Za-z_][A-Za-z0-9_-]*): (?P<v>" + _QUOTED + "|" + _TIMESTAMP + r")$")


def _scalar(v):
    return v[1:-1] if v.startswith("'") else v


def _render(version, ignore):
    """The writer's canonical form of a parsed policy (auditor-run.py _ignores_from_statements)."""
    out = ["version: %s" % version, "ignore:"]
    for cid, entries in ignore.items():
        out.append("  %s:" % cid)
        for entry in entries:
            for sel, props in entry.items():
                out.append("    - '%s':" % sel)
                for k, v in props.items():
                    out.append("        %s: %s" % (k, v if re.fullmatch(_TIMESTAMP, v) else "'%s'" % v))
    return "\n".join(out) + "\n"


def load(text):
    """{ignore-id: [{selector: {key: value}}]} for a policy that is byte-exactly the writer's."""
    lines = text.split("\n")
    if len(lines) < 3 or lines[-1] != "":
        raise ValueError(".snyk: not the auditor's policy (want `version:` + `ignore:` lines, "
                         "newline-terminated)")
    m = re.fullmatch("version: (" + _VERSION + ")", lines[0])
    if not m:
        raise ValueError(".snyk line 1: want `version: v<N>[.<N>...]`, got %r" % lines[0])
    version = m.group(1)
    if lines[1] != "ignore:":
        raise ValueError(".snyk line 2: want `ignore:`, got %r" % lines[1])
    ignore, cur_id, cur_props = {}, None, None
    for n, line in enumerate(lines[2:-1], 3):
        m = _ID.match(line)
        if m:
            cur_id, cur_props = m.group("id"), None
            if cur_id in ignore:
                raise ValueError(".snyk line %d: duplicate ignore id %s" % (n, cur_id))
            ignore[cur_id] = []
            continue
        m = _SEL.match(line)
        if m and cur_id is not None:
            cur_props = {}
            ignore[cur_id].append({_scalar(m.group("sel")): cur_props})
            continue
        m = _KV.match(line)
        if m and cur_props is not None:
            if m.group("k") in cur_props:
                raise ValueError(".snyk line %d: duplicate key %s" % (n, m.group("k")))
            cur_props[m.group("k")] = _scalar(m.group("v"))
            continue
        raise ValueError(".snyk line %d: not in the auditor's ignore shape: %r" % (n, line))
    for cid, entries in ignore.items():
        if len(cid) > _MAX_KEY:
            raise ValueError(".snyk: ignore id longer than %d characters" % _MAX_KEY)
        if not entries:
            raise ValueError(".snyk: ignore id %s has no selector" % cid)
        for entry in entries:
            for sel, props in entry.items():
                if len(sel) + 2 > _MAX_KEY:
                    raise ValueError(".snyk: a selector of %s is longer than %d characters" % (cid, _MAX_KEY))
                if not props:
                    raise ValueError(".snyk: a selector of %s has no properties" % cid)
    if _render(version, ignore) != text:
        raise ValueError(".snyk: not byte-for-byte the auditor's canonical policy")
    return {"ignore": ignore}
