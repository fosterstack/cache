"""A strict reader for the `.snyk` ignore policy the auditor writes (auditor-run.py
_ignores_from_statements) — the one production reader of that file, so the auditor needs no YAML
library at runtime. It accepts exactly that block shape:

    version: v1.5.0
    ignore:
      <ID>:
        - '<selector>':
            <key>: <value>

(and an empty `ignore:` / `ignore: {}`, and `patch: {}`). Scalars are exactly what the writer
emits: a single-quoted string with no quote inside, or — the writer's only plain forms — an ISO
timestamp value (`expires`) or a version token; selectors are single-quoted, ids a plain
[A-Za-z0-9._-] token. No YAML feature is interpreted — a trailing comment, an
anchor/alias/tag, a double-quoted or escaped string, a flow collection — so none is "read as text"
with a meaning YAML would not give it: anything else raises ValueError, and the caller treats an
unreadable policy as a failed check (fail closed), never as "no ignores". Whole-line `#` comments
and blank lines are skipped (YAML ignores them too).
"""
import re

_VERSION = r"[A-Za-z0-9._-]+"
_TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"
_QUOTED = r"'[^']*'"
_TOP = re.compile(r"^(version|ignore|patch):(?: (.*))?$")
_ID = re.compile(r"^  (?P<id>[A-Za-z0-9._-]+):$")
_SEL = re.compile(r"^    - (?P<sel>" + _QUOTED + r"):$")
# a value is single-quoted, or a bare timestamp — never any other plain scalar (whose YAML meaning,
# e.g. a trailing `:` that makes it invalid, this reader would otherwise have to reproduce)
_KV = re.compile(r"^        (?P<k>[A-Za-z_][A-Za-z0-9_-]*): (?P<v>" + _QUOTED + "|" + _TIMESTAMP + r")$")


def _scalar(v):
    return v[1:-1] if v.startswith("'") else v


def load(text):
    """{ignore-id: [{selector: {key: value}}]} for a policy in the auditor's shape."""
    ignore, section, cur_id, cur_props = {}, None, None, None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _TOP.match(line)
        if m:
            section, rest = m.group(1), (m.group(2) or "")
            if section == "ignore" and rest not in ("", "{}"):
                raise ValueError(".snyk line %d: `ignore:` must open a block" % n)
            if section == "patch" and rest != "{}":
                raise ValueError(".snyk line %d: only an empty `patch: {}` is accepted" % n)
            if section == "version" and not re.fullmatch(_VERSION, rest):
                raise ValueError(".snyk line %d: version must be a plain token" % n)
            cur_id = cur_props = None
            continue
        if section != "ignore":
            raise ValueError(".snyk line %d: unexpected content %r" % (n, line))
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
            cur_props[m.group("k")] = _scalar(m.group("v"))
            continue
        raise ValueError(".snyk line %d: not in the auditor's ignore shape: %r" % (n, line))
    return {"ignore": ignore}
