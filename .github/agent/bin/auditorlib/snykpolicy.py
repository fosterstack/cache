"""A strict reader for the `.snyk` ignore policy the auditor writes (auditor-run.py
_ignores_from_statements) — the one production reader of that file, so the auditor needs no YAML
library at runtime. It accepts exactly that block shape:

    version: v1.5.0
    ignore:
      <ID>:
        - '<selector>':
            <key>: <value>

(and an empty `ignore:` / `ignore: {}`, and `patch: {}`). Anything else raises ValueError:
the caller treats an unreadable policy as a problem (fail closed), never as "no ignores".
"""
import re

_TOP = re.compile(r"^(version|ignore|patch):\s*(.*)$")
_ID = re.compile(r"^  (\S+?):\s*$")
_SEL = re.compile(r"^    - (?P<sel>'[^']*'|\"[^\"]*\"|[^'\"\s]\S*?):\s*$")
_KV = re.compile(r"^        (?P<k>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<v>.*?)\s*$")


def _scalar(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def load(text):
    """{ignore-id: [{selector: {key: value}}]} for a policy in the auditor's shape."""
    ignore, section, cur_id, cur_props = {}, None, None, None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _TOP.match(line)
        if m:
            section, rest = m.group(1), m.group(2).strip()
            if section == "ignore" and rest not in ("", "{}"):
                raise ValueError(".snyk line %d: `ignore:` must open a block" % n)
            if section == "patch" and rest != "{}":
                raise ValueError(".snyk line %d: only an empty `patch: {}` is accepted" % n)
            if section == "version" and not rest:
                raise ValueError(".snyk line %d: empty version" % n)
            cur_id = cur_props = None
            continue
        if section != "ignore":
            raise ValueError(".snyk line %d: unexpected content %r" % (n, line))
        m = _ID.match(line)
        if m:
            cur_id, cur_props = m.group(1), None
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
