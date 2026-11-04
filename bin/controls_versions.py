("The version table of the controls document, read in one place (REQ-REL-012): "
 "bin/evidence-letter.py and bin/release-metadata.py both import this.")
import re

# the only characters a quoted note, summary or change cell may hold: no markup, entity or link can be written with them
QUOTED = re.compile(r"[A-Za-z0-9 .,:;()'/-]+")  # "Fix: a crash (rare)." matches; "a&#105;b" and "[x](y)" do not
# "| 2 | 2026-11-20 | Adds a step |" matches; "| Version | Signed | Change |" does not
ROW = re.compile(r"^\| *([0-9]+) *\| *([0-9]{4}-[0-9]{2}-[0-9]{2}) *\|([^|\n]*)\|", re.M)


class NoVersionRow(ValueError):
    pass


def controls_versions(controls_text):
    ("[(version, signed date, change cell)] from the rows `| 1 | 2026-10-20 | ... |` of the controls document, "
     "oldest first.")
    rows = [(int(v), d, c.strip()) for v, d, c in ROW.findall(controls_text)]
    if not rows:
        raise NoVersionRow("the controls document has no version row")
    return sorted(rows)
