#!/usr/bin/env python3
"""Write the Go module list SBOM (rule 20) from the binary's own embedded module list.

The SBOM lists the modules the binary embeds (`go version -m`). Every embedded path@version
must be in BOTH vendor/modules.txt and dependency-provenance.json (a subset check, not
equality): a vendored module the binary does not embed is in the dependency list, not here.
Path and version are compared; the vendor-mode binary list carries no hashes. Anything this
tool cannot resolve (a replace line, an unparseable line, a missing input) refuses. No
scanner makes or gates this file. The output has a fixed creation time, so two runs are byte-equal.

NTIA minimum elements (0707 fix 3): the root package (the binary, SPDXRef-fscache) names its supplier (Organization: FosterStack); the document DESCRIBES the root package and the
root DEPENDS_ON each embedded module; the creators are the organization and this tool. Which relationship SPDX wants for modules compiled into one binary: the specification text
(read in v2.3.1, relationship type definitions) defines DEPENDS_ON as "A depends on B" and CONTAINS as "A contains B", gives STATIC_LINK for a file that statically links a binary
library, and states no rule for embedded modules; DEPENDS_ON is chosen because the NTIA element is a "dependency relationship". The created time stays the fixed epoch below: a
real build time would give two builds of the same inputs different bytes, which the Rebuild comparison refuses. That is the one deviation from the NTIA timestamp element, and it is stated
here on purpose.
"""
import argparse
import json
import re
import sys


def refuse(msg):
    print("go-module-sbom: " + msg, file=sys.stderr)
    sys.exit(2)


def read_vendored(path):
    mods = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as e:
        refuse("cannot read %s: %s" % (path, e))
    for ln in lines:
        if not ln.startswith("# "):
            continue
        parts = ln[2:].split()
        if "=>" in parts:
            refuse("%s: a replace line cannot be resolved: %s" % (path, ln))
        if len(parts) != 2:
            refuse("%s: unparseable module line: %s" % (path, ln))
        mods[parts[0]] = parts[1]
    return mods


def read_provenance(path):
    try:
        d = json.load(open(path, encoding="utf-8"))
        return {m["path"]: m["version"] for m in d["modules"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        refuse("cannot read %s: %s" % (path, e))


HEADER = re.compile(r"[^\t\r\n]+: go[0-9][^\t\r\n]*")


def read_embedded(path):
    """Parse `go version -m` output strictly: a header line (`<file>: go1.x`), then only tab-indented path, mod, dep, => and build
    lines. Anything else (an empty file, garbage, CRLF, a BOM, spaces instead of tabs, an unknown keyword, a dep without a version)
    is refused, so an unreadable input can never become an empty SBOM."""
    deps = {}
    try:
        raw = open(path, "rb").read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        refuse("cannot read %s: %s" % (path, e))
    if "\r" in text or text.startswith("\ufeff"):
        refuse("%s: carriage returns or a byte-order mark: this is not `go version -m` output" % path)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or not HEADER.fullmatch(lines[0]):
        refuse("%s: the first line is not a `go version -m` header (<file>: go1.x); refusing input that is not Go build information" % path)
    seen_module = False
    seen_build = False
    for ln in lines[1:]:
        if ln == "":
            continue
        f = ln.split("\t")
        if f[0] != "" or len(f) < 2 or f[1] not in ("path", "mod", "dep", "=>", "build"):
            refuse("%s: unrecognised line (not a tab-indented go version -m entry): %r" % (path, ln))
        if f[1] == "=>":
            refuse("%s: a replace line cannot be resolved: %s" % (path, ln.strip()))
        if f[1] in ("path", "mod"):
            seen_module = True
        if f[1] == "build":
            seen_build = True
        if f[1] == "dep":
            if seen_build:
                refuse("%s: a dep line after a build line (the go version -m order is path, mod, dep, build): %r" % (path, ln))
            if len(f) > 5 or (len(f) == 5 and f[4] != "" and not f[4].startswith("h1:")):   # a -mod=vendor build prints an EMPTY sum field
                refuse("%s: unexpected extra fields on a dep line: %r" % (path, ln))
            if len(f) < 4 or not f[2] or not f[3]:
                refuse("%s: unparseable dep line (a module path and a version are required): %r" % (path, ln))
            if f[2] in deps:
                refuse("%s: the module %s is listed twice" % (path, f[2]))
            deps[f[2]] = f[3]
    if not seen_module or not seen_build:
        refuse("%s: no path, mod and build lines: this is not (complete) build information of a Go program" % path)
    return deps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modules", required=True)
    ap.add_argument("--provenance", required=True)
    ap.add_argument("--buildinfo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", default="fscache")        # the package the binary is shipped in (fscache or fscache-fips)
    ap.add_argument("--version", default=None)          # its apk version without the epoch (0.3.0, 0.3.0_rc1); the root package has no version when it is not given
    ap.add_argument("--epoch", default="0")             # the recipe's epoch; the root version is VERSION-rEPOCH, the way the apk is named
    a = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", a.name) or (a.version is not None and not re.fullmatch(r"[A-Za-z0-9._+~_-]+", a.version)) or not re.fullmatch(r"[0-9]+", a.epoch):
        refuse("--name, --version and --epoch must be plain package-name, version and number words")
    vend, prov, emb = read_vendored(a.modules), read_provenance(a.provenance), read_embedded(a.buildinfo)
    bad = []
    for p, v in sorted(emb.items()):
        if vend.get(p) != v:
            bad.append("%s@%s is embedded but %s in %s" % (
                p, v, "not vendored" if p not in vend else "vendored as " + vend[p], a.modules))
        if prov.get(p) != v:
            bad.append("%s@%s is embedded but %s in %s" % (
                p, v, "absent" if p not in prov else "recorded as " + prov[p], a.provenance))
    if bad:
        refuse("module list does not match the binary:\n  " + "\n  ".join(bad))
    root = {"SPDXID": "SPDXRef-fscache", "name": a.name, "supplier": "Organization: FosterStack", "downloadLocation": "NOASSERTION", "filesAnalyzed": False}
    if a.version is not None:
        full = "%s-r%s" % (a.version, a.epoch)
        root["versionInfo"] = full
        root["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:apk/fosterstack/%s@%s" % (a.name, full)}]
    mods = [{"SPDXID": "SPDXRef-gomod-%d" % i, "name": p, "versionInfo": v,
             "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                               "referenceLocator": "pkg:golang/%s@%s" % (p, v)}]}
            for i, (p, v) in enumerate(sorted(emb.items()))]
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-fscache"}]
    rels += [{"spdxElementId": "SPDXRef-fscache", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": m["SPDXID"]} for m in mods]
    doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
           "name": "fscache-go-modules", "documentNamespace": "https://fosterstack.invalid/spdx/fscache-go-modules",
           "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Organization: FosterStack", "Tool: go-module-sbom"]},
           "packages": [root] + mods, "relationships": rels}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
