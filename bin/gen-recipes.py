#!/usr/bin/env python3
"""Generate the melange recipes from their templates, and check that the committed ones are exactly that (v0.3.0 rule 21).

  gen-recipes.py [--template T] [--regular R] [--fips F] [--baselayout-template BT] [--baselayout B] [--melange-lock L]
                 [--fips-module M] (--check | --write | --emit DIR)

Defaults: build/melange.yaml.tmpl, build/melange.yaml, build/melange-fips.yaml, build/melange-baselayout.yaml.tmpl, build/melange-baselayout.yaml,
build/locks/melange.lock, build/locks/fips-module.txt (relative to the repository root).
The third recipe (the file-only base layout, 0710) comes from its own template: the only placeholder is @PACKAGES@ (one whole line, the same pins as the other
recipes) and the template has its own pin, BASELAYOUT_TEMPLATE_SHA256; @VERSION@ is left as written.
Two DATA files feed the template, and they are the only thing the daily refresh job ever edits: the melange lock (the package pins of the build environment) and the
FIPS module file (the certified Go Cryptographic Module, vX.Y.Z-<8 hex>). Both have a closed line grammar; anything else is refused. The generator holds no FIPS constant.
The template is plain text with a CLOSED set of named placeholders and nothing else is substituted or parsed:
  @NAME@          package name (fscache, or fscache-fips)
  @DESCRIPTION@   package description
  @PACKAGES@      a whole line: the environment package pins, one "      - name=version" line per line of the melange lock
  @FIPS_EXPORT@   a whole line: the GOFIPS140 setting in the FIPS recipe, the line is dropped in the standard one
  @FIPS_PROOF@    a whole line block: the proof that the binary records the certified module, dropped in the standard one
  @VERSION@       left as written (build-apk.sh replaces it with the apk version)
The template must hold no GOFIPS140 (the two FIPS constants live HERE), no tab, carriage return or NUL, and be UTF-8; each of the four named placeholders appears
exactly once, FIPS_EXPORT and FIPS_PROOF each alone on a line. Nothing is parsed or compared as YAML, so there is no parser difference to exploit.
What the generator does NOT do: it does not read or judge the shell in the template. Behaviour parity of the two builds rests on the template being reviewed and
pinned (TEMPLATE_SHA256 below: --check fails if the template changes, naming the pin; a change must update the pin in the same reviewed change), and the final control
is build-apk.sh's check of the packaged binary (GOFIPS140 stamp, version, vcs), which is mandatory in CI.
--check exits 0 when all three committed files equal the generator's output byte for byte, 1 when a file differs (the diff is printed) or the template breaks a rule,
2 when a file is missing or unreadable. --write writes the three files.
"""
import argparse
import difflib
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# sha256 of build/melange.yaml.tmpl: a change to the template must update this line in the same reviewed change
TEMPLATE_SHA256 = "046f3ee631006982d941ebd8f44036a1eb5e7d8813a3f6f30ae5e89a39cdfc66"   # TEST-SUBST
# sha256 of build/melange-baselayout.yaml.tmpl: the same rule as the pin above
BASELAYOUT_TEMPLATE_SHA256 = "6ba2171c3cf0c04e95359cc00c28864771c3cc1e8933b4ab4e437997e1e79de6"   # TEST-SUBST
ALLOWED_SUBST = ("${{targets.destdir}}", "${{build.arch}}")
ALLOWED_IF = re.compile(r"    if: \$\{\{build\.arch\}\} == '(x86_64|aarch64)'")
NAMED = ("NAME", "DESCRIPTION", "PACKAGES", "FIPS_EXPORT", "FIPS_PROOF")
LITERAL = ("VERSION",)
LOCK_LINE = re.compile(r"[a-z0-9][a-z0-9._+-]*=[0-9][A-Za-z0-9._+~-]*")
FIPS_MODULE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[0-9a-f]{8}")


def read_data(path, what):
    """a data file the daily job rewrites: plain ASCII, one fixed line grammar, a final newline, nothing else"""
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        bad("cannot read %s (%s): %s" % (what, path, e), 2)
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw or any(c >= 0x80 for c in raw):
        bad("%s (%s) must be plain ASCII lines, each ending in a plain newline (no carriage return)" % (what, path))
    return raw.decode("ascii")[:-1].split("\n")


def read_packages(path):
    lines = read_data(path, "the melange lock")
    if not lines or lines == [""]:
        bad("the melange lock %s holds no package" % path)
    seen = set()
    for ln in lines:
        if not LOCK_LINE.fullmatch(ln):
            bad("the melange lock %s has a line that is not name=version: %r" % (path, ln))
        name = ln.split("=", 1)[0]
        if name in seen:
            bad("the melange lock %s names %s twice" % (path, name))
        seen.add(name)
    return lines


def read_fips_module(path):
    lines = read_data(path, "the FIPS module file")
    if len(lines) != 1 or not FIPS_MODULE.fullmatch(lines[0]):
        bad("the FIPS module file %s must hold exactly one line vMAJOR.MINOR.PATCH-<8 hex digits> (found %r)" % (path, lines))
    return lines[0]


def bad(msg, code=1):
    print("gen-recipes: " + msg, file=sys.stderr)
    sys.exit(code)


def read_template(path):
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        bad("cannot read the template %s: %s" % (path, e), 2)
    for ch, name in ((b"\t", "a tab"), (b"\r", "a carriage return"), (b"\0", "a NUL byte")):
        if ch in raw:
            bad("the template %s holds %s; refusing" % (path, name))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        bad("the template %s is not UTF-8 text" % path)
    if "GOFIPS140" in text:
        bad("the template %s mentions GOFIPS140: the FIPS lines live in the generator's two constants only" % path)
    for tok in re.findall(r"@[A-Za-z0-9_]*@", text):
        if tok[1:-1] not in NAMED + LITERAL:
            bad("the template %s holds the placeholder %s, which is not one of the named set (%s)" % (path, tok, ", ".join(NAMED)))
    for n in NAMED:
        if text.count("@%s@" % n) != 1:
            bad("the placeholder @%s@ must appear exactly once in the template (found %d)" % (n, text.count("@%s@" % n)))
    # melange substitutes ${{...}} anywhere and evaluates `if:` per step: any use outside a closed set could make the two recipes BEHAVE differently while
    # differing only "by name" (review round 8): so the set of substitutions, the `if:` conditions, the places of the name and the build steps are all closed
    for tok in re.findall(r"\$\{\{[^}]*\}\}", text):
        if tok not in ALLOWED_SUBST:
            bad("the template %s holds the substitution %s; only %s are allowed" % (path, tok, ", ".join(ALLOWED_SUBST)))
    if text.count("${{") != len(re.findall(r"\$\{\{[^}]*\}\}", text)):
        bad("the template %s holds a '${{' that is not a closed substitution; refusing" % path)
    for ln in text.split("\n"):
        if re.match(r"\s*(-\s*)?if\s*:", ln) and not ALLOWED_IF.fullmatch(ln):
            bad("the template %s holds the condition %r; only the two build.arch conditions are allowed" % (path, ln.strip()))
    lines = text.split("\n")
    top = [i for i, ln in enumerate(lines) if re.match(r"\S", ln)]
    pk = lines.index("package:") if "package:" in lines else -1
    if pk < 0:
        bad("the template %s has no package: block" % path)
    pend = min([i for i in top if i > pk] or [len(lines)])
    for ph, want in (("NAME", "  name: @NAME@"), ("DESCRIPTION", "  description: @DESCRIPTION@")):
        at = [i for i, ln in enumerate(lines) if "@%s@" % ph in ln]
        if len(at) != 1 or lines[at[0]] != want or not pk < at[0] < pend:
            bad("@%s@ may appear only as the line %r inside the package: block (it would otherwise let melange behave differently for the FIPS package)" % (ph, want))
    for n in ("PACKAGES", "FIPS_EXPORT", "FIPS_PROOF"):
        if ("\n@%s@\n" % n) not in text:
            bad("@%s@ must be alone on its line" % n)
    got = hashlib.sha256(raw).hexdigest()
    if got != TEMPLATE_SHA256:
        bad("the template changed: update TEMPLATE_SHA256 in the same reviewed change (the template %s has sha256 %s, the pin is %s)" % (path, got, TEMPLATE_SHA256))
    return text


def read_baselayout_template(path):
    """the base-layout template: plain UTF-8 text with one @PACKAGES@ line and the literal @VERSION@, and its pin"""
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        bad("cannot read the template %s: %s" % (path, e), 2)
    for ch, name in ((b"\t", "a tab"), (b"\r", "a carriage return"), (b"\0", "a NUL byte")):
        if ch in raw:
            bad("the template %s holds %s; refusing" % (path, name))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        bad("the template %s is not UTF-8 text" % path)
    for tok in re.findall(r"@[A-Za-z0-9_]*@", text):
        if tok not in ("@PACKAGES@", "@VERSION@"):
            bad("the template %s holds the placeholder %s, which is not @PACKAGES@ or @VERSION@" % (path, tok))
    if text.count("@PACKAGES@") != 1 or ("\n@PACKAGES@\n") not in text:
        bad("@PACKAGES@ must appear exactly once in the template %s, alone on its line" % path)
    got = hashlib.sha256(raw).hexdigest()
    if got != BASELAYOUT_TEMPLATE_SHA256:
        bad("the template changed: update BASELAYOUT_TEMPLATE_SHA256 in the same reviewed change (the template %s has sha256 %s, the pin is %s)"
            % (path, got, BASELAYOUT_TEMPLATE_SHA256))
    return text


def generate_baselayout(text, packages):
    return "\n".join("\n".join("      - " + p for p in packages) if ln == "@PACKAGES@" else ln for ln in text.split("\n"))


def generate(text, variant, packages, module):
    """module is the certified Go Cryptographic Module, vX.Y.Z-<8 hex>, from the FIPS module data file: the generator holds no FIPS constant of its own"""
    fips = variant == "fips"
    name, desc = ("fscache-fips", "the cache server, built with the Go FIPS 140-3 module") if fips else ("fscache", "the cache server")
    export = "      export GOFIPS140=" + module.split("-")[0]
    # the proof is captured to a file and searched there: a pipe could end the first process early (SIGPIPE under pipefail) and fail a correct binary
    proof = "      go version -m ${{targets.destdir}}/usr/bin/fscache > /tmp/fscache-gobuildinfo.txt\n      grep -q 'GOFIPS140=%s' /tmp/fscache-gobuildinfo.txt" % module
    out = []
    for ln in text.split("\n"):
        if ln == "@PACKAGES@":
            out.extend("      - " + p for p in packages)
        elif ln == "@FIPS_EXPORT@":
            if fips:
                out.append(export)
        elif ln == "@FIPS_PROOF@":
            if fips:
                out.append(proof)
        else:
            out.append(ln.replace("@NAME@", name).replace("@DESCRIPTION@", desc))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default=os.path.join(ROOT, "build/melange.yaml.tmpl"))
    ap.add_argument("--regular", default=os.path.join(ROOT, "build/melange.yaml"))
    ap.add_argument("--fips", default=os.path.join(ROOT, "build/melange-fips.yaml"))
    ap.add_argument("--baselayout-template", default=os.path.join(ROOT, "build/melange-baselayout.yaml.tmpl"))
    ap.add_argument("--baselayout", default=os.path.join(ROOT, "build/melange-baselayout.yaml"))
    ap.add_argument("--melange-lock", default=os.path.join(ROOT, "build/locks/melange.lock"))
    ap.add_argument("--fips-module", default=os.path.join(ROOT, "build/locks/fips-module.txt"))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    g.add_argument("--emit", metavar="DIR", help="write the three generated recipes (melange.yaml, melange-fips.yaml, melange-baselayout.yaml) into DIR and nothing else (the daily job reads them from there)")
    a = ap.parse_args()
    text = read_template(a.template)
    bl_text = read_baselayout_template(a.baselayout_template)
    if os.path.abspath(a.regular) == os.path.abspath(a.fips):
        bad("--regular and --fips name the same file; refusing (one recipe would silently replace the other)", 2)
    packages, module = read_packages(a.melange_lock), read_fips_module(a.fips_module)
    want = {a.regular: generate(text, "regular", packages, module), a.fips: generate(text, "fips", packages, module),
            a.baselayout: generate_baselayout(bl_text, packages)}
    if a.emit:
        for fn, variant in (("melange.yaml", "regular"), ("melange-fips.yaml", "fips")):
            with open(os.path.join(a.emit, fn), "w", encoding="utf-8") as f:
                f.write(generate(text, variant, packages, module))
        with open(os.path.join(a.emit, "melange-baselayout.yaml"), "w", encoding="utf-8") as f:
            f.write(generate_baselayout(bl_text, packages))
        return
    if a.write:
        for path, content in want.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        return
    failed = False
    for path, content in want.items():
        try:
            have = open(path, "rb").read().decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            bad("cannot read %s: %s" % (path, e), 2)
        if have != content:
            failed = True
            print("gen-recipes: %s is not what the generator makes from the template:" % path, file=sys.stderr)
            print("\n".join(difflib.unified_diff(content.splitlines(), have.splitlines(), "generated", path, lineterm="", n=0)), file=sys.stderr)
    if failed:
        sys.exit(1)


main()
