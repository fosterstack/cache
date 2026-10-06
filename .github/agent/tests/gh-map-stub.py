#!/usr/bin/env python3
# a gh stub for the offline tests: GH_MAP is a JSON file {api path: value}; --jq supports .field, .a.b and .[]; {"__b64": "..."} is a binary body; {"__err": "..."} fails
import base64, json, os, re, sys
a = sys.argv[1:]
if not a or a[0] != "api":
    sys.exit(1)
jq = a[a.index("--jq") + 1] if "--jq" in a else None
path = [x for x in a[1:] if not x.startswith("-") and x != jq][0]
m = json.load(open(os.environ["GH_MAP"]))
if path not in m:
    sys.stderr.write("gh: Not Found (HTTP 404)\n"); sys.exit(1)
v = m[path]
if isinstance(v, dict) and "__err" in v:
    sys.stderr.write(v["__err"] + "\n"); sys.exit(1)
if isinstance(v, dict) and "__b64" in v:
    sys.stdout.buffer.write(base64.b64decode(v["__b64"])); sys.exit(0)
if jq == ".[]":
    for x in v: print(json.dumps(x))
elif jq and re.fullmatch(r"\.\w+\[\]", jq):
    for x in v[jq[1:-2]]: print(json.dumps(x))
elif jq and jq.startswith("."):
    for k in jq[1:].split("."):
        v = v[k]
    print(v if isinstance(v, str) else json.dumps(v))
else:
    print(json.dumps(v))
