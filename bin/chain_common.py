"""Small helpers shared by bin/chain-verify.py and bin/chain_hostile.py: the refusal, base64, the openssl call, strict JSON and
the clock. No policy lives here."""
import base64
import datetime as dt
import json
import os
import subprocess

OPENSSL = os.environ.get("OPENSSL", "openssl")


class Refuse(Exception):
    def __init__(self, stage, reason):
        super().__init__(reason)
        self.stage, self.reason = stage, reason


def refuse(stage, reason):
    raise Refuse(stage, reason)


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode()


def ssl(*args, inp=None, check=True):
    r = subprocess.run((OPENSSL,) + args, input=inp, capture_output=True)
    if check and r.returncode:
        raise RuntimeError("openssl %s failed: %s" % (" ".join(args[:2]), r.stderr.decode(errors="replace")[:200]))
    return r


def parse_now(s):
    if not s:
        return dt.datetime.now(dt.timezone.utc)
    for f in ("%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return dt.datetime.strptime(s, f).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    raise SystemExit("error: --now must be ISO 8601 UTC (YYYYmmddHHMMSSZ or YYYY-mm-ddTHH:MM:SSZ)")

def no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def strict_json(raw):
    """JSON in which a repeated key is an error: Python keeps the last one, other readers keep the first."""
    return json.loads(raw, object_pairs_hook=no_duplicate_keys)


def load_json(path, what):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as ex:
        raise Refuse("policy", "%s %s is missing or not JSON: %s" % (what, path, ex))
