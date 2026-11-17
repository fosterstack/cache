#!/usr/bin/env python3
"""The two offline halves of signing a patch tag with the one release KMS key (REQ-REL-009-AC5, AC6).

`prepare` writes the unsigned annotated tag object and the sha256 of the OpenSSH signed-data blob over
it: the digest the KMS key signs (RSASSA-PKCS1-v1_5 SHA-256), which is what the
rsa-sha2-256 signature of an SSH SIGNATURE block is. `assemble` puts the key and that signature into the block and
appends it to the object. Only a patch tag vX.Y.Z with Z >= 1 is made: the admission of a tag accepts the release key on
no other tag. Nothing is written when a check fails.
"""
import argparse, base64, hashlib, os, re, struct, sys

PATCH = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.[1-9][0-9]*")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")     # DER prefix of a SHA-256 DigestInfo


def s(b):
    return struct.pack(">I", len(b)) + b


def fields(b):
    out, o = [], 0
    while o < len(b):
        n = struct.unpack(">I", b[o:o + 4])[0]
        out.append(b[o + 4:o + 4 + n])
        o += 4 + n
    return out


def signed_data(obj):
    return b"SSHSIG" + s(b"git") + s(b"") + s(b"sha256") + s(hashlib.sha256(obj).digest())


def write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def prepare(a):
    if not PATCH.fullmatch(a.tag):
        sys.exit("tag-sign: %r is not a patch tag vX.Y.Z with Z >= 1" % a.tag)
    if not COMMIT.fullmatch(a.commit):
        sys.exit("tag-sign: %r is not a full commit sha" % a.commit)
    if "\n" in a.tagger:
        sys.exit("tag-sign: the tagger is one line")
    with open(a.notes, "rb") as fh:
        notes = fh.read()
    obj = ("object %s\ntype commit\ntag %s\ntagger %s %d +0000\n\n" % (a.commit, a.tag, a.tagger, a.time)).encode() + notes
    write(a.object, obj)
    write(a.digest, (hashlib.sha256(signed_data(obj)).hexdigest() + "\n").encode())


def rsa_key(path):
    with open(path) as fh:
        parts = fh.read().split()
    if len(parts) < 3 or parts[1] != "ssh-rsa":
        sys.exit("tag-sign: %s holds no ssh-rsa key" % path)
    blob = base64.b64decode(parts[2])
    kind, e, n = fields(blob)
    return blob, int.from_bytes(e, "big"), int.from_bytes(n, "big")


def assemble(a):
    blob, e, n = rsa_key(a.signer_file)
    with open(a.object, "rb") as fh:
        obj = fh.read()
    with open(a.signature, "rb") as fh:
        sig = fh.read()
    k = (n.bit_length() + 7) // 8
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(SHA256_INFO) - 32) + b"\x00" + SHA256_INFO \
        + hashlib.sha256(signed_data(obj)).digest()
    if len(sig) != k or pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big") != want:
        sys.exit("tag-sign: the signature is not the key's signature of this tag")
    body = b"SSHSIG" + struct.pack(">I", 1) + s(blob) + s(b"git") + s(b"") + s(b"sha256") + s(s(b"rsa-sha2-256") + s(sig))
    b64 = base64.b64encode(body).decode()
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    block = "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"
    write(a.out, obj + block.encode())


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("prepare")
    for k in ("tag", "commit", "notes", "tagger", "object", "digest"):
        q.add_argument("--" + k, required=True)
    q.add_argument("--time", type=int, required=True)
    q.set_defaults(run=prepare)
    q = sub.add_parser("assemble")
    for k in ("object", "signature", "signer-file", "out"):
        q.add_argument("--" + k, required=True)
    q.set_defaults(run=assemble)
    a = p.parse_args(argv)
    try:
        a.run(a)
    except OSError as e:
        sys.exit("tag-sign: %s" % e)


if __name__ == "__main__":
    main(sys.argv[1:])
