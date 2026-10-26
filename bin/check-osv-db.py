"""bin/check-osv-db.py CACHE ECOFILE NOW MAX_AGE: the databases bin/check-scan.sh's osv-scanner scans used (REQ-CHAIN-006-AC15). Reads the downloaded <ecosystem>/all.zip
files under CACHE and prints a JSON list of {ecosystem, db_source_url, db_source_basis, db_newest_record_modified, db_digest}; any fault exits 1."""
import datetime, hashlib, json, os, sys, zipfile
cache, ecofile, now, max_age = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
HOST = "https://osv-vulnerabilities.storage.googleapis.com"   # the only allowed osv database host
def fail(m):
    print("check-scan: " + m, file=sys.stderr); sys.exit(1)
ecos = {l.strip() for l in open(ecofile) if l.strip()}
zips = sorted(os.path.join(d, f) for d, _, fs in os.walk(cache) for f in fs if f == "all.zip")
if not zips:
    fail("no osv database zip in the cache after the run: osv-scanner scanned against no downloaded database")
have = {os.path.basename(os.path.dirname(z)) for z in zips}
for e in sorted(ecos):
    if e not in have and e.split(":")[0] not in have:
        fail("no osv database zip for the reported ecosystem %s (the cache holds %s): osv-scanner scanned it against no downloaded database" % (e, sorted(have)))
out = []
for z in zips:
    eco = os.path.basename(os.path.dirname(z))
    if eco not in ecos and not any(e.split(":")[0] == eco for e in ecos):
        fail("the osv database %s is for %s, not one the scan targets (the scans reported %s)" % (z, eco, sorted(ecos)))
    try:
        with zipfile.ZipFile(z) as zf:
            recs = [json.loads(zf.read(n)) for n in zf.namelist() if n.endswith(".json")]
    except (zipfile.BadZipFile, ValueError, OSError) as e:
        fail("the osv database for %s is unreadable: %s" % (eco, e))
    if not recs:
        fail("the osv database for %s holds no record" % eco)
    dated = []
    for r in recs:
        m = r.get("modified") if isinstance(r, dict) else None
        if isinstance(m, str):
            try:
                dated.append((datetime.datetime.fromisoformat(m.replace("Z", "+00:00")), m))
            except ValueError:
                pass
    if not dated:
        fail("the osv database for %s has no record with a readable modified date" % eco)
    t, newest = max(dated)
    if now - t.timestamp() > max_age:
        fail("the osv database for %s has its newest record modified %s, older than 48 hours: OSV records change constantly, so a stale "
             "newest modification means the database was not refreshed" % (eco, newest))
    out.append({"ecosystem": eco, "db_source_url": "%s/%s/all.zip" % (HOST, eco), "db_source_basis": "documented", "db_newest_record_modified": newest,
                "db_digest": "sha256:" + hashlib.sha256(open(z, "rb").read()).hexdigest()})
print(json.dumps(out))
