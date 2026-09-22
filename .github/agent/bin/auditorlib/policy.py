"""Auditor policy constants — the thresholds and tables the code applies exactly.
No vendor or model names live here; model ids come from the agent environment."""

# Vote lineage: which scanners share a vulnerability database lineage. Grype and
# Trivy both derive from the same advisory feeds and count as ONE anchore-aqua vote.
LINEAGE = {
    "grype": "anchore-aqua",
    "trivy": "anchore-aqua",
    "osv-scanner": "osv",
    "osv-scanner-gomod": "osv",
    "snyk": "snyk",
    "govulncheck": "go-vulndb",
}

# Risk-acceptance thresholds (owner policy). At or above any of these, an accepted
# reachable-no-fix item additionally opens an owner-decision issue.
THRESHOLD_SEVERITIES = {"critical"}          # Critical severity escalates
IGNORE_EXPIRY_DAYS = 30                       # per-scanner ignore lifetime

# Notification triggers (REQ-AUD-9 AC3) — the only conditions that reach a human.
NOTIFY_TRIGGERS = [
    "reachable-nofix-critical-kev-or-exploited",
    "unassessed-after-fallback",
    "five-iteration-stop",
    "fips-module-selection-failure",
    "behaviour-change-under-bump",
]
NOTIFY_CHANNEL = "owner-decision-issue"
OWNER_LABEL = "owner-decision"

# Run bounds.
MAX_ITERATIONS = 5
TOKEN_BUDGET = 200000

# VEX product scope and statement-id scheme.
REPO_URL = "ghcr.io/fosterstack/cache"
VEX_PRODUCT = "pkg:oci/cache?repository_url=%s" % REPO_URL
VEX_BASE = "https://fosterstack.com/vex/cache/openvex"


def stmt_id(finding_id):
    return "%s#stmt-%s" % (VEX_BASE, finding_id.lower())


def lineage_of(scanner):
    return LINEAGE.get(scanner, scanner)
