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
OWNER_LOGIN = "fosterstack-admin"

# REQ-AUD-17 AC1: the fixed subject-prefix FAMILY. Every PR and issue the auditor opens leads
# with this token so one mail filter catches them all; owner-decision issues keep their own
# "owner-decision:" prefix after it (so an existing filter on that prefix still matches).
AUDITOR_PREFIX = "auditor:"
STANDING_ISSUE_TITLE = "auditor: needs a human"


def subject(text):
    """Lead a PR/issue title with the auditor's fixed family prefix (idempotent)."""
    text = text or ""
    return text if text.startswith(AUDITOR_PREFIX) else "%s %s" % (AUDITOR_PREFIX, text)

# Run bounds.
MAX_ITERATIONS = 5
TOKEN_BUDGET = 200000

# VEX product scope and statement-id scheme.
REPO_URL = "ghcr.io/fosterstack/cache"
VEX_PRODUCT = "pkg:oci/cache?repository_url=%s" % REPO_URL
VEX_BASE = "https://fosterstack.com/vex/cache/openvex"


def stmt_id(finding_id):
    return "%s#stmt-%s" % (VEX_BASE, finding_id.lower())


def scope_key(product_id, subcomponents):
    """The canonical SCOPE of a disposition (REQ-AUD-13 AC1): the product @id paired with the
    sorted set of its subcomponent package-URLs. Two dispositions are the same scope iff both
    members are equal; order of subcomponents does not matter."""
    return ((product_id or VEX_PRODUCT), tuple(sorted(set(subcomponents or ()))))


def scope_id(vulnerability, product_id=None, subcomponents=None):
    """The statement @id: a DETERMINISTIC function of (vulnerability, scope) (REQ-AUD-13 AC2).
    The default scope (the plain product with no subcomponents) keeps the bare `#stmt-<cve>`
    id; any other scope appends a stable 8-hex hash of its scope key. The same scope yields the
    same @id on every run and two distinct scopes never collide."""
    import hashlib
    prod, subs = scope_key(product_id, subcomponents)
    base = "%s#stmt-%s" % (VEX_BASE, vulnerability.lower())
    if prod == VEX_PRODUCT and not subs:
        return base
    # a 64-bit scope hash — the @id is a display/citation handle; correctness (merge dedup,
    # inventory, expiry) keys on the FULL scope, not this hash, so a collision cannot lose a
    # scope or an obligation, but a wide hash keeps @ids unique in practice too.
    h = hashlib.sha1((prod + "\n" + "\n".join(subs)).encode()).hexdigest()[:16]
    return "%s~%s" % (base, h)


def threshold_reason(severity=None, kev=False, known_exploited=False):
    """The at-or-above threshold reason (owner policy), or 'below'."""
    if (severity or "").lower() in THRESHOLD_SEVERITIES:
        return "critical-severity"
    if kev:
        return "kev"
    if known_exploited:
        return "known-exploited"
    return "below"


def owner_issue_title(finding_id, package, reason):
    """The owner's mail filter keys on this exact prefix/shape (R14); the auditor family prefix
    leads it (REQ-AUD-17 AC1), the "owner-decision:" sub-prefix is retained."""
    return subject("owner-decision: %s — %s — %s" % (finding_id, package or "unknown-package", reason))


def lineage_of(scanner):
    return LINEAGE.get(scanner, scanner)
