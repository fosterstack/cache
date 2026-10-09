#!/usr/bin/env bash
# The hostile Build step of the dry run (v0.3.0 rules 52a and 59; REQ-CHAIN-001-AC5). It runs as a step of the Build job, only when
# the dry run asks for it (`if: ${{ inputs.hostile }}`), and tries the six ways a Build step could reach Sign's signing identity.
# It writes only the RAW MATERIAL of each attempt (a file under attempts/) and never says whether an attempt worked: the verify
# job judges every attempt with the real verifier, so this step cannot grade itself.
#
#   attempt_mint_sign_cert                       ask Fulcio for a certificate and sign a provenance statement with it; the only
#                                                certificate this job can get names the Build stage file, never Sign's
#   attempt_read_sign_token                      look for Sign's identity token on this runner (Sign runs on another machine)
#   attempt_read_sign_key                        look for Sign's signing key material on this runner
#   attempt_hand_sign_code                       give Sign a digest list that carries code instead of digests
#   attempt_forge_provenance                     write provenance for different digests and sign it with this job's own identity
#   attempt_call_sign_from_other_workflow        a second workflow that calls stage-sign.yml at the tag: its record is made by a
#                                                throwaway workflow on the dry-run ref (never merged) and uploaded as hostile-caller
#
# The token and key attempts write a first line `# transcript: ...` (what was tried) and then the attempt's own output; a file
# without both is an error for the verifier, never a sign of isolation. No token or key is ever copied into the material: only
# the CLAIMS of this job's own token (header.payload., no signature) and the sha256 of the PUBLIC key of every key file found.
# Every file this step writes has a LITERAL path (the pin checker refuses a job that runs a committed file and also writes to a
# path it cannot place), so the work directory is the literal hostile-work/ in the workspace.
set -uo pipefail

mkdir -p attempts hostile-work

# this job's own identity token, reduced to header.payload. (no signature): enough to read its claims, useless as a token
own_claims() {
  [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || return 1
  local tok
  tok=$(curl -fsS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value) || return 1
  [ -n "$tok" ] || return 1
  printf '%s.%s.\n' "$(printf '%s' "$tok" | cut -d. -f1)" "$(printf '%s' "$tok" | cut -d. -f2)"
}

# statement BUILDER-ID: SLSA provenance (on stdout) for digests Build never attested, claiming the given builder
statement() {
  jq -n --arg b "$1" '{_type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1",
       subject: [{name: "image-production", digest: {sha256: "0000000000000000000000000000000000000000000000000000000000000000"}}],
       predicate: {buildDefinition: {buildType: "hostile", externalParameters: {}, internalParameters: {}, resolvedDependencies: []}, runDetails: {builder: {id: $b}}}}'
}

# forged_record STATEMENT-FILE: a DSSE envelope of the verify shape (on stdout) over that statement, signed with THIS job's own
# certificate (cosign signs the PAE bytes as a blob; the certificate it gets names stage-build.yml, never stage-sign.yml)
forged_record() {
  local pt="application/vnd.in-toto+json" pem
  [ -x hostile-work/cosign ] || bash bin/install-scanner.sh cosign hostile-work > /dev/null || return 1
  { printf 'DSSEv1 %d %s %d ' "${#pt}" "$pt" "$(wc -c < "$1")"; cat "$1"; } > hostile-work/pae.bin
  hostile-work/cosign sign-blob --yes --bundle hostile-work/forged.bundle.json hostile-work/pae.bin > /dev/null 2>&1 || return 1
  pem=$(jq -r '.verificationMaterial.certificate.rawBytes' hostile-work/forged.bundle.json | base64 -d | openssl x509 -inform DER) || return 1
  jq -n --arg pt "$pt" --arg payload "$(base64 < "$1" | tr -d '\n')" --arg sig "$(jq -r '.messageSignature.signature' hostile-work/forged.bundle.json)" \
        --arg cert "$(printf '%s\n' "$pem" | base64 | tr -d '\n')" \
        --argjson stamps "$(jq '[(.verificationMaterial.timestampVerificationData.rfc3161Timestamps // [])[] | {type: "tsp", data: .signedTimestamp}]' hostile-work/forged.bundle.json)" \
        '{payloadType: $pt, payload: $payload, signatures: [{keyid: "", sig: $sig, certificate: $cert, intermediates: [], timestamps: $stamps}]}'
}

attempt_mint_sign_cert() {
  statement "https://github.com/${GITHUB_REPOSITORY:-fosterstack/cache}/.github/workflows/stage-sign.yml@${GITHUB_REF:-refs/heads/dry-run}" > hostile-work/mint.json
  forged_record hostile-work/mint.json > hostile-work/mint-record.json && cp hostile-work/mint-record.json attempts/mint_sign_cert.json
  return 0
}

attempt_read_sign_token() {
  {
    echo "# transcript: searched /proc/*/environ for a token belonging to the sign job, then asked the runner for this job's own token"
    grep -l -a 'ACTIONS_ID_TOKEN_REQUEST' /proc/[0-9]*/environ 2> /dev/null | head -5 | sed 's#^#a process on this runner holds a token request address: #'
    # the claims of the token this job can get (no signature): the verifier reads job_workflow_ref from them. If no token can be
    # fetched there is nothing to grade and the verifier reports an error, so the dry run is red instead of vacuously green.
    claims=$(own_claims) && echo "claims: $claims"
  } > attempts/read_sign_token.txt
}

# Sign's key lives in cosign's memory on another VM; whatever key files this runner holds are not it unless their public key is the
# one in Sign's certificate. So the material is each key file's PUBLIC key hash (the private key is never copied) and the number
# of files searched (a search of nothing proves nothing); the verifier compares the hashes with Sign's certificate.
# The workspace is not searched: it holds this repository, whose test files contain key-shaped text.
attempt_read_sign_key() {
  local f
  {
    echo "# transcript: searched HOME, RUNNER_TEMP, /tmp and /dev/shm for private key files and recorded the sha256 of each one's public key"
    echo "searched: $(grep -rIl '' "${HOME:-/nonexistent}" "${RUNNER_TEMP:-/nonexistent}" /tmp /dev/shm 2> /dev/null | wc -l | tr -d ' ') files"
    for f in $(grep -rIl -e 'BEGIN [A-Z ]*PRIVATE KEY' "${HOME:-/nonexistent}" "${RUNNER_TEMP:-/nonexistent}" /tmp /dev/shm 2> /dev/null | head -50); do
      printf 'pubkey-sha256: %s\n' "$(openssl pkey -in "$f" -pubout -outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)"
    done
  } > attempts/read_sign_key.txt
}

attempt_hand_sign_code() {
  cat > attempts/hand_sign_code.json <<'EOF'
{"image-production":"sha256:$(touch attempts/ran-by-sign)","image-fips":"sha256:0000000000000000000000000000000000000000000000000000000000000000","apk;curl evil":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}
EOF
}

attempt_forge_provenance() {
  statement "https://github.com/${GITHUB_REPOSITORY:-fosterstack/cache}/.github/workflows/stage-build.yml@${GITHUB_REF:-refs/heads/dry-run}" > hostile-work/forge.json
  forged_record hostile-work/forge.json > hostile-work/forge-record.json && cp hostile-work/forge-record.json attempts/forge_provenance.json
  return 0
}

# The record comes from a throwaway second workflow that calls stage-sign.yml on this ref; without it this attempt did not run, and
# a dry run that skipped an attempt must be red, not green.
attempt_call_sign_from_other_workflow() {
  if [ ! -f hostile-caller/record.json ]; then
    echo "attempt_call_sign_from_other_workflow: hostile-caller/record.json is missing: the throwaway second-caller workflow did not run on this ref" >&2
    return 1
  fi
  cp hostile-caller/record.json attempts/call_sign_from_other_workflow.json
}

attempt_mint_sign_cert
attempt_read_sign_token
attempt_read_sign_key
attempt_hand_sign_code
attempt_forge_provenance
attempt_call_sign_from_other_workflow
