# Source: independent second-gate review, audits/2026-09-22/cve-auditor-matrix-second-gatefirst-pass-inert/evidence/first-pass-inert.py
# Checked in verbatim as a TEST INPUT (adversary) for bin/auditor-matrix-mutants.sh. Not auditor code.
import json,sys
from pathlib import Path
name=Path(sys.argv[0]).stem
args=sys.argv[1:]
def flag(k): return args[args.index(k)+1]
out={}
if name=='auditor-classify':
    findings=json.load(open(flag('--run-state')))['findings']
    findings=[dict(f,artifact=f['expected_artifact']) for f in findings]
    out=next(f for f in findings if f['id']==flag('--finding-id')) if '--finding-id' in args else findings
elif name=='auditor-defectlog' and args[0]=='run':
    out={'total_model_calls':0}
elif name=='auditor-votes':
    out=[dict(cve=f['cve'],**f['expected']) for f in json.load(open(args[0]))['findings']]
elif name=='auditor-adjudicate':
    out=json.load(open(flag('--scenario')))
    out['attempt_order']=out['expected_attempt_order']
    out['emitted_exploit_code']=False
    out['deterministic_model_calls']=0
elif name=='auditor-report':
    p=Path(flag('--run-state'))
    if p.name=='scanner-down.json': print('trivy '+json.load(open(p))['run']['candidate_digests']['production'])
    elif p.name=='multi-category.json': print('\n'.join('## '+str(i) for i in range(1,8)))
    else: print(p.read_text())
    sys.exit(7)
print(json.dumps(out))
sys.exit(7)
