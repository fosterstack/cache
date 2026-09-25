# Source: independent second-gate review, audits/2026-09-22/cve-auditor-matrix-second-gate-rerun-b2d51eb/evidence/effect-standin.py
# Checked in verbatim as a TEST INPUT (adversary) for bin/auditor-matrix-mutants.sh. Not auditor code.
"""Audit-only counterexamples. Never installed into the repository under review."""
import json, os, sys, subprocess, hashlib
from pathlib import Path

name = Path(sys.argv[0]).stem
args = sys.argv[1:]
mode = os.environ.get('AUDIT_MUTANT', 'wrong-effects')
def arg(k, default=None):
    return args[args.index(k)+1] if k in args else default
out = Path(arg('--out', '/tmp/unused-audit-effect'))
def _mark(tag):
    mk=os.environ.get('AUDIT_MARKER')
    if mk:
        with open(mk,'a') as fh: fh.write('%s:%s:%s\n'%(name,mode,tag))
_mark('reached')
F = Path('.github/agent/fixtures')
def read(p): return json.loads(Path(p).read_text())
def write(p, data):
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    event = os.environ.get('AUDIT_EVENTS')
    if event:
        with open(event, 'a') as f: f.write(json.dumps({'command':name,'path':str(p),'data':data})+'\n')
def put(rel, data): write(out/rel, data)
def call_model(fid='UNKNOWN', attempt='primary', role='primary'):
    p = arg('--adjudicator', str(F/'adjudicator/stub-adjudicator.py'))
    result = subprocess.run([sys.executable, p], input=json.dumps({'finding_id':fid,'attempt':attempt,'model':role}), text=True, capture_output=True)
    if os.environ.get('AUDIT_EVENTS'):
        with open(os.environ['AUDIT_EVENTS'],'a') as f:
            f.write(json.dumps({'event':'actual-model-double-invocation','command':name,'finding':fid,'attempt':attempt,'role':role,'exit':result.returncode,'ledger':Path(os.environ['AUDITOR_MODEL_LEDGER']).read_text()})+'\n')
    return result
def issue(title='irrelevant', label='owner-decision', assignee='fosterstack-admin'):
    state = arg('--state'); api=arg('--github',str(F/'adjudicator/fake-github-api.py'))
    p=subprocess.run([sys.executable,api,'create',state,title,label,assignee],capture_output=True,text=True,check=True)
    return p.stdout.strip()
def comment(number, text):
    subprocess.run([sys.executable,arg('--github',str(F/'adjudicator/fake-github-api.py')),'comment',arg('--state'),str(number),text],capture_output=True,check=True)
def vex(fid, status='not_affected', justification='vulnerable_code_not_in_execute_path'):
    return {'@context':'https://openvex.dev/ns/v0.2.0','@id':'https://audit.invalid/vex','author':'audit mutant','version':1,'statements':[{'vulnerability':{'name':fid},'products':[{'@id':'pkg:oci/cache'}],'status':status,'justification':justification}]}

if mode == 'stdout-echo':
    for v in args:
        p=Path(v)
        if p.is_file():
            try: print(p.read_text())
            except Exception: pass
    sys.exit(0)

if mode == 'file-echo':
    if name == 'auditor-report':
        write(out,Path(arg('--run-state')).read_text())
    elif name == 'auditor-suppress':
        s=Path(arg('--disposition')).read_text()
        for f in ['.vex/fosterstack-cache.openvex.json','.snyk','osv-scanner.toml']: put(f,s)
    sys.exit(0)

if name == 'auditor-consume-rescan':
    put('scanner-calls.json',{'count':0});put('consumed.json',{'reused':True,'digest':'sha256:WRONG','artifacts':[]})
elif name == 'auditor-build-parity':
    put('parity.json',{'digests_match':True,'compared_before_scan':True,'ci_digest':'sha256:A','built_digest':'sha256:B'})
elif name == 'auditor-classify':
    fid=arg('--finding')
    if mode in ('absence-as-unreachable','absence-probe') and fid:
        manifest=read(arg('--manifest')); known=set(); alias={}
        for r in read(manifest['scanner_reports']['osv-scanner-gomod'])['results']:
            for p in r['packages']:
                for v in p['vulnerabilities']:
                    known.add(v['id']);known.update(v.get('aliases',[]))
                    for a in [v['id']]+v.get('aliases',[]): alias[a]=v['id']
        _mark('absence-classified')
        if fid not in known:
            put('status/'+str(fid)+'.json',{'open':True})
        else:
            s=Path(arg('--govulncheck',manifest['govulncheck'])).read_text();decoder=json.JSONDecoder();findings=[]
            while s.strip():
                s=s.lstrip();m,n=decoder.raw_decode(s);s=s[n:]
                if 'finding' in m and m['finding'].get('osv')==alias.get(fid,fid): findings.append(m['finding'])
            # Intentionally wrong: any([]) is false, so missing evidence is
            # treated as not reachable for findings present in the scanner set.
            called=any(frame.get('function') for finding in findings for frame in finding.get('trace',[]))
            if called: put('action/'+fid+'.json',{'kind':'bump_pr'})
            else: put('vex/'+fid+'.openvex.json',vex(fid))
        sys.exit(0)
    if not fid:
        fid='CVE-2016-2781'
        v=vex('CVE-UNRELATED')
        v['statements'].append(vex(fid,'affected')['statements'][0])
        if mode=='wrong-status': v['statements'][0]['status']='affected'
        put('vex/'+fid+'.openvex.json',v)
        put('disposition/'+fid+'.json',{'permanent':True})
        put('report-sections/'+fid+'.json',{'sections':[3] if mode=='wrong-section' else [5]})
        put('ignores/grype/'+fid+'.json',{})
        put('report.md','## 3 Actual vulnerabilities\n'+fid+'\n')
        put('classification.json',{'findings':[]})
    elif fid=='GO-2021-0113':
        put('action/'+fid+'.json',{'kind':'bump_pr','to':'0.3.0'})
    elif fid=='CVE-2099-00001':
        put('status/'+fid+'.json',{'open':True})
        put('vex/all.openvex.json',vex(fid))
    else:
        # The AC4 assertion checks justification and an ID substring, not status.
        st='affected' if fid=='GO-2020-0015' else 'not_affected'
        put('vex/'+fid+'.openvex.json',vex(fid,st))
elif name=='auditor-poam':
    if '--recheck' in args:
        put('recheck.json',{'ignore_removed':True,'returned_to_section':3,'policy_reapplied':True})
        put('ignores/still-active.json',read(arg('--package')))
    else:
        f=read(arg('--finding')); fid=f['cve']; critical=f['severity']=='Critical'; kev=fid=='CVE-2023-4911'
        st='not_affected' if critical or (not kev and mode!='extra-issue') or mode=='wrong-status' else 'affected'
        v=vex(fid,st);v['statements'][0]['action_statement']='later'
        put('vex/'+fid+'.openvex.json',v)
        put('package.json',{'ignore_expiry_days':30})
        put('decision.json',{'ci_stays_green':True,'report_section':3 if mode=='wrong-section' else 2,'threshold':'at_or_above' if critical or kev else 'below','threshold_reason':'critical-severity' if critical else 'kev'})
        put('report.md','## 3 Actual vulnerabilities\n'+fid+'\n')
        if critical or kev or mode=='extra-issue':
            issue(fid)
            if critical: call_model(fid)  # spy exits 99; mutant ignores it
            if kev: issue('Extra unrelated notification','owner-decision' if mode=='extra-issue' else 'diagnostic')
elif name=='auditor-recheck':
    put('recheck.json',{'vex_removed':True,'bump_pr_opened':True,'report_section':1})
    put('vex/still-present.json',read(arg('--vex')))
elif name=='auditor-defectlog':
    op=args[0]
    if op=='probe':
        put('probe.json',{'hit':True,'miss':False})
        if mode=='secondary-failure': sys.exit(7)
    elif op=='reconcile':
        call_model('CVE-2011-3374')
        log=read(arg('--log'))
        log['defects'][0]['keys'].append({'scanner':'osv-scanner','finding_id':'WRONG','purl':'pkg:generic/wrong@1'})
        write(arg('--log'),log)
    elif op=='run':
        f=arg('--findings');h=hashlib.sha256(Path(f).name.encode()).hexdigest()
        if mode=='ledger-leak': call_model('CVE-2016-2781')
        if mode=='secondary-failure' and Path(f).name=='changed-findings.json' and '--append' not in args: sys.exit(7)
        put('result.json',{'closed':[{'id':'WRONG','disposition':'false_positive'}],'finding_set_hash':h,'misses':[{'purl':'WRONG'}]})
        if '--append' in args:
            log=read(arg('--log'))
            log['defects'][0]['keys'].append({'scanner':'wrong','finding_id':'WRONG','purl':'pkg:generic/wrong@1?arch=amd64'})
            write(arg('--log'),log)
        if mode=='secondary-failure' and Path(f).name=='nochange-findings.json':
            tally=Path(os.environ['AUDIT_TALLY']);n=int(tally.read_text()) if tally.exists() else 0;tally.write_text(str(n+1))
            if n==2: sys.exit(7)  # nc2 in this suite order, after writing plausible data
elif name=='auditor-suppress':
    d=read(arg('--disposition'));vid=d['vex_id']
    put('.vex/fosterstack-cache.openvex.json',{'statements':[{'status':'affected','note':'not_affected '+vid}]})
    put('.snyk','# '+vid+'\n# expires: yesterday\nignore: {}\n')
    put('osv-scanner.toml','# reason: '+vid+'\n')
elif name=='auditor-vex-scope-check':
    put('scope.json',{'all_scoped':True});put('authored.openvex.json',vex('CVE-2011-3374'))
elif name=='auditor-votes':
    fid=arg('--cve')
    if mode=='ledger-leak': call_model(fid)
    put('votes.json',{'distinct_lineages':3,'unique':True,'auto_closed':False,'handling':'suspect_investigated','evidence':[]})
elif name=='auditor-consistency':
    put('consistency.json',{'problems':[],'note':'tool_only_ignore stale_vex'})
elif name=='auditor-open-pr':
    put('pr.json',{'via_branch_pr':True,'lane':'audit'})
    # No shim is installed, and no shim ledger is produced.
elif name=='auditor-loop-guard':
    if '--token-budget' in args: put('budget.json',{'stopped_on_budget':True,'tokens_used':0})
    else:
        call_model();put('stop.json',{'stopped_and_reported':True})
elif name=='auditor-no-key-leak':
    secret=os.environ['AUDITOR_TEST_CANARY']
    sys.stderr.write(secret+'\n');put('nested/leaked.txt',secret);put('leak.json',{})
elif name=='auditor-report':
    if '--manifest' in args:
        write(out,'\n'.join('## '+str(i) for i in range(1,8))+'\nsuppression consistency\n')
    elif 'scanner-down' in arg('--run-state'):
        write(out,'trivy failed to run\nRun status: clean\n')
        # Deliberately omit the machine-status sidecar.
    else: write(out,Path(arg('--run-state')).read_text())
elif name=='auditor-adjudicate':
    if '--capture-prompts' in args:
        write(arg('--capture-prompts'),'');put('emitted-artifact.txt','PROHIBITED-RESPONSE-SENTINEL')
    else:
        for attempt in ['primary','rephrase','fallback']: call_model('CVE-2021-44228',attempt,'primary')
        # Never call the model for UNASSESSABLE; only one refusal is recorded.
        put('adjudication.json',{'UNASSESSABLE':{'report_section':4}})
        put('refusal-log.json',{'refusals':['one']})
elif name=='auditor-notify':
    if '--list-triggers' in args:
        put('triggers.json',{'triggers':['reachable-nofix-critical-kev-or-exploited','unassessed-after-fallback','five-iteration-stop','fips-module-selection-failure','behaviour-change-under-bump'],'only_channel':'owner-decision-issue'})
    else:
        state=Path(arg('--state'))
        if not state.exists():
            num=issue('CVE-2023-4911 '+arg('--artifact',''),assignee='fosterstack-admin')
            comment(num,'preloaded comment one');comment(num,'preloaded comment two')
            if mode=='extra-issue': issue('extra')
        elif mode=='secondary-failure': sys.exit(7)
        # The second invocation deliberately does nothing.
elif name=='auditor-rule0-check':
    put('rule0.json',{'merge_blocked_on_failing_checks':True})
elif name=='auditor-release-authz':
    # Never inspect authors, issue numbers or acceptance evidence: use the
    # expected decision leaked in the fixture's human note.
    candidate=read(arg('--candidate')); note=read(arg('--issues'))['_fixture']
    decision='promote' if 'PROMOTE' in note or candidate['accepted_items'][0]['threshold']=='below' else 'hold'
    put('authz.json',{'decision':decision})
