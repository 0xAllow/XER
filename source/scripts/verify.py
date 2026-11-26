#!/usr/bin/env python3
"""Run real Go verification, recording failures and blocked checks honestly.
No scheduler is installed, no external transfer endpoint is contacted.
Go/scanner may download their own tools or public vulnerability metadata.
"""
import argparse, json, os, pathlib, re, shutil, subprocess, tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--output',default='verification-results.json')
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
results=[]
def run(command,env=None,timeout=300):
    try:
        p=subprocess.run(command,cwd=root,env=env,capture_output=True,text=True,timeout=timeout)
        return dict(command=command,status='PASS' if p.returncode==0 else 'FAIL',exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)
    except (OSError,subprocess.TimeoutExpired) as e:
        return dict(command=command,status='BLOCKED' if isinstance(e,OSError) else 'TIMEOUT',error=str(e))
go=os.environ.get('XER_GO_BINARY') or shutil.which('go')
version=run([go,'version']) if go else dict(command=['go','version'],status='BLOCKED',error='Go SDK missing')
if version.get("status")!="PASS": version["status"]="BLOCKED"
results.append(version)
match=re.match(r'^go version go(\d+)\.(\d+)\.(\d+)',version.get('stdout',''))
valid=version.get('status')=='PASS' and bool(match) and tuple(map(int,match.groups()))>=(1,27,4)
commands=[['build','./...'],['test','-count=1','-timeout=5m','./...'],['test','-race','-count=1','-timeout=5m','./...'],['vet','./...'],['test','-cover','-timeout=5m','./...']]
for command in commands:
    row=run([go]+command) if valid else dict(command=['go']+command,status='BLOCKED',reason='Go SDK 1.27.4+ is unavailable; the discovered go command is not a suitable SDK')
    results.append(row)
scanner=shutil.which('govulncheck')
results.append(run([scanner,'./...']) if valid and scanner else dict(command=['govulncheck','./...'],status='BLOCKED',reason='scanner or Go SDK unavailable'))
if valid:
    with tempfile.TemporaryDirectory(prefix='xer-cross-') as build_dir:
        for target in ['linux/amd64','linux/arm64','windows/amd64','darwin/amd64','darwin/arm64']:
            goos,arch=target.split('/');env=dict(os.environ,GOOS=goos,GOARCH=arch,CGO_ENABLED='0')
            row=run([go,'build','-trimpath','-o',str(pathlib.Path(build_dir)/target.replace('/','-')),'.'],env)
            row['target']=target;results.append(row)
else:
    results.append(dict(command=['go','build','cross-platform matrix'],status='BLOCKED',reason='Go SDK unavailable'))
output=pathlib.Path(args.output).resolve();output.write_text(json.dumps(results,indent=2)+'\n')
for row in results:print(row['status'], ' '.join(row['command']))
raise SystemExit(0 if all(r['status']=='PASS' for r in results) else 2)
