#!/usr/bin/env python3
"""Disposable POSIX/OpenSSH component checks. This does NOT execute XER Go.
No network, real user data or scheduler state is touched.
"""
from pathlib import Path
import argparse, json, os, shutil, subprocess, tempfile

def quote(s):return '"'+s.replace('\\','\\\\').replace('"','\\"')+'"'

def probes():
    rows=[]
    with tempfile.TemporaryDirectory(prefix='xer-release-probes-') as td:
        root=Path(td)
        if os.name=='posix':
            import fcntl
            victim=root/'unrelated';victim.write_bytes(b'')
            link=root/'symlink';link.symlink_to(victim)
            rejected=False
            try:fd=os.open(link,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
            except OSError:rejected=True
            else:os.close(fd)
            rows.append(dict(test='POSIX_NOFOLLOW_BEFORE_WRITE',status='PASS' if rejected and victim.read_bytes()==b'' else 'FAIL'))
            hard=root/'hardlink';os.link(victim,hard);fd=os.open(hard,os.O_RDWR|os.O_NOFOLLOW)
            try:rejected=os.fstat(fd).st_nlink!=1
            finally:os.close(fd)
            rows.append(dict(test='POSIX_HARDLINK_DETECT_BEFORE_WRITE',status='PASS' if rejected and victim.read_bytes()==b'' else 'FAIL'))
            lock=root/'lock';a=os.open(lock,os.O_CREAT|os.O_RDWR,0o600);b=os.open(lock,os.O_RDWR)
            fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB);busy=False
            try:fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:busy=True
            os.close(a);fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);os.close(b)
            rows.append(dict(test='POSIX_KERNEL_LOCK_RECOVERY',status='PASS' if busy else 'FAIL'))
            source=root/'part';source.write_bytes(b'new');dest=root/'dest';dest.write_bytes(b'keep')
            refused=False
            try:os.link(source,dest)
            except FileExistsError:refused=True
            rows.append(dict(test='POSIX_ATOMIC_NO_OVERWRITE',status='PASS' if refused and dest.read_bytes()==b'keep' else 'FAIL'))
            fd=os.open(root,os.O_RDONLY);os.fsync(fd);os.close(fd)
            rows.append(dict(test='POSIX_DIRECTORY_SYNC',status='PASS'))
        server=next((x for x in ['/usr/lib/openssh/sftp-server','/usr/lib/ssh/sftp-server','/usr/libexec/sftp-server'] if Path(x).is_file()),None)
        sftp=shutil.which('sftp')
        if sftp and server:
            for name in ['literal[1].txt','name with "quote".txt']:
                source=root/name;source.write_bytes(b'component round-trip\n');remote=root/'remote';dest=root/'copy'
                batch='put '+quote(str(source))+' '+quote(str(remote))+'\nget '+quote(str(remote))+' '+quote(str(dest))+'\n'
                p=subprocess.run([sftp,'-D',server,'-b','-'],input=batch,text=True,capture_output=True,timeout=10)
                correct=p.returncode==0 and dest.read_bytes()==source.read_bytes()
                rows.append(dict(test='LOCAL_OPENSSH_BATCH_ROUNDTRIP',path_case=name,status='PASS' if correct else 'FAIL',exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr))
        else:rows.append(dict(test='LOCAL_OPENSSH_BATCH_ROUNDTRIP',status='SKIP',reason='OpenSSH subsystem unavailable'))
    return rows
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--json');args=parser.parse_args();result=probes();data=json.dumps({'scope':'OS/OpenSSH components, NOT XER execution','results':result},indent=2)+'\n'
    if args.json:Path(args.json).write_text(data)
    print(data);raise SystemExit(any(r['status']=='FAIL' for r in result))
