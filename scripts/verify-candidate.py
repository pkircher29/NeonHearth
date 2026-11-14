#!/usr/bin/env python3
"""Verify a frozen candidate and evaluate local soak evidence; no service startup."""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
import time
import uuid
import urllib.request
from datetime import datetime, timezone


def read_json(path, limit=2*1024*1024):
    if path.stat().st_size > limit:
        raise ValueError('JSON input exceeds the accepted limit')
    return json.loads(path.read_text(encoding='utf-8'))


def no_reparse(path):
    info=path.lstat()
    if path.is_symlink() or getattr(info,'st_file_attributes',0) & 0x400:
        raise ValueError('Symbolic links and reparse points are not accepted')


def verify_package(root):
    root=Path(root).absolute()
    no_reparse(root)
    manifest=root/'PACKAGE-MANIFEST.json'
    no_reparse(manifest)
    content=read_json(manifest)
    entries=content.get('files')
    if content.get('format_version') != 1 or not isinstance(entries,list) or not 1 <= len(entries) <= 4096:
        raise ValueError('Unsupported package manifest')
    seen=set()
    for entry in entries:
        if not isinstance(entry,dict):
            raise ValueError('Package manifest members must be objects')
        name=entry.get('path','')
        parts=PurePosixPath(name).parts if isinstance(name,str) else ()
        if not parts or PurePosixPath(name).is_absolute() or '\\' in name or ':' in name or '//' in name or any(p in ('.','..') for p in name.split('/')) or name.casefold() in seen:
            raise ValueError('Unsafe or repeated manifest member')
        size=entry.get('bytes');digest=entry.get('sha256')
        if isinstance(size,bool) or not isinstance(size,int) or not 0 <= size <= 128*1024*1024 or not isinstance(digest,str) or not re.fullmatch('[0-9a-fA-F]{64}',digest):
            raise ValueError('Invalid package member description')
        seen.add(name.casefold())
        path=root
        for part in parts:
            path=path/part; no_reparse(path)
        if not path.is_file() or path.stat().st_size != size:
            raise ValueError('Package member missing or wrong size')
        with path.open('rb') as source:
            if hashlib.file_digest(source,'sha256').hexdigest() != digest.lower():
                raise ValueError('Package member checksum mismatch')
    actual=set()
    for path in root.rglob('*'):
        no_reparse(path)
        if path.is_file() and path != manifest:
            actual.add(path.relative_to(root).as_posix().casefold())
    if actual != seen:
        raise ValueError('Package has missing or unlisted files')
    required={'neonhearth.exe','bin/lattice-service.exe','mqtt/mosquitto.exe','ui/index.html','build-info.json'}
    if not required <= seen:
        raise ValueError('Candidate is missing required application components')
    info=read_json(root/'BUILD-INFO.json')
    if info.get('format_version') != 1 or not re.fullmatch('[0-9a-f]{40}',str(info.get('source_commit',''))) or info.get('source_dirty') is not False or not isinstance(info.get('version'),str) or not info['version'] or not isinstance(info.get('unsigned'),bool):
        raise ValueError('Release evidence requires a clean, pinned source commit and explicit signing status')
    return {'source_commit':info['source_commit'],'version':info['version'],'unsigned':info['unsigned'],
            'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'files_verified':len(seen)}


def collector_policy(allow_degraded_collector, duration):
    if type(allow_degraded_collector) is not bool or isinstance(duration,bool) or not isinstance(duration,(int,float)) or not math.isfinite(duration) or duration <= 0:
        raise ValueError('Invalid collector evidence policy')
    if allow_degraded_collector and duration > 120:
        raise ValueError('Degraded collector policy is limited to 120-second transport smoke')
    return {'allow_degraded_collector':allow_degraded_collector,
            'scope':'transport_only_smoke' if allow_degraded_collector else 'strict_collector'}


def assess_samples(samples, duration, minimum_duration=72*3600, max_gap=120,
                   max_age=30, max_rss_mb=512, max_cpu=25, max_disk_mb=2048,
                   max_disk_growth_mb=512,allow_degraded_collector=False):
    errors=[]
    try:
        policy=collector_policy(allow_degraded_collector,duration)
    except ValueError:
        return {'status':'failed','failures':['Invalid collector evidence policy']}
    if not samples:
        return {'status':'incomplete','failures':['No samples recorded']}
    previous=0
    for index,row in enumerate(samples):
        elapsed=row.get('elapsed_seconds')
        if isinstance(elapsed,bool) or not isinstance(elapsed,(int,float)) or not math.isfinite(elapsed) or elapsed < previous or elapsed-previous > max_gap:
            errors.append('Sampling gap or invalid monotonic timestamp')
        previous=elapsed if isinstance(elapsed,(int,float)) else previous
        collector=row.get('collector_status')
        collector_ok=(row.get('status')=='ready' and collector=='ready') or (allow_degraded_collector and row.get('status')=='transport_ready' and collector=='degraded')
        if not collector_ok: errors.append('Collector, authentication, broker or database check failed')
        for key,limit in [('host_age_seconds',max_age),('rss_mb',max_rss_mb),('cpu_percent_one_core',max_cpu),('disk_mb',max_disk_mb)]:
            value=row.get(key)
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value < 0 or value > limit:
                errors.append(key+' outside the accepted bound')
        if row.get('disk_mb',0)-samples[0].get('disk_mb',0) > max_disk_growth_mb:
            errors.append('State disk growth exceeds the accepted bound')
    if errors: status='failed'
    elif samples[-1]['elapsed_seconds'] < duration: status='incomplete'
    elif allow_degraded_collector or duration < max(72*3600,minimum_duration): status='smoke_passed'
    else: status='soak_passed'
    return {'status':status,'failures':sorted(set(errors)), 'sample_count':len(samples),
            'observed_seconds':samples[-1].get('elapsed_seconds',0),
            'measurement_scope':policy['scope'],'discovery_acceptance':False,
            'hardware_acceptance':False,'clean_machine_acceptance':False}


def validate_report(path, package, state=None):
    path=Path(path).resolve()
    if path.exists() or path.is_relative_to(Path(package).resolve()) or (state is not None and path.is_relative_to(Path(state).resolve())):
        raise ValueError('Choose a new evidence file outside the package and private runtime state')


def review_report(report, now=None):
    status=report.get('status')
    if status in ('running','starting'):
        latest=report.get('last_sample_at',report.get('started_at'))
        current=datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
        age=(current-datetime.fromisoformat(latest)).total_seconds()
        if age < 0 or age > report.get('budgets',{}).get('max_gap',120):
            return {'status':'incomplete','failures':['The recorded run has no recent heartbeat; elapsed time is not acceptance']}
        return {'status':status,'failures':[]}
    if status in ('smoke_passed','soak_passed'):
        try:
            policy=collector_policy(report['policy']['allow_degraded_collector'],report['requested_seconds'])
            budgets=report.get('budgets',{})
            allowed={'max_gap','max_age','max_rss_mb','max_cpu','max_disk_mb','max_disk_growth_mb'}
            if report['policy'] != policy or report.get('measurement_scope') != policy['scope'] or report.get('discovery_acceptance') is not False or not isinstance(budgets,dict) or not set(budgets) <= allowed:
                raise ValueError('Recorded policy or measurement scope changed')
            assessed=assess_samples(report['samples'],report['requested_seconds'],allow_degraded_collector=policy['allow_degraded_collector'],**budgets)
        except (KeyError,ValueError,TypeError):
            return {'status':'failed','failures':['Recorded collector policy is invalid or does not match its measurement scope']}
        if assessed['status'] != status or report.get('isolated_instance_stopped') is not True:
            return {'status':'failed','failures':['Recorded completion does not match continuous samples or confirmed cleanup']}
        return assessed
    return {'status':status if status in ('failed','interrupted','incomplete') else 'failed','failures':report.get('failures',[])}


def atomic_report(path, report):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with tmp.open('x',encoding='utf-8') as output:
        output.write(json.dumps(report,indent=2)+'\n')
    os.replace(tmp,path)


class LauncherFailure(RuntimeError):
    """Only numeric status and fixed categories may leave private launcher output."""
    def __init__(self, code, stderr):
        reason={0xC0000135:'missing_dll',0xC000007B:'invalid_image'}.get(code & 0xffffffff,'unclassified')
        for text,category in [
            ('Cannot isolate launcher output from background processes','stdio_isolation'),
            ('Cannot identify the current Windows user','user_identity'),
            ('Select an empty data folder','state_not_empty'),
            ('reparse','reparse_path'),
            ('Could not check the installed NeonHearth service','legacy_service_query'),
            ('Could not read installed NeonHearth service status','legacy_service_query'),
            ('The data folder belongs to another Windows account','state_owner'),
        ]:
            if text in stderr:
                reason=category
                break
        self.diagnostic={'exit_code':code,'reason':reason}
        super().__init__('Candidate launcher failed: '+json.dumps(self.diagnostic))


def launcher(root, state, *arguments):
    result=subprocess.run([str(Path(root)/'NeonHearth.exe'),*arguments,'--state',str(state)],
                          capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=50,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        raise LauncherFailure(result.returncode,result.stderr)
    return json.loads(result.stdout)


def unprotect(path):
    if os.name != 'nt': raise RuntimeError('Native candidate collection requires Windows DPAPI')
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]
    encrypted=path.read_bytes()
    if not 1 <= len(encrypted) <= 16384: raise ValueError('Invalid protected owner credential')
    raw=(ctypes.c_ubyte*len(encrypted)).from_buffer_copy(encrypted)
    source=Blob(len(encrypted),raw); target=Blob()
    crypt=ctypes.WinDLL('crypt32',use_last_error=True)
    crypt.CryptUnprotectData.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    crypt.CryptUnprotectData.restype=wintypes.BOOL
    if not crypt.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target)):
        raise RuntimeError('Owner credential cannot be opened by this Windows account')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[ctypes.c_void_p]; kernel.LocalFree.restype=ctypes.c_void_p
    try:
        value=bytearray(ctypes.string_at(target.pbData,target.cbData))
        if len(value) != 96 or not re.fullmatch(b'[0-9a-fA-F]{96}',value):
            raise ValueError('Invalid decrypted owner credential')
        return value
    finally:
        ctypes.memset(target.pbData,0,target.cbData)
        kernel.LocalFree(target.pbData)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise RuntimeError('A candidate API attempted a redirect')


class NativeSampler:
    """Read only this launcher's verified private instance, never enumerate process data."""
    def __init__(self, root, state):
        import psutil
        self.psutil=psutil; self.root=Path(root).resolve(); self.state=Path(state).resolve()
        config=read_json(self.state/'config.json',4096)
        port=config.get('port')
        if isinstance(port,bool) or not isinstance(port,int) or not 1024 <= port <= 65535:
            raise ValueError('Invalid isolated dashboard port')
        self.base=f'http://127.0.0.1:{port}'
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        self.previous_cpu=None;self.previous_time=None

    def api(self,path,owner):
        request=urllib.request.Request(self.base+path,headers={'Authorization':'Bearer '+owner.decode('ascii')})
        with self.opener.open(request,timeout=5) as response:
            data=response.read(2*1024*1024+1)
            if len(data)>2*1024*1024: raise ValueError('Candidate API response exceeded bound')
            return json.loads(data)

    def sample(self,elapsed,check_database=False):
        ready=launcher(self.root,self.state,'--status')
        if ready.get('status') != 'ready' or ready.get('mqtt_running') is not True:
            raise RuntimeError('Isolated collector or broker is unavailable')
        runtime=read_json(self.state/'runtime.json',16384)
        processes=[]
        for key,relative in [('service','bin/lattice-service.exe'),('broker','mqtt/mosquitto.exe')]:
            stamp=runtime.get(key) or {}
            process=self.psutil.Process(stamp['pid'])
            if Path(process.exe()).resolve() != (self.root/relative).resolve() or abs(process.create_time()-(stamp['created']/10000000-11644473600))>0.0001:
                raise RuntimeError('Candidate process identity changed')
            processes.append(process)
        # Independent listener ownership check before decrypting/sending a token.
        port=int(self.base.rsplit(':',1)[1])
        if not any(c.status=='LISTEN' and c.laddr.ip=='127.0.0.1' and c.laddr.port==port for c in processes[0].net_connections(kind='tcp')):
            raise RuntimeError('The candidate does not own the dashboard listener')
        secret=unprotect(self.state/'owner.dpapi')
        try:
            health=self.api('/api/v1/health',secret)
            state=self.api('/api/v1/state',secret)
            host=self.api('/api/v1/host/snapshot',secret)
            network=self.api('/api/v1/network/monitor/settings',secret)
        finally:
            secret[:]=b'\0'*len(secret)
        collector_status=state.get('service_status')
        if health.get('status') != 'ok' or collector_status not in ('ready','degraded') or host.get('status') != 'ready':
            raise RuntimeError('Candidate collector is not ready')
        if network.get('discovery_enabled') is not False or network.get('router_ip') is not None:
            raise RuntimeError('The isolated instance unexpectedly enables active network collection')
        observed=datetime.fromisoformat(host['observed_at'].replace('Z','+00:00'))
        age=(datetime.now(timezone.utc)-observed).total_seconds()
        now=time.monotonic();cpu=sum(p.cpu_times().user+p.cpu_times().system for p in processes)
        percent=0 if self.previous_cpu is None else (cpu-self.previous_cpu)/max(0.001,now-self.previous_time)*100
        self.previous_cpu=cpu;self.previous_time=now
        disk=sum(p.stat().st_size for p in self.state.rglob('*') if p.is_file())/1048576
        if check_database:
            db=self.state/'data/NeonHearth/lattice.db'
            if not db.is_file(): raise RuntimeError('Candidate database is missing')
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True,timeout=3) as connection:
                connection.execute('PRAGMA query_only=ON')
                if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                    raise RuntimeError('Candidate database integrity check failed')
        return {'elapsed_seconds':elapsed,'status':'ready' if collector_status=='ready' else 'transport_ready',
                'collector_status':collector_status,'host_age_seconds':age,
                'sequence':state['sequence'],'rss_mb':sum(p.memory_info().rss for p in processes)/1048576,
                'cpu_percent_one_core':percent,'disk_mb':disk,'database_checked':check_database}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--soak-report',type=Path,help='Review stored smoke/soak evidence against this frozen package')
    args=parser.parse_args()
    validate_report(args.output,args.package)
    report={'status':'failed','hardware_acceptance':False,'clean_machine_acceptance':False}
    try:
        frozen=verify_package(args.package)
        report.update(frozen,status='package_verified')
        if args.soak_report:
            stored=read_json(args.soak_report,16*1024*1024)
            if stored.get('candidate') != frozen:
                raise ValueError('Evidence belongs to a different frozen candidate')
            report.update(review_report(stored))
    except Exception as error:
        report['failure']=type(error).__name__
    atomic_report(args.output,report)
    print(json.dumps(report))
    return 0 if report['status'] in ('package_verified','smoke_passed','soak_passed') else 1


if __name__=='__main__': raise SystemExit(main())
