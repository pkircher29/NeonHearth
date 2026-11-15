#!/usr/bin/env python3
"""Run an explicitly isolated Windows candidate smoke/soak; never opens a browser."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import time
from datetime import datetime, timezone

spec=importlib.util.spec_from_file_location('candidate_verifier',Path(__file__).with_name('verify-candidate.py'))
verify=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def args_for_run(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',required=True,type=Path)
    parser.add_argument('--state',required=True,type=Path,help='New empty QA directory; never your existing Home Hub state')
    parser.add_argument('--output',required=True,type=Path,help='New evidence file outside package and state')
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--mqtt-port',required=True,type=int)
    parser.add_argument('--duration-seconds',type=float,default=72*3600)
    parser.add_argument('--interval-seconds',type=float,default=60)
    parser.add_argument('--max-gap-seconds',type=float,default=120)
    parser.add_argument('--max-host-age-seconds',type=float,default=30)
    parser.add_argument('--max-rss-mb',type=float,default=512)
    parser.add_argument('--max-cpu-percent',type=float,default=25,help='Combined collector/broker CPU as percent of one logical CPU')
    parser.add_argument('--max-state-mb',type=float,default=2048)
    parser.add_argument('--max-growth-mb',type=float,default=512)
    parser.add_argument('--allow-degraded-collector',action='store_true',help='Permit an explicitly transport-only smoke of at most 120 seconds; never a soak')
    result=parser.parse_args(argv)
    values=[result.duration_seconds,result.interval_seconds,result.max_gap_seconds,result.max_host_age_seconds,result.max_rss_mb,result.max_cpu_percent,result.max_state_mb,result.max_growth_mb]
    if any(not math.isfinite(v) or v <= 0 for v in values): parser.error('Durations and budgets must be positive finite numbers')
    if not 1 <= result.interval_seconds <= 60 or result.max_gap_seconds <= result.interval_seconds or result.duration_seconds/result.interval_seconds > 10000:
        parser.error('Use a 1–60 second interval, a larger gap limit, and at most 10,000 samples')
    if result.port==result.mqtt_port or any(not 1024 <= p <= 65535 for p in [result.port,result.mqtt_port]):
        parser.error('Choose two distinct unused unprivileged loopback ports')
    try: verify.collector_policy(result.allow_degraded_collector,result.duration_seconds)
    except ValueError:parser.error('Degraded collectors are permitted only in transport smoke runs of at most 120 seconds')
    return result


def preflight(args):
    root=args.package.resolve();state=args.state.resolve()
    default=Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'NeonHearthHomeHub'
    if state==default.resolve() or state.is_relative_to(default.resolve()) or default.resolve().is_relative_to(state):
        raise ValueError('The customer Home Hub state is not a QA destination')
    if state==root or state.is_relative_to(root) or root.is_relative_to(state):
        raise ValueError('QA state and candidate package must be separate')
    if state.exists() and (not state.is_dir() or any(state.iterdir())):
        raise ValueError('The QA state directory must be empty; existing data is preserved')
    if state.exists(): verify.no_reparse(state)
    verify.validate_report(args.output,root,state)
    package=verify.verify_package(root)
    if os.name != 'nt': raise RuntimeError('Native candidate collection is Windows-only')
    import psutil  # explicit test-tool dependency; never silently omit resource evidence
    for port in [args.port,args.mqtt_port]:
        with socket.socket() as reservation:
            reservation.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            reservation.bind(('127.0.0.1',port))
    # The native launcher creates this directory with an explicit user owner
    # and protected ACL. Elevated default mkdir can assign Administrators as
    # owner, which the launcher's private-state boundary correctly rejects.
    state.parent.mkdir(parents=True,exist_ok=True)
    return root,state,package


def run(args):
    policy=verify.collector_policy(getattr(args,'allow_degraded_collector',False),args.duration_seconds)
    root,state,package=preflight(args)
    samples=[]
    thresholds={'max_gap':args.max_gap_seconds,'max_age':args.max_host_age_seconds,'max_rss_mb':args.max_rss_mb,
                'max_cpu':args.max_cpu_percent,'max_disk_mb':args.max_state_mb,'max_disk_growth_mb':args.max_growth_mb}
    report={'status':'starting','candidate':package,'started_at':datetime.now(timezone.utc).isoformat(),
            'qa_state_path':str(state),'package_path':str(root),
            'policy':policy,'measurement_scope':policy['scope'],'discovery_acceptance':False,
            'requested_seconds':args.duration_seconds,'sample_interval_seconds':args.interval_seconds,
            'budgets':thresholds,'samples':samples,'clean_machine_acceptance':False,'hardware_acceptance':False,
            'recovery_exercises_performed':False,'signing_acceptance':False}
    # Signing status is a package declaration, never a trusted-signature check.
    report['signing_status']='unsigned' if package['unsigned'] else 'declared_signed_not_verified'
    verify.atomic_report(args.output,report)
    started=False
    try:
        started=True
        ready=verify.launcher(root,state,'--no-browser','--port',str(args.port),'--mqtt-port',str(args.mqtt_port))
        if ready.get('status') != 'ready': raise RuntimeError('The QA instance did not start')
        verify.atomic_report(state/'.neonhearth-acceptance.json',{'candidate':package,'purpose':'isolated acceptance only'})
        sampler=verify.NativeSampler(root,state)
        begin=time.monotonic();last_db_check=-3600
        while True:
            elapsed=time.monotonic()-begin
            db_check=elapsed-last_db_check >= 3600 or elapsed >= args.duration_seconds
            try:
                row=sampler.sample(elapsed,check_database=db_check)
                if db_check: last_db_check=elapsed
            except Exception as error:
                row={'elapsed_seconds':elapsed,'status':'failed','failure_type':type(error).__name__}
            samples.append(row)
            assessed=verify.assess_samples(samples,args.duration_seconds,allow_degraded_collector=policy['allow_degraded_collector'],**thresholds)
            report.update(assessed)
            if report['status']=='incomplete':report['status']='running'
            report['last_sample_at']=datetime.now(timezone.utc).isoformat()
            verify.atomic_report(args.output,report)
            if assessed['status']!='incomplete':break
            time.sleep(min(args.interval_seconds,max(0,args.duration_seconds-(time.monotonic()-begin))))
        final_package=verify.verify_package(root)
        if final_package!=package: raise RuntimeError('Candidate changed during the run')
    except KeyboardInterrupt:
        report.update(status='interrupted',failures=['Run interrupted; elapsed uptime is not acceptance'])
    except Exception as error:
        report.update(status='failed',failure_type=type(error).__name__)
        if isinstance(error,verify.LauncherFailure):
            report['launcher_failure']=error.diagnostic
    finally:
        if started:
            try:
                stopped=verify.launcher(root,state,'--stop')
                if stopped.get('status')!='stopped':raise RuntimeError('Stop was not confirmed')
                report['isolated_instance_stopped']=True
            except Exception as error:
                report.update(status='failed',isolated_instance_stopped=False,cleanup_failure_type=type(error).__name__)
                if isinstance(error,verify.LauncherFailure):
                    report['cleanup_launcher_failure']=error.diagnostic
        report['ended_at']=datetime.now(timezone.utc).isoformat()
        verify.atomic_report(args.output,report)
    # All private state and evidence are retained for inspection; nothing is deleted.
    print(json.dumps({k:v for k,v in report.items() if k!='samples'}))
    return 0 if report['status'] in ('smoke_passed','soak_passed') else 1


if __name__=='__main__':
    try:
        raise SystemExit(run(args_for_run()))
    except (ValueError,RuntimeError,OSError,ImportError) as error:
        print(json.dumps({'status':'failed','phase':'preflight','failure_type':type(error).__name__}))
        raise SystemExit(1)
