import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verify = load('candidate_verify_test', 'verify-candidate.py')

    def package(self):
        names = ['NeonHearth.exe', 'bin/lattice-service.exe', 'mqtt/mosquitto.exe', 'ui/index.html']
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        (self.root / 'BUILD-INFO.json').write_text(json.dumps({'format_version':1, 'source_commit':'a'*40, 'source_dirty':False, 'version':'0.1.0-test', 'unsigned':True}), encoding='utf-8')
        entries=[]
        for path in self.root.rglob('*'):
            if path.is_file():
                data=path.read_bytes()
                entries.append({'path':path.relative_to(self.root).as_posix(), 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()})
        (self.root/'PACKAGE-MANIFEST.json').write_text(json.dumps({'format_version':1,'files':entries}),encoding='utf-8')

    def test_verified_package_records_exact_commit_and_manifest_digest(self):
        self.package()
        result=self.verify.verify_package(self.root)
        self.assertEqual(result['source_commit'], 'a'*40)
        self.assertEqual(len(result['manifest_sha256']),64)
        self.assertTrue(result['unsigned'])

    def test_launcher_failure_retains_exit_code_without_private_output(self):
        private='Bearer private-test-token C:/private/path'
        result=SimpleNamespace(returncode=-1073741515,stdout=private,stderr=private)
        with patch.object(self.verify.subprocess,'run',return_value=result):
            with self.assertRaises(self.verify.LauncherFailure) as raised:
                self.verify.launcher(self.root,self.root/'qa','--no-browser')
        self.assertEqual(raised.exception.diagnostic,{'exit_code':-1073741515,'reason':'missing_dll'})
        self.assertNotIn(private,str(raised.exception))

    def test_launcher_failure_classifies_only_known_fixed_messages(self):
        result=SimpleNamespace(returncode=1,stdout='private-test-token',stderr='Cannot isolate launcher output from background processes: private-test-token')
        with patch.object(self.verify.subprocess,'run',return_value=result):
            with self.assertRaises(self.verify.LauncherFailure) as raised:
                self.verify.launcher(self.root,self.root/'qa','--stop')
        self.assertEqual(raised.exception.diagnostic,{'exit_code':1,'reason':'stdio_isolation'})
        self.assertNotIn('private-test-token',str(raised.exception))

    def test_preflight_leaves_private_state_creation_to_the_native_launcher(self):
        soak=load('candidate_preflight_test','soak-candidate.py')
        state=self.root/'qa-parent'/'private-state'
        args=SimpleNamespace(package=self.root/'package',state=state,output=self.root/'evidence.json',port=58131,mqtt_port=58193)
        # Elevated Windows directory creation may assign Administrators as owner.
        # The launcher must create its final state with its explicit user SID.
        with patch.object(soak,'os',SimpleNamespace(name='nt',environ={})),patch.object(soak.verify,'verify_package',return_value={}),patch.object(soak.socket,'socket'),patch.dict('sys.modules',{'psutil':SimpleNamespace()}):
            soak.preflight(args)
        self.assertTrue(state.parent.is_dir())
        self.assertFalse(state.exists())

    def test_changed_payload_fails_before_any_runtime_is_started(self):
        self.package()
        (self.root/'bin/lattice-service.exe').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.verify.verify_package(self.root)

    def test_traversal_case_duplicates_and_unlisted_files_are_refused(self):
        self.package()
        manifest=self.root/'PACKAGE-MANIFEST.json'
        original=json.loads(manifest.read_text())
        for name in ['../outside', '/absolute', 'C:/outside', 'ui\\index.html', 'ui//index.html']:
            value=json.loads(json.dumps(original)); value['files'][0]['path']=name
            manifest.write_text(json.dumps(value))
            with self.assertRaises(ValueError, msg=name): self.verify.verify_package(self.root)
        manifest.write_text(json.dumps(original))
        (self.root/'private-token.txt').write_text('not a package member')
        with self.assertRaises(ValueError): self.verify.verify_package(self.root)

    def test_short_run_cannot_claim_a_72_hour_soak(self):
        self.assertEqual(self.verify.assess_samples([self.sample(0),self.sample(5)],duration=5,minimum_duration=259200)['status'],'smoke_passed')

    @staticmethod
    def sample(elapsed, **changes):
        row={'elapsed_seconds':elapsed,'status':'ready','collector_status':'ready','host_age_seconds':1,'sequence':1,'rss_mb':32,'cpu_percent_one_core':2,'disk_mb':5}
        row.update(changes)
        return row

    def test_timeout_stale_sampling_gap_and_resource_limits_fail(self):
        cases=[self.sample(10,status='timeout'),self.sample(10,host_age_seconds=31),self.sample(10,rss_mb=513),self.sample(10,cpu_percent_one_core=26),self.sample(10,disk_mb=2049)]
        for row in cases:
            self.assertEqual(self.verify.assess_samples([self.sample(0),row],duration=10)['status'],'failed',row)
        self.assertEqual(self.verify.assess_samples([self.sample(0),self.sample(200)],duration=200,max_gap=120)['status'],'failed')

    def test_degraded_collector_is_rejected_by_default(self):
        samples=[self.sample(0,status='transport_ready',collector_status='degraded'),self.sample(15,status='transport_ready',collector_status='degraded')]
        self.assertEqual(self.verify.assess_samples(samples,duration=15)['status'],'failed')

    def test_explicit_short_transport_policy_keeps_real_degraded_status(self):
        samples=[self.sample(0,status='transport_ready',collector_status='degraded'),self.sample(15,status='transport_ready',collector_status='degraded')]
        result=self.verify.assess_samples(samples,duration=15,allow_degraded_collector=True)
        self.assertEqual(result['status'],'smoke_passed')
        self.assertEqual(result['measurement_scope'],'transport_only_smoke')
        self.assertFalse(result['discovery_acceptance'])
        self.assertEqual(samples[-1]['collector_status'],'degraded')
        for row in [self.sample(15,status='timeout',collector_status='degraded'),self.sample(15,status='transport_ready',collector_status='degraded',host_age_seconds=31)]:
            self.assertEqual(self.verify.assess_samples([samples[0],row],duration=15,allow_degraded_collector=True)['status'],'failed')

    def test_degraded_policy_cannot_enable_long_runs_or_72_hour_passes(self):
        samples=[self.sample(0),self.sample(120)]
        for duration in [121,259200]:
            self.assertEqual(self.verify.assess_samples(samples,duration=duration,allow_degraded_collector=True)['status'],'failed')
        soak=load('candidate_soak_policy_test','soak-candidate.py')
        base=['--package','candidate','--state','qa','--output','evidence','--port','58131','--mqtt-port','58193','--allow-degraded-collector']
        for duration in ['121','259200']:
            with patch('sys.stderr'),self.assertRaises(SystemExit) as error:
                soak.args_for_run(base+['--duration-seconds',duration])
            self.assertEqual(error.exception.code,2)

    def test_review_refuses_a_forged_scope_or_long_degraded_policy(self):
        samples=[self.sample(0,status='transport_ready',collector_status='degraded'),self.sample(15,status='transport_ready',collector_status='degraded')]
        report={'status':'smoke_passed','requested_seconds':15,'samples':samples,'budgets':{},'isolated_instance_stopped':True,
                'policy':{'allow_degraded_collector':True,'scope':'transport_only_smoke'},'measurement_scope':'transport_only_smoke','discovery_acceptance':False}
        self.assertEqual(self.verify.review_report(report)['status'],'smoke_passed')
        report['policy']['scope']='strict_collector'
        self.assertEqual(self.verify.review_report(report)['status'],'failed')
        report['policy']['scope']='transport_only_smoke';report['requested_seconds']=259200;report['status']='soak_passed'
        self.assertEqual(self.verify.review_report(report)['status'],'failed')

    def test_boolean_metrics_and_non_object_manifest_entries_fail_cleanly(self):
        for key in ['host_age_seconds','rss_mb','cpu_percent_one_core','disk_mb']:
            for value in [True,False]:
                self.assertEqual(self.verify.assess_samples([self.sample(0),self.sample(5,**{key:value})],duration=5)['status'],'failed')
        self.package();manifest=self.root/'PACKAGE-MANIFEST.json';value=json.loads(manifest.read_text())
        for entry in [None,42,'not an entry',[]]:
            value['files'][0]=entry;manifest.write_text(json.dumps(value))
            with self.assertRaises(ValueError):self.verify.verify_package(self.root)

    def test_complete_continuous_interval_and_freshness_are_required(self):
        samples=[self.sample(i) for i in range(0,259201,60)]
        self.assertEqual(self.verify.assess_samples(samples,duration=259200)['status'],'soak_passed')
        self.assertEqual(self.verify.assess_samples(samples[:-1],duration=259200)['status'],'incomplete')
        self.assertEqual(self.verify.assess_samples([self.sample(259200)],duration=259200)['status'],'failed')

    def test_report_destination_cannot_overwrite_the_candidate_or_existing_evidence(self):
        self.package()
        with self.assertRaises(ValueError): self.verify.validate_report(self.root/'BUILD-INFO.json',self.root)
        existing=self.root.parent/'existing-evidence.json'
        existing.write_text('preserve')
        self.addCleanup(existing.unlink)
        with self.assertRaises(ValueError): self.verify.validate_report(existing,self.root)

    def test_stale_running_report_is_incomplete_not_a_pass(self):
        report={'status':'running','last_sample_at':'2026-01-01T00:00:00+00:00','budgets':{'max_gap':120}}
        self.assertEqual(self.verify.review_report(report,'2026-01-01T00:03:00+00:00')['status'],'incomplete')

    def test_reviewer_rejects_a_short_report_mislabeled_as_soak(self):
        report={'status':'soak_passed','requested_seconds':5,'samples':[self.sample(0),self.sample(5)],'budgets':{}}
        self.assertEqual(self.verify.review_report(report,'2026-01-01T00:03:00+00:00')['status'],'failed')

    def test_dirty_source_cannot_be_a_release_evidence_package(self):
        self.package()
        path=self.root/'BUILD-INFO.json'
        value=json.loads(path.read_text());value['source_dirty']=True
        path.write_text(json.dumps(value))
        # Rebuild its manifest entry so this tests provenance, not corruption.
        manifest=self.root/'PACKAGE-MANIFEST.json'; value=json.loads(manifest.read_text())
        for entry in value['files']:
            if entry['path']=='BUILD-INFO.json':
                entry['bytes']=path.stat().st_size;entry['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.verify.verify_package(self.root)

    def test_native_smoke_stops_only_its_instance_and_keeps_truthful_evidence(self):
        soak=load('candidate_soak_test','soak-candidate.py')
        state=self.root/'qa';state.mkdir(); output=self.root/'smoke.json'
        args=SimpleNamespace(package=self.root,state=state,output=output,port=58131,mqtt_port=58193,duration_seconds=5,
                             interval_seconds=1,max_gap_seconds=120,max_host_age_seconds=30,max_rss_mb=512,max_cpu_percent=25,max_state_mb=2048,max_growth_mb=512)
        calls=[]
        def launcher(root, private, *arguments):
            self.assertEqual(private,state)
            calls.append(arguments)
            return {'status':'stopped' if '--stop' in arguments else 'ready'}
        frozen={'source_commit':'a'*40,'manifest_sha256':'b'*64,'unsigned':True}
        sampler=SimpleNamespace(sample=lambda elapsed,check_database:self.sample(elapsed))
        with patch('builtins.print'),patch.object(soak,'preflight',return_value=(self.root,state,frozen)),patch.object(soak.verify,'launcher',side_effect=launcher),patch.object(soak.verify,'NativeSampler',return_value=sampler),patch.object(soak.verify,'verify_package',return_value=frozen),patch.object(soak.time,'monotonic',side_effect=[0,0,0,5]),patch.object(soak.time,'sleep'):
            self.assertEqual(soak.run(args),0)
        result=json.loads(output.read_text())
        self.assertEqual(result['status'],'smoke_passed')
        self.assertTrue(result['isolated_instance_stopped'])
        self.assertFalse(result['clean_machine_acceptance'])
        self.assertFalse(result['signing_acceptance'])
        self.assertIn('--no-browser',calls[0])
        self.assertEqual(calls[-1],('--stop',))

    def test_native_timeout_persists_failed_status_and_attempts_cleanup(self):
        soak=load('candidate_soak_failed_test','soak-candidate.py')
        state=self.root/'qa';state.mkdir();output=self.root/'failed.json'
        args=SimpleNamespace(package=self.root,state=state,output=output,port=58131,mqtt_port=58193,duration_seconds=5,
                             interval_seconds=1,max_gap_seconds=120,max_host_age_seconds=30,max_rss_mb=512,max_cpu_percent=25,max_state_mb=2048,max_growth_mb=512)
        frozen={'source_commit':'a'*40,'manifest_sha256':'b'*64,'unsigned':True}
        calls=[]
        def launcher(root,private,*arguments):
            calls.append(arguments)
            return {'status':'stopped' if '--stop' in arguments else 'ready'}
        sampler=SimpleNamespace(sample=lambda *args,**kwargs:(_ for _ in ()).throw(TimeoutError()))
        with patch('builtins.print'),patch.object(soak,'preflight',return_value=(self.root,state,frozen)),patch.object(soak.verify,'launcher',side_effect=launcher),patch.object(soak.verify,'NativeSampler',return_value=sampler),patch.object(soak.verify,'verify_package',return_value=frozen),patch.object(soak.time,'monotonic',side_effect=[0,0]):
            self.assertEqual(soak.run(args),1)
        result=json.loads(output.read_text())
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['samples'][0]['failure_type'],'TimeoutError')
        self.assertEqual(calls[-1],('--stop',))


if __name__=='__main__': unittest.main()
