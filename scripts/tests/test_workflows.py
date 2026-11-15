"""Static checks of the release pipeline wiring.

The workflows cannot be executed locally, so this verifies the invariants that
a typo would silently break: job graph, output references, artifact names, and
the rule that third-party build code never shares a job with the signing
identity.
"""
import re
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pyyaml is installed by ci.yml's web job, not by the release build job
    raise unittest.SkipTest('pyyaml is not installed')

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'


def load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding='utf-8'))


def uncommented(text):
    return chr(10).join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def walk(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)
    elif isinstance(node, str):
        yield node


class ReleaseWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = load('release.yml')
        cls.sign = load('sign.yml')
        cls.jobs = cls.release['jobs']

    def test_needs_reference_existing_jobs(self):
        for name, job in self.jobs.items():
            needs = job.get('needs', [])
            needs = [needs] if isinstance(needs, str) else needs
            for need in needs:
                self.assertIn(need, self.jobs, f'{name} needs unknown job {need}')

    def test_output_references_are_declared_and_reachable(self):
        for name, job in self.jobs.items():
            needs = job.get('needs', [])
            needs = [needs] if isinstance(needs, str) else needs
            for text in walk({k: v for k, v in job.items() if k != 'outputs'}):
                for producer, output in re.findall(r'needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_]+)', text):
                    self.assertIn(producer, needs, f'{name} reads {producer}.{output} without needing it')
                    produced = self.jobs[producer]
                    if 'uses' in produced:  # reusable workflow outputs
                        self.assertIn(output, (self.sign.get('on') or self.sign.get(True))['workflow_call']['outputs'])
                    else:
                        self.assertIn(output, produced.get('outputs', {}), f'{producer} has no output {output}')

    def test_every_downloaded_artifact_is_uploaded_somewhere(self):
        uploaded = set()
        downloaded = []
        for job in list(self.jobs.values()) + list(self.sign['jobs'].values()):
            for step in job.get('steps', []):
                uses = step.get('uses', '')
                name = str(step.get('with', {}).get('name', ''))
                if uses.startswith('actions/upload-artifact'):
                    uploaded.add(name)
                if uses.startswith('actions/download-artifact') and name:
                    downloaded.append(name)
        # sign.yml uploads under the caller-chosen `signed_artifact` names
        signed = {job['with']['signed_artifact'] for job in self.jobs.values() if job.get('uses', '').endswith('sign.yml')}
        uploaded |= signed
        for name in downloaded:
            if 'inputs.' in name:  # sign.yml downloads the caller-chosen artifact
                continue
            literals = re.findall(r"'([A-Za-z0-9_.-]+)'", name) or [name]
            for literal in literals:
                self.assertTrue(
                    any(literal == up or re.fullmatch(re.sub(r'\$\{\{[^}]*\}\}', '.*', up), literal) for up in uploaded),
                    f'artifact {literal} is downloaded but never uploaded')

    def test_signing_artifacts_are_signed_by_sign_workflow_only(self):
        for name, job in self.jobs.items():
            if 'uses' in job and job['uses'].endswith('sign.yml'):
                self.assertEqual(job['permissions'].get('id-token'), 'write')
                self.assertTrue(job['if'].startswith("needs.plan.outputs.sign == 'true'"), name)
            else:
                self.assertNotIn('environment', job, f'{name} must not use the signing environment')
                self.assertNotEqual(job.get('permissions', {}).get('id-token'), 'write', name)
        self.assertNotEqual(self.release['permissions'].get('id-token'), 'write')

    def test_sign_workflow_runs_no_build_tooling(self):
        text = uncommented((WORKFLOWS / 'sign.yml').read_text(encoding='utf-8'))
        for forbidden in ('cargo ', 'npm ', 'pip ', 'dotnet', 'install-wix', 'rust-toolchain', 'setup-node', 'GITHUB_ENV'):
            self.assertNotIn(forbidden, text, f'sign.yml must not contain {forbidden!r}')
        job = self.sign['jobs']['sign']
        self.assertEqual(job['environment'], 'release-signing')
        self.assertIn('refs/heads/main', job['if'])
        self.assertIn('refs/tags/v', job['if'])

    def test_every_action_is_pinned_by_full_sha(self):
        for path in list(WORKFLOWS.glob('*.yml')) + [ROOT / '.github/actions/install-wix/action.yml']:
            for text in walk(yaml.safe_load(path.read_text(encoding='utf-8'))):
                pass
            for line in path.read_text(encoding='utf-8').splitlines():
                match = re.match(r'\s*-?\s*uses:\s*(\S+)', line)
                if match and not match.group(1).startswith('./'):
                    self.assertRegex(match.group(1), r'@[0-9a-f]{40}$', f'{path.name}: {match.group(1)}')

    def test_no_dangerous_trigger_and_no_untrusted_interpolation_in_scripts(self):
        for path in WORKFLOWS.glob('*.yml'):
            data = yaml.safe_load(path.read_text(encoding='utf-8'))
            triggers = data.get('on', data.get(True, {}))
            self.assertNotIn('pull_request_target', triggers, path.name)
            for job in data['jobs'].values():
                for step in job.get('steps', []):
                    run = step.get('run', '')
                    for expression in re.findall(r'\$\{\{\s*([^}]*)\}\}', run):
                        self.assertFalse(
                            re.match(r'(github\.(head_ref|event\.)|inputs\.|vars\.)', expression.strip()),
                            f'{path.name}: untrusted value interpolated into a script: {expression}')

    def test_tags_fail_without_signing_and_check_main_ancestry(self):
        plan = '\n'.join(step.get('run', '') for step in self.jobs['plan']['steps'])
        self.assertIn('merge-base --is-ancestor', plan)
        self.assertIn('requires signing', plan)
        self.assertIn('refs/heads/main', plan)

    def test_unsigned_candidates_still_run_the_arm64_smoke_and_tags_require_signing(self):
        smoke = self.jobs['windows-arm64-smoke']['if']
        self.assertIn('!cancelled()', smoke)
        self.assertIn("needs.package-home-hub.result == 'success'", smoke)
        release = self.jobs['release']
        self.assertIn('!cancelled()', release['if'])
        self.assertIn("needs.plan.outputs.sign == 'true'", release['if'])
        for job in ('sign-programs', 'sign-msi', 'sign-bundle', 'package-home-hub', 'windows-arm64-smoke', 'finalize-installer', 'linux-packages'):
            self.assertIn(f"needs.{job}.result == 'success'", release['if'])
            self.assertIn(job, release['needs'])

    def test_jobs_after_skippable_signing_jobs_have_explicit_conditions(self):
        """A skipped job skips every transitive dependent that has no explicit `if`."""
        def needs_of(name):
            needs = self.jobs[name].get('needs', [])
            return [needs] if isinstance(needs, str) else list(needs)
        skippable = {n for n, j in self.jobs.items() if j.get('uses', '').endswith('sign.yml')}
        changed = True
        while changed:
            changed = False
            for name in self.jobs:
                if name not in skippable and any(n in skippable for n in needs_of(name)):
                    skippable.add(name)
                    changed = True
        for name in skippable:
            if self.jobs[name].get('uses', '').endswith('sign.yml'):
                continue
            condition = self.jobs[name].get('if', '')
            signing_only = condition.startswith("needs.plan.outputs.sign == 'true'")
            self.assertTrue('!cancelled()' in condition or signing_only,
                            f'{name} would be skipped together with an unsigned candidate signing jobs')

    def test_signing_check_workflow_is_gone(self):
        self.assertFalse((WORKFLOWS / 'signing-check.yml').exists())

    def test_signing_helpers_do_not_export_through_github_env(self):
        for name in ('setup.ps1', 'sign.ps1', 'verify.ps1'):
            text = uncommented((ROOT / 'scripts' / 'windows-signing' / name).read_text(encoding='utf-8'))
            self.assertNotIn('GITHUB_ENV', text, name)

    def test_release_assets_are_verified_before_publishing(self):
        release = '\n'.join(step.get('run', '') for step in self.jobs['release']['steps'])
        for artifact in ('windows-home-hub', 'windows-msi', 'linux-packages-amd64'):
            self.assertIn(f'artifacts/{artifact} --expect', release)
        self.assertIn('sbom-cyclonedx', release)


class CiWiringTests(unittest.TestCase):
    def test_ci_declares_read_only_permissions(self):
        self.assertEqual(load('ci.yml')['permissions'], {'contents': 'read'})


if __name__ == '__main__':
    unittest.main()
