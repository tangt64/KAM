#!/usr/bin/env python3
"""Compare real Helm rendering to standalone YAML and reject unsafe settings."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
import install_config as package


def key(doc):
    return (doc['kind'], doc['metadata'].get('namespace', ''), doc['metadata']['name'])


def main():
    subprocess.run([sys.executable, str(ROOT / 'deploy/sync_chart.py'), '--check'], check=True)
    helm = os.environ.get('HELM_BINARY') or shutil.which('helm')
    if not helm:
        raise SystemExit('Helm required; set HELM_BINARY to a verified local Helm binary')
    report = {'status': 'running', 'rendered_profiles': [], 'rejected_profiles': []}
    with tempfile.TemporaryDirectory(prefix='kam-chart-') as folder:
        values_file = Path(folder) / 'values.yaml'
        def write(value):
            values_file.write_text(yaml.safe_dump(value), encoding='utf-8')
        def render(value, namespace='kam-system', lint=False):
            write(value)
            argv = [helm, 'lint', str(package.CHART), '--strict'] if lint else [helm, 'template', 'kiki-kam', str(package.CHART), '--include-crds']
            return subprocess.run([*argv, '-n', namespace, '-f', str(values_file)], capture_output=True, text=True)
        base = {'auth': {'image': 'example.invalid/kiki-kam@sha256:' + 'a' * 64, 'audience': 'https://kubernetes.default.svc'}}
        variants = {
            'ha': base,
            'single-node-local': package.merge(base, yaml.safe_load((ROOT / 'deploy/values-local.yaml').read_text())),
            'multi-namespace': package.merge(base, {'controller': {'targets': [{'namespace': 'dev', 'profiles': ['view']}, {'namespace': 'qa', 'profiles': ['view', 'edit']}]}}),
            'private-registry-nodeport': package.merge(base, {'imagePullSecrets': [{'name': 'private-registry'}], 'auth': {'service': {'type': 'NodePort', 'nodePort': 30443}}}),
            'controller-only': {'auth': {'enabled': False}},
        }
        for name, value in variants.items():
            result = render(value)
            if result.returncode:
                raise RuntimeError(result.stderr)
            write(value)
            cfg = package.config([values_file])
            expected = {key(d): d for docs in package.documents(cfg).values() for d in docs}
            rendered = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
            actual = {key(doc): doc for doc in rendered}
            assert len(actual) == len(rendered), 'Duplicate resource names'
            assert actual == expected, 'Helm / standalone drift for ' + name
            assert not any(doc['kind'] in {'Secret', 'Namespace'} for doc in rendered)
            assert all('state.json' not in d.get('data', {}) for d in rendered)
            for doc in rendered:
                if doc['kind'] == 'Deployment':
                    pod = doc['spec']['template']['spec']
                    assert pod['securityContext']['runAsNonRoot']
                    assert pod['containers'][0]['securityContext']['readOnlyRootFilesystem']
            lint = render(value, lint=True)
            assert lint.returncode == 0, lint.stdout + lint.stderr
            report['rendered_profiles'].append({'name': name, 'resources': len(rendered)})
        invalid = {
            'missing-auth-image': {'auth': {'audience': base['auth']['audience']}},
            'missing-audience': {'auth': {'image': base['auth']['image']}},
            'audience-placeholder': package.merge(base, {'auth': {'audience': 'REPLACE_WITH_EXISTING_API_AUDIENCE'}}),
            'unpinned-auth-image': package.merge(base, {'auth': {'image': 'localhost/kam:local'}}),
            'unpinned-controller': package.merge(base, {'controller': {'image': 'python:latest'}}),
            'protected-namespace': package.merge(base, {'controller': {'targets': [{'namespace': 'kam-system', 'profiles': ['view']}]}}),
            'duplicate-namespace': package.merge(base, {'controller': {'targets': [{'namespace': 'dev', 'profiles': ['view']}] * 2}}),
            'invalid-profile': package.merge(base, {'controller': {'targets': [{'namespace': 'dev', 'profiles': ['cluster-admin']}]}}),
            'zero-replicas': package.merge(base, {'auth': {'replicas': 0}}),
            'wrong-nodeport': package.merge(base, {'auth': {'service': {'type': 'NodePort', 'nodePort': 12345}}}),
            'clusterip-with-nodeport': package.merge(base, {'auth': {'service': {'nodePort': 30443}}}),
            'unknown-setting': package.merge(base, {'password': 'must-not-be-accepted'}),
        }
        for name, value in invalid.items():
            assert render(value).returncode != 0, 'Helm accepted ' + name
            write(value)
            try:
                cfg = package.config([values_file])
                if cfg['auth']['audience'].startswith('REPLACE_'):
                    raise ValueError('placeholder')
            except ValueError:
                pass
            else:
                raise AssertionError('Standalone accepted ' + name)
            report['rejected_profiles'].append(name)
        assert render(base, namespace='dev').returncode != 0
        report['status'] = 'passed'
        target = ROOT / '.tools/local-chart-result.json'
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
