#!/usr/bin/env python3
"""Regenerate/check static chart assets from the authoritative Python renderers."""
import argparse
import hashlib
import json
from pathlib import Path
import yaml
import render
import render_auth
import install_config

ROOT = Path(__file__).resolve().parents[1]


def assets():
    original = render.manifests('kam-target-blueprint', render.DEFAULT_IMAGE, ['view'])
    name = original[-2]['metadata']['name']
    substitutions = {'kam-target-blueprint': '__TARGET_NAMESPACE__', name: '__CONTROLLER_NAME__', render.DEFAULT_IMAGE: '__CONTROLLER_IMAGE__'}
    def tokens(value):
        if isinstance(value, dict):
            return {k: tokens(v) for k, v in value.items()}
        if isinstance(value, list):
            return [tokens(v) for v in value]
        return substitutions.get(value, value) if isinstance(value, str) else value
    controller = tokens(original[1:])
    code_hash = hashlib.sha256((ROOT / 'deploy/controller.py').read_text(encoding='utf-8').encode()).hexdigest()
    for doc in controller:
        if doc['kind'] == 'Role':
            for rule in doc['rules']:
                if rule.get('verbs') == ['bind']:
                    rule['resourceNames'] = '__PROFILES_JSON__'
        if doc['kind'] == 'Deployment':
            doc['spec']['template']['metadata']['annotations'] = {'access.kam.dustbox.kr/source-sha256': code_hash}
            for env in doc['spec']['template']['spec']['containers'][0]['env']:
                if env['name'] == 'KAM_PROFILES':
                    env['value'] = '__PROFILE_CSV__'
    auth = render_auth.manifests('example.invalid/kam@sha256:' + 'a' * 64, audience='__API_AUDIENCE__')
    for doc in auth:
        if doc['kind'] == 'Deployment':
            doc['spec']['template']['spec']['containers'][0]['image'] = '__AUTH_IMAGE__'
    cfg = install_config.config([ROOT / 'deploy/values-local.yaml'], audience='https://kubernetes.default.svc')
    example = [d for group in install_config.documents(cfg).values() for d in group]
    for doc in example:
        if doc['kind'] == 'Deployment' and doc['metadata']['name'] == 'kiki-kam-auth':
            doc['spec']['template']['spec']['containers'][0]['args'][-1] = 'REPLACE_WITH_EXISTING_API_AUDIENCE'
    return {
        'charts/kiki-kam/files/controller.json': json.dumps(controller, indent=2) + '\n',
        'charts/kiki-kam/files/auth.json': json.dumps(auth, indent=2) + '\n',
        'charts/kiki-kam/crds/kamaccessgrants.yaml': yaml.safe_dump(original[0], sort_keys=False),
        'deploy/manifests/10-crd.yaml': yaml.safe_dump(original[0], sort_keys=False),
        'deploy/manifests/local-example.yaml': '# EDITING EXAMPLE ONLY. Replace API audience and supply images/state/TLS before installation.\n' + yaml.safe_dump_all(example, sort_keys=False),
        'deploy/bootstrap/identity-state.yaml': '# FIRST INSTALL ONLY: kubectl create -f this-file. Never apply, replace, or Helm-manage account state.\n' + yaml.safe_dump(render_auth.state_secret(), sort_keys=False),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for name, content in assets().items():
        path = ROOT / name
        if args.check:
            if not path.is_file() or path.read_text(encoding='utf-8') != content:
                raise SystemExit('Generated asset drift: ' + name + '; run python deploy/sync_chart.py')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8', newline='\n')
    print('Chart/manifest assets are synchronized')


if __name__ == '__main__':
    main()
