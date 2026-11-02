"""Local install values and standalone manifests; no cluster/network access."""
import copy
import hashlib
import json
from pathlib import Path
import re
import yaml
import render
import render_auth

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / 'charts/kiki-kam'


def merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        result[key] = merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else copy.deepcopy(value)
    return result


def validate_schema(value, schema, path='values'):
    # This chart uses only this bounded JSON-schema subset. Helm also validates the full schema.
    kinds = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'integer': int, 'null': type(None)}
    types = schema.get('type', [])
    if isinstance(types, str):
        types = [types]
    if types and not any(type(value) is kinds[t] for t in types):
        raise ValueError(path + ': invalid type')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError(path + ': unsupported value')
    if isinstance(value, dict):
        props = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys() - props.keys():
            raise ValueError(path + ': unknown setting')
        if set(schema.get('required', [])) - value.keys():
            raise ValueError(path + ': missing setting')
        for key, item in value.items():
            if key in props:
                validate_schema(item, props[key], path + '.' + key)
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', 10000):
            raise ValueError(path + ': invalid item count')
        if schema.get('uniqueItems') and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            raise ValueError(path + ': duplicate items')
        for item in value:
            validate_schema(item, schema['items'], path + '[]')
    if type(value) is int and (value < schema.get('minimum', value) or value > schema.get('maximum', value)):
        raise ValueError(path + ': outside allowed range')
    if isinstance(value, str) and 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
        raise ValueError(path + ': invalid format')


def config(files=(), *, image=None, audience=None):
    value = yaml.safe_load((CHART / 'values.yaml').read_text(encoding='utf-8'))
    for file in files:
        override = yaml.safe_load(Path(file).read_text(encoding='utf-8'))
        if not isinstance(override, dict):
            raise ValueError('Values must be a mapping')
        value = merge(value, override)
    if image is not None:
        value['auth']['image'] = image
    if audience is not None:
        value['auth']['audience'] = audience
    validate_schema(value, json.loads((CHART / 'values.schema.json').read_text(encoding='utf-8')))
    digest = r'[^\s]+@sha256:[a-f0-9]{64}'
    if not re.fullmatch(digest, value['controller']['image']):
        raise ValueError('controller.image requires a SHA-256 digest')
    auth = value['auth']
    if auth['enabled']:
        pattern = r'[^\s]+' if value['local']['allowUnpinnedImages'] else digest
        if not re.fullmatch(pattern, auth['image']):
            raise ValueError('Supply auth.image by digest or explicitly enable local tag mode')
        if not auth['audience'] or auth['audience'].startswith('REPLACE_') or any(c.isspace() for c in auth['audience']):
            raise ValueError('Supply the existing API audience')
        service = auth['service']
        if (service['type'] == 'NodePort') != bool(service['nodePort']):
            raise ValueError('Only NodePort requires an explicit nodePort')
        if service['type'] == 'NodePort' and service['nodePort'] < 30000:
            raise ValueError('NodePort must be in 30000..32767')
    seen = set()
    for target in value['controller']['targets']:
        ns = target['namespace']
        if ns in {'default', 'kam-system'} or ns.startswith('kube-') or ns in seen:
            raise ValueError('Protected or duplicate controller namespace')
        seen.add(ns)
    return value


def workload(documents, options, pull_secrets):
    code = next((d['data']['controller.py'] for d in documents if d['kind'] == 'ConfigMap' and 'controller.py' in d.get('data', {})), None)
    for doc in documents:
        if doc['kind'] == 'Deployment':
            doc['spec']['replicas'] = options['replicas']
            if code is not None:
                doc['spec']['template']['metadata'].setdefault('annotations', {})['access.kam.dustbox.kr/source-sha256'] = hashlib.sha256(code.encode()).hexdigest()
            pod = doc['spec']['template']['spec']
            pod['containers'][0]['imagePullPolicy'] = options['imagePullPolicy']
            pod['imagePullSecrets'] = copy.deepcopy(pull_secrets)
            if options['replicas'] == 1:
                pod['topologySpreadConstraints'][0]['whenUnsatisfiable'] = 'ScheduleAnyway'
        elif doc['kind'] == 'PodDisruptionBudget' and options['replicas'] == 1:
            doc['spec']['minAvailable'] = 0
    return documents


def documents(value):
    crd = render.manifests('dev', value['controller']['image'], ['view'])[0]
    authentication = []
    if value['auth']['enabled']:
        # The original renderer's digest-only contract remains unchanged.
        authentication = render_auth.manifests('local.invalid/kam@sha256:' + 'a' * 64, audience=value['auth']['audience'])
        for doc in authentication:
            if doc['kind'] == 'Deployment':
                doc['spec']['template']['spec']['containers'][0]['image'] = value['auth']['image']
            if doc['kind'] == 'Service':
                doc['spec']['type'] = value['auth']['service']['type']
                if doc['spec']['type'] == 'NodePort':
                    doc['spec']['ports'][0]['nodePort'] = value['auth']['service']['nodePort']
        workload(authentication, value['auth'], value['imagePullSecrets'])
    controllers = []
    for target in value['controller']['targets']:
        controllers.extend(workload(render.manifests(target['namespace'], value['controller']['image'], target['profiles'])[1:], value['controller'], value['imagePullSecrets']))
    return {'10-crd.yaml': [crd], '20-auth.yaml': authentication, '30-controllers.yaml': controllers}
