#!/usr/bin/env python3
"""Render KAM authentication; account state is created separately, never applied."""
import argparse
import base64
import json
import re
import yaml


def state_secret(namespace='kam-system'):
    return {'apiVersion': 'v1', 'kind': 'Secret',
            'metadata': {'name': 'kiki-kam-identities', 'namespace': namespace},
            'type': 'Opaque', 'data': {'state.json': base64.b64encode(
                b'{"schema":1,"users":{},"sessions":{}}').decode()}}


def manifests(image, namespace='kam-system', audience=None):
    if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('Supply a reviewed authentication image pinned by SHA-256')
    if namespace != 'kam-system':
        raise ValueError('Use the protected kam-system namespace')
    if not audience or any(c.isspace() for c in audience):
        raise ValueError('Supply an existing Kubernetes API audience')
    name = 'kiki-kam-auth'
    meta = {'name': name, 'namespace': namespace}
    sa = {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': dict(meta)}
    role = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role',
            'metadata': dict(meta), 'rules': [{'apiGroups': [''], 'resources': ['secrets'],
             'resourceNames': ['kiki-kam-identities'], 'verbs': ['get', 'update']}]}
    bind = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
            'metadata': dict(meta), 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io',
             'kind': 'Role', 'name': name}, 'subjects': [{'kind': 'ServiceAccount',
             'name': name, 'namespace': namespace}]}
    admin = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole',
             'metadata': {'name': 'kiki-kam-grant-admin'}, 'rules': [
                 {'apiGroups': ['access.kam.dustbox.kr'], 'resources': ['kamaccessgrants'],
                  'verbs': ['get', 'list', 'create', 'update', 'patch', 'delete']}]}
    admin_binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
                     'metadata': {'name': 'kiki-kam-grant-admin'},
                     'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole',
                                 'name': 'kiki-kam-grant-admin'},
                     'subjects': [{'kind': 'Group', 'name': 'kiki-kam:account-admins',
                                   'apiGroup': 'rbac.authorization.k8s.io'}]}
    discovery = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole',
                 'metadata': {'name': 'kiki-kam-namespace-discovery'},
                 'rules': [{'apiGroups': [''], 'resources': ['namespaces'], 'verbs': ['get', 'list']}]}
    discovery_binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
                         'metadata': {'name': 'kiki-kam-namespace-discovery'},
                         'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole',
                                     'name': 'kiki-kam-namespace-discovery'},
                         'subjects': [{'kind': 'Group', 'name': 'kiki-kam:users',
                                       'apiGroup': 'rbac.authorization.k8s.io'}]}
    service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': dict(meta), 'spec': {
        'selector': {'app': name}, 'ports': [{'name': 'https', 'port': 443, 'targetPort': 8443}]}}
    pod = {'serviceAccountName': name, 'terminationGracePeriodSeconds': 20,
           'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'fsGroup': 65532,
                               'seccompProfile': {'type': 'RuntimeDefault'}},
           'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': 'kubernetes.io/hostname',
               'whenUnsatisfiable': 'DoNotSchedule', 'labelSelector': {'matchLabels': {'app': name}}}],
           'containers': [{'name': 'auth', 'image': image, 'args': ['serve', '--audience', audience],
               'ports': [{'containerPort': 8443}],
               'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                   'capabilities': {'drop': ['ALL']}},
               'resources': {'requests': {'cpu': '100m', 'memory': '64Mi'},
                             'limits': {'cpu': '1', 'memory': '256Mi'}},
               'readinessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/readyz', 'port': 8443}},
               'livenessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/healthz', 'port': 8443}},
               'volumeMounts': [{'name': 'tls', 'mountPath': '/tls', 'readOnly': True},
                                {'name': 'webhook', 'mountPath': '/webhook', 'readOnly': True}]}],
           'volumes': [{'name': 'tls', 'secret': {'secretName': 'kiki-kam-tls', 'defaultMode': 0o440}},
                       {'name': 'webhook', 'configMap': {'name': 'kiki-kam-webhook-ca'}}]}
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': dict(meta),
                  'spec': {'replicas': 2, 'selector': {'matchLabels': {'app': name}},
                           'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 0, 'maxUnavailable': 1}},
                           'template': {'metadata': {'labels': {'app': name}}, 'spec': pod}}}
    pdb = {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': dict(meta),
           'spec': {'minAvailable': 1, 'selector': {'matchLabels': {'app': name}}}}
    return [sa, role, bind, admin, admin_binding, discovery, discovery_binding, service, deployment, pdb]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--audience')
    parser.add_argument('--state-only', action='store_true')
    args = parser.parse_args()
    if args.state_only:
        print(json.dumps(state_secret()))
    else:
        if not args.image:
            parser.error('--image is required')
        print(yaml.safe_dump_all(manifests(args.image, audience=args.audience), sort_keys=False))
