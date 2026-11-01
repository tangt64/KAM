"""Real HTTPS CLI + mTLS webhook + Kubernetes/etcd integration, without impersonation.

No existing cluster or paid VM is used. envtest has no kubelet/scheduler/GC.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path(os.environ.get('KAM_ENVTEST_DIR', ROOT / '.tools/envtest')).resolve()
BIN = CACHE / 'controller-tools/envtest'
KAM = (ROOT / '.tools/kam').resolve()


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def eventually(check, seconds=60):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.5)
    raise AssertionError('condition timed out')


def main():
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'checks': {}, 'status': 'failed',
              'environment': 'loopback envtest Kubernetes 1.37.0 + etcd; no kubelet/scheduler/GC',
              'impersonation_used': False}
    assert hashlib.sha256((CACHE / 'envtest.tar.gz').read_bytes()).hexdigest() == 'f03faedfc68d2a78cee5cb02618bb44e7f67044f4c5fc957f72d3307fda61a9c'
    processes, logs = [], []
    with tempfile.TemporaryDirectory(prefix='kiki-kam-auth-') as directory:
        root = Path(directory)

        def run(*args, input=None, env=None, required=True):
            r = subprocess.run(list(map(str, args)), input=input, cwd=root, env=env,
                               capture_output=True, text=True, timeout=120)
            if required and r.returncode:
                # Commands contain paths/usernames only; passwords always use stdin.
                raise AssertionError('command failed: ' + ' '.join(map(str, args[:4])) + '\n' + r.stderr[-1800:])
            return r

        def start(name, args, env=None):
            log = open(root / (name + '.log'), 'w+')
            logs.append(log)
            p = subprocess.Popen(list(map(str, args)), env=env, cwd=root, stdout=log, stderr=log)
            processes.append(p)
            return p

        def certificate(name, ca, cn, usage):
            run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key',
                '-out', name + '.csr', '-subj', '/CN=' + cn)
            (root / 'extensions').write_text('subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=' + usage + '\n')
            run('openssl', 'x509', '-req', '-in', name + '.csr', '-CA', ca + '.crt', '-CAkey', ca + '.key',
                '-CAcreateserial', '-out', name + '.crt', '-days', '1', '-extfile', 'extensions')

        def save(name, value):
            path = root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return path

        try:
            for ca in ['ca', 'auth-ca']:
                run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', ca + '.key',
                    '-out', ca + '.crt', '-days', '1', '-subj', '/CN=' + ca)
            certificate('server', 'ca', 'localhost', 'serverAuth')
            certificate('admin', 'ca', 'kam-integration/O=system:masters', 'clientAuth')
            certificate('auth-server', 'auth-ca', 'localhost', 'serverAuth')
            certificate('auth-client', 'auth-ca', 'kiki-kam-apiserver', 'clientAuth')
            run('openssl', 'genrsa', '-out', 'sa.key', '2048')
            ep, pp, ap, authp, authp2 = [port() for _ in range(5)]
            base, auth = f'https://127.0.0.1:{ap}', f'https://127.0.0.1:{authp}'
            webhook = save('webhook.json', {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'webhook',
                'clusters': [{'name': 'webhook', 'cluster': {'server': auth + '/authenticate',
                    'certificate-authority': str(root / 'auth-ca.crt')}}],
                'users': [{'name': 'apiserver', 'user': {'client-certificate': str(root / 'auth-client.crt'),
                    'client-key': str(root / 'auth-client.key')}}],
                'contexts': [{'name': 'webhook', 'context': {'cluster': 'webhook', 'user': 'apiserver'}}]})
            start('etcd', [BIN / 'etcd', '--data-dir=' + str(root / 'etcd'),
                f'--listen-client-urls=http://127.0.0.1:{ep}', f'--advertise-client-urls=http://127.0.0.1:{ep}',
                f'--listen-peer-urls=http://127.0.0.1:{pp}', f'--initial-advertise-peer-urls=http://127.0.0.1:{pp}',
                f'--initial-cluster=default=http://127.0.0.1:{pp}'])
            start('apiserver', [BIN / 'kube-apiserver', f'--etcd-servers=http://127.0.0.1:{ep}',
                '--bind-address=127.0.0.1', '--advertise-address=127.0.0.1', '--endpoint-reconciler-type=none',
                f'--secure-port={ap}', '--tls-cert-file=' + str(root / 'server.crt'),
                '--tls-private-key-file=' + str(root / 'server.key'), '--client-ca-file=' + str(root / 'ca.crt'),
                '--authorization-mode=RBAC', '--service-account-issuer=https://kubernetes.default.svc',
                '--service-account-signing-key-file=' + str(root / 'sa.key'), '--service-account-key-file=' + str(root / 'sa.key'),
                '--service-cluster-ip-range=10.254.0.0/24', '--authentication-token-webhook-config-file=' + str(webhook),
                '--authentication-token-webhook-version=v1', '--authentication-token-webhook-cache-ttl=1s'])
            admin_cfg = save('admin.json', {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'admin',
                'clusters': [{'name': 'cluster', 'cluster': {'server': base, 'certificate-authority': str(root / 'ca.crt')}}],
                'users': [{'name': 'admin', 'user': {'client-certificate': str(root / 'admin.crt'), 'client-key': str(root / 'admin.key')}}],
                'contexts': [{'name': 'admin', 'context': {'cluster': 'cluster', 'user': 'admin'}}]})
            env = dict(os.environ, PATH=str(BIN) + ':' + os.environ['PATH'], HOME=str(root), KUBECONFIG=str(admin_cfg))

            def kubectl(*words, cfg=admin_cfg, body=None, required=True):
                return run(BIN / 'kubectl', '--kubeconfig', cfg, '--request-timeout=5s', *words,
                           input=json.dumps(body) if body else None, env=env, required=required)

            eventually(lambda: kubectl('get', '--raw=/readyz', required=False).returncode == 0, seconds=90)
            for ns in ['kam-system', 'dev']:
                kubectl('create', 'namespace', ns)
            import importlib.util
            def module(name):
                spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / (name + '.py'))
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                return m
            renderer, auth_renderer = module('render'), module('render_auth')
            controller_name = 'kam-' + hashlib.sha256(b'dev').hexdigest()[:16]
            for obj in renderer.manifests('dev', renderer.DEFAULT_IMAGE, ['view']):
                kubectl('apply', '--server-side', '--dry-run=server', '-f', '-', body=obj)
                kubectl('apply', '--server-side', '-f', '-', body=obj)
            kubectl('wait', '--for=condition=Established', 'crd/kamaccessgrants.access.kam.dustbox.kr', '--timeout=30s')
            auth_objects = auth_renderer.manifests('example.invalid/kam@sha256:' + 'a' * 64,
                                                  audience='https://kubernetes.default.svc')
            for obj in auth_objects:
                kubectl('apply', '--server-side', '--dry-run=server', '-f', '-', body=obj)
                kubectl('apply', '--server-side', '-f', '-', body=obj)
            kubectl('create', '-f', '-', body=auth_renderer.state_secret())
            kubectl('patch', 'clusterrole', 'view', '--type=merge', '-p', json.dumps({
                'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']}]}))

            def sa_config(name):
                token = kubectl('-n', 'kam-system', 'create', 'token', name, '--duration=10m').stdout.strip()
                return token, save(name + '.json', {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'sa',
                    'clusters': [{'name': 'c', 'cluster': {'server': base, 'certificate-authority': str(root / 'ca.crt')}}],
                    'users': [{'name': 'sa', 'user': {'token': token}}],
                    'contexts': [{'name': 'sa', 'context': {'cluster': 'c', 'user': 'sa'}}]})
            _, auth_cfg = sa_config('kiki-kam-auth')
            ctrl_token, _ = sa_config(controller_name)
            credentials = root / 'controller-credentials'
            credentials.mkdir(mode=0o700)
            (credentials / 'token').write_text(ctrl_token)
            (credentials / 'token').chmod(0o600)
            (credentials / 'ca.crt').write_bytes((root / 'ca.crt').read_bytes())
            start('controller', ['python3', ROOT / 'deploy/controller.py'], env=dict(env,
                KAM_NAMESPACE='dev', KAM_LEASE_NAMESPACE='kam-system', KAM_LEASE_NAME=controller_name,
                KAM_POD_NAME='envtest-controller', KAM_CREDENTIALS_DIR=str(credentials),
                KUBERNETES_SERVICE_HOST='127.0.0.1', KUBERNETES_SERVICE_PORT=str(ap)))
            common = [KAM, '--kubeconfig', auth_cfg, 'serve', '--tls-cert', root / 'auth-server.crt',
                '--tls-key', root / 'auth-server.key', '--webhook-client-ca', root / 'auth-ca.crt',
                '--audience', 'https://kubernetes.default.svc']
            for name, target in [('auth', authp), ('auth-second-replica', authp2)]:
                start(name, [*common, '--listen', f'127.0.0.1:{target}'], env=env)
            tls = ssl.create_default_context(cafile=str(root / 'auth-ca.crt'))
            def healthy():
                try:
                    with urllib.request.urlopen(auth + '/healthz', context=tls, timeout=1):
                        return True
                except Exception:
                    return False
            eventually(healthy)
            initial_password = secrets.token_urlsafe(24)
            run(KAM, '--kubeconfig', admin_cfg, 'bootstrap', '--username', 'admin', '--password-stdin',
                input=initial_password, env=env)
            admin_login, alice_login = root / 'admin-login.json', root / 'alice-login.json'

            def cli(cfg, *words, password=None, required=True):
                return run(KAM, '--kubeconfig', cfg, *words, input=password, env=env, required=required)

            def login(cfg, name, password, origin=auth):
                return cli(cfg, 'login', origin, '--username', name, '--server', base,
                    '--ca-file', str(root / 'auth-ca.crt'), '--api-ca-file', str(root / 'ca.crt'),
                    '--password-stdin', password=password)

            login(admin_login, 'admin', initial_password)
            alice_password = secrets.token_urlsafe(24)
            alice = json.loads(cli(admin_login, 'user', 'create', 'alice', '--password-stdin', password=alice_password).stdout)
            cli(admin_login, '-n', 'dev', 'grant', 'alice')
            login(alice_login, 'alice', alice_password)
            assert json.loads(cli(alice_login, 'whoami').stdout)['id'] == alice['id']
            assert kubectl('-n', 'dev', 'get', 'pods', cfg=alice_login).returncode == 0
            assert kubectl('-n', 'dev', 'get', 'secrets', cfg=alice_login, required=False).returncode != 0
            assert kubectl('-n', 'default', 'get', 'pods', cfg=alice_login, required=False).returncode != 0
            assert cli(alice_login, 'user', 'list', required=False).returncode != 0
            cli(alice_login, 'namespace', 'use', 'dev')
            cli(alice_login, 'permissions')
            report['checks']['real_password_login_uid_namespace_rbac_no_impersonation'] = True
            # No password or bearer token appears in kubeconfig.
            config = json.loads(kubectl('config', 'view', '--raw', '-ojson', cfg=alice_login).stdout)
            assert config['users'][0]['user'].get('exec') and not config['users'][0]['user'].get('token')
            report['checks']['exec_credential_and_private_cache'] = True
            # A second service process validates the same shared session/account state.
            login(root / 'alice-second.json', 'alice', alice_password, f'https://127.0.0.1:{authp2}')
            report['checks']['two_auth_replicas_share_cas_secret_state'] = True
            assert kubectl('-n', 'kam-system', 'get', 'secrets', cfg=auth_cfg, required=False).returncode != 0
            assert kubectl('-n', 'dev', 'get', 'pods', cfg=auth_cfg, required=False).returncode != 0
            report['checks']['auth_service_sa_is_limited_to_one_secret'] = True

            def revoked(cfg):
                result = kubectl('-n', 'dev', 'get', 'pods', cfg=cfg, required=False)
                return result.returncode != 0 and any(word in result.stderr.lower() for word in ['unauthorized', 'forbidden', 'provide credentials', 'must be logged in'])
            replacement_password = secrets.token_urlsafe(24)
            cli(admin_login, 'user', 'passwd', 'alice', '--password-stdin', password=replacement_password)
            revoke_started = time.monotonic()
            eventually(lambda: revoked(alice_login), seconds=25)
            report.setdefault('revocation_seconds', {})['password_reset'] = round(time.monotonic() - revoke_started, 3)
            assert cli(alice_login, 'whoami', required=False).returncode != 0
            login(alice_login, 'alice', replacement_password)
            cached_profile = Path(config['users'][0]['user']['exec']['args'][-1])
            logout_token = json.loads(cached_profile.read_text())['token']
            cli(alice_login, 'logout')
            def logout_denied():
                request = urllib.request.Request(base + '/api/v1/namespaces/dev/pods', headers={'Authorization': 'Bearer ' + logout_token})
                try:
                    with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(root / 'ca.crt')), timeout=5):
                        return False
                except urllib.error.HTTPError as error:
                    return error.code == 401
            logout_started = time.monotonic()
            eventually(logout_denied, seconds=25)
            report.setdefault('revocation_seconds', {})['logout'] = round(time.monotonic() - logout_started, 3)

            assert not json.loads(kubectl('config', 'view', '-ojson', cfg=alice_login).stdout).get('contexts')
            report['checks']['password_reset_and_logout_revoke_sessions'] = True
            login(alice_login, 'alice', replacement_password)
            cli(admin_login, 'user', 'disable', 'alice')
            revoke_started = time.monotonic()
            eventually(lambda: revoked(alice_login), seconds=25)
            report.setdefault('revocation_seconds', {})['account_disable'] = round(time.monotonic() - revoke_started, 3)
            grants = json.loads(kubectl('-n', 'dev', 'get', 'kag', '-ojson').stdout)['items']
            assert not grants
            cli(admin_login, 'user', 'enable', 'alice')
            assert cli(alice_login, 'whoami', required=False).returncode != 0
            cli(admin_login, 'user', 'delete', 'alice')
            recreated = json.loads(cli(admin_login, 'user', 'create', 'alice', '--password-stdin', password=alice_password).stdout)
            assert recreated['id'] != alice['id']
            login(alice_login, 'alice', alice_password)
            assert kubectl('-n', 'dev', 'get', 'pods', cfg=alice_login, required=False).returncode != 0
            report['checks']['disable_enable_delete_recreate_do_not_restore_old_access'] = True
            expiry = (datetime.now(timezone.utc) + timedelta(seconds=35)).isoformat().replace('+00:00', 'Z')
            cli(admin_login, '-n', 'dev', 'grant', 'alice', '--expires-at', expiry)
            kubectl('-n', 'dev', 'get', 'pods', cfg=alice_login)
            eventually(lambda: revoked(alice_login), seconds=60)
            report['checks']['grant_expiry_revokes_actual_user_access'] = True
            # Reapply resources without ever reapplying the credential Secret.
            before = json.loads(kubectl('-n', 'kam-system', 'get', 'secret', 'kiki-kam-identities', '-ojson').stdout)['data']
            for obj in auth_objects:
                kubectl('apply', '--server-side', '-f', '-', body=obj)
            after = json.loads(kubectl('-n', 'kam-system', 'get', 'secret', 'kiki-kam-identities', '-ojson').stdout)['data']
            assert before == after
            assert kubectl('-n', 'kam-system', 'get', 'secret', 'kiki-kam-identities', cfg=alice_login, required=False).returncode != 0
            report['checks']['reinstall_preserves_accounts_and_state_secret_is_private'] = True
            try:
                req = urllib.request.Request(auth + '/authenticate', data=b'{}', headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, context=tls)
                raise AssertionError('unauthenticated webhook accepted')
            except urllib.error.HTTPError as e:
                assert e.code == 403
            report['checks']['webhook_requires_dedicated_mtls_client'] = True
            assert cli(admin_login, 'user', 'disable', 'admin', required=False).returncode != 0
            report['checks']['last_administrator_preserved'] = True
            report['status'] = 'passed'
        except Exception as e:
            report['error'] = str(e)
            raise
        finally:
            for p in reversed(processes):
                p.terminate()
            for p in reversed(processes):
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            for log in logs:
                log.close()
            report['finished_at'] = datetime.now(timezone.utc).isoformat()
            output = ROOT / '.tools/auth-api-result.json'
            output.parent.mkdir(exist_ok=True)
            output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
