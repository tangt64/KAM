#!/usr/bin/env python3
"""Create dedicated KAM TLS material locally; never prints private keys."""
import argparse
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True)
    p.add_argument('--hostname', required=True, help='Hostname or IP used by the routed HTTPS endpoint')
    p.add_argument('--renew', action='store_true', help='Reuse the dedicated CA; replace leaf certificates only')
    a = p.parse_args()
    try:
        ipaddress.ip_address(a.hostname)
        san = 'IP:' + a.hostname
    except ValueError:
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', a.hostname):
            p.error('Invalid hostname')
        san = 'DNS:' + a.hostname
    out = Path(a.out).resolve()
    if out.exists() and not a.renew:
        p.error('Output already exists; choose a new directory or --renew')
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix='.tls-', dir=out) as folder:
        temp = Path(folder)
        def run(*words):
            subprocess.run(words, cwd=temp, check=True, capture_output=True)
        if a.renew:
            for name in ['kam-ca.crt', 'kam-ca.key']:
                src = out / name
                if not src.is_file() or src.is_symlink():
                    p.error('Existing dedicated CA required')
                shutil.copyfile(src, temp / name)
        else:
            run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '3650',
                '-keyout', 'kam-ca.key', '-out', 'kam-ca.crt', '-subj', '/CN=kiki-kam-dedicated-ca')
        for name, subject, purpose in [('kam-server', a.hostname, 'serverAuth'),
                                        ('kam-apiserver', 'kiki-kam-apiserver', 'clientAuth')]:
            run('openssl', 'req', '-newkey', 'rsa:3072', '-nodes', '-keyout', name + '.key',
                '-out', name + '.csr', '-subj', '/CN=' + subject)
            (temp / 'extensions').write_text('extendedKeyUsage=' + purpose + '\nsubjectAltName=' + san +
                ',DNS:kiki-kam-auth.kam-system.svc,DNS:kiki-kam-auth.kam-system.svc.cluster.local\n')
            run('openssl', 'x509', '-req', '-in', name + '.csr', '-CA', 'kam-ca.crt', '-CAkey', 'kam-ca.key',
                '-CAcreateserial', '-days', '90', '-out', name + '.crt', '-extfile', 'extensions')
        names = ['kam-server.crt', 'kam-server.key', 'kam-apiserver.crt', 'kam-apiserver.key']
        if not a.renew:
            names += ['kam-ca.crt', 'kam-ca.key']
        for name in names:
            target = out / name
            if target.is_symlink():
                p.error('Refusing a symlink output')
            (temp / name).chmod(0o600)
            (temp / name).replace(target)
    print('Dedicated KAM TLS material prepared; leaf certificates expire in 90 days: ' + str(out))


if __name__ == '__main__':
    main()
