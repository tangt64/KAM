#!/usr/bin/env python3
"""Supply official Helm 4.3.1 by SHA-256; never stores artifacts in Git."""
import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PINS = {'x86_64': ('amd64', '0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b'),
        'aarch64': ('arm64', '8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88')}
if platform.system() != 'Linux' or platform.machine() not in PINS:
    raise SystemExit('Supply a verified HELM_BINARY on this platform')
arch, expected = PINS[platform.machine()]
name = 'helm-v4.3.1-linux-' + arch + '.tar.gz'
cache = ROOT / '.tools/helm'
cache.mkdir(parents=True, exist_ok=True)
archive = cache / name
manual = ROOT / 'artifacts' / name
if manual.is_file():
    data = manual.read_bytes()
elif archive.is_file():
    data = archive.read_bytes()
else:
    with urllib.request.urlopen('https://get.helm.sh/' + name, timeout=90) as response:
        data = response.read(50 * 1024 * 1024 + 1)
if len(data) > 50 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('Helm archive SHA-256/size mismatch')
archive.write_bytes(data)
with tarfile.open(fileobj=io.BytesIO(data)) as tar:
    member = tar.getmember('linux-' + arch + '/helm')
    if not member.isfile() or member.size > 100 * 1024 * 1024:
        raise SystemExit('Unexpected Helm archive member')
    binary = tar.extractfile(member).read()
target = cache / ('helm-' + arch)
if target.is_symlink():
    raise SystemExit('Refusing a symlink Helm cache')
if not target.is_file() or hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(binary).digest():
    target.write_bytes(binary)
target.chmod(0o755)
print(target)
