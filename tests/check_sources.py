"""Reject executable artifacts and private key files in the source tree."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
skip = {'.git', '.tools', 'artifacts', '.venv', '__pycache__', 'node_modules'}
errors = []
for path in root.rglob('*'):
    if any(part in skip for part in path.relative_to(root).parts) or not path.is_file():
        continue
    data = path.read_bytes()
    if b'\0' in data or data.startswith((b'\x7fELF', b'MZ', b'PK\x03\x04', b'\x1f\x8b')):
        errors.append(str(path.relative_to(root)))
    if path.suffix in {'.key', '.pem', '.crt'}:
        errors.append(str(path.relative_to(root)))
if errors:
    raise SystemExit('Unexpected artifact/private material: ' + ', '.join(errors))
print('Source-only policy passed')
