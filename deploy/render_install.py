#!/usr/bin/env python3
"""Render concrete local YAML; state/TLS and host API configuration are never emitted."""
import argparse
from pathlib import Path
import yaml
from install_config import config, documents


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('-f', '--values', action='append', default=[])
    p.add_argument('--auth-image')
    p.add_argument('--audience')
    p.add_argument('--output', required=True)
    p.add_argument('--force', action='store_true', help='Replace previously rendered public manifests')
    args = p.parse_args()
    try:
        value = config(args.values, image=args.auth_image, audience=args.audience)
        if value['auth']['enabled'] and value['auth']['audience'].startswith('REPLACE_'):
            raise ValueError('Replace the audience placeholder with the existing API audience')
        output = Path(args.output).resolve()
        rendered = documents(value)
        for name in rendered:
            path = output / name
            if path.is_symlink() or (path.exists() and not args.force):
                raise ValueError('Output exists or is a symlink: ' + str(path))
        output.mkdir(parents=True, exist_ok=True)
        for name, items in rendered.items():
            (output / name).write_text(yaml.safe_dump_all(items, sort_keys=False), encoding='utf-8')
        print('Local public manifests prepared: ' + str(output))
    except (ValueError, OSError) as error:
        p.error(str(error))


if __name__ == '__main__':
    main()
