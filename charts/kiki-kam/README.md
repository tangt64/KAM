# KIKI KAM local source chart

Use this directory directly with `helm upgrade --install kiki-kam ./charts/kiki-kam -n kam-system -f YOUR-VALUES.yaml`.
See [local installation](../../docs/LOCAL-INSTALL.md) for external state/TLS bootstrap, plain YAML, local single-node values, webhook integration and uninstall boundaries.

Default HA replicas: 2. Explicit local profile: `../../deploy/values-local.yaml`.
Chart credentials are never embedded. CRDs use `crds/` and need a separately reviewed upgrade.
