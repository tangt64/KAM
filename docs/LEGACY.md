# KAM = Kubernetes Account Manager (RBAC/ServiceAccount)

**KAM** is a CLI that manages Kubernetes RBAC bindings and ServiceAccounts.

## Important concept

Kubernetes does **not** store "User" objects.

kam defines a **logical user** as:
- a subject name (kind=User)
- the set of RBAC bindings granted to that subject.

So, `kam user create` means: **declare the user and grant initial access**.

## Build

This repo uses Go modules.

```bash
go mod tidy
go build -o kam
```

## Examples

Grant view in namespace `dev`:
```bash
./kam user create gookhyun -n dev --role view
```

Replace access in a namespace:
```bash
./kam user set gookhyun -n dev --role edit
```

Revoke everywhere (kam-managed only):
```bash
./kam user delete gookhyun
```

List logical users (derived from kam-labeled bindings):
```bash
./kam user list
```

Dry-run:
```bash
./kam user create gookhyun -n dev --role view --dry-run
```

## Guardrails
- Refuses to bind `cluster-admin` and `system:*` ClusterRoles by default.
- Deletes **only kam-managed** bindings unless `--force` is used.
