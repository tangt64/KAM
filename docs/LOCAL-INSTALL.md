# KAM 로컬 YAML·Helm 설치

이 문서는 로컬 checkout의 소스 차트를 사용하는 절차입니다. Helm 저장소 등록·차트 아카이브 배포는 필요하지 않습니다. YAML 생성은 클러스터에 접속하지 않습니다. 외부 이미지 다운로드가 불가능한 환경에서는 두 이미지를 노드에 미리 공급해야 합니다.

## 파일

| 경로 | 용도 |
| --- | --- |
| `charts/kiki-kam/` | 의존성 없는 로컬 Helm 차트 0.1.0 |
| `deploy/values-local.yaml` | 단일 노드: auth/controller 1 replica, auth 로컬 태그·Never pull 명시적 허용 |
| `deploy/manifests/10-crd.yaml` | CRD 원문 |
| `deploy/manifests/local-example.yaml` | 편집용 전체 YAML 예시. audience placeholder를 바꾸기 전 적용 금지 |
| `deploy/bootstrap/identity-state.yaml` | 최초 한 번만 create하는 외부 계정 Secret |
| `deploy/render_install.py` | 설정에서 실제 설치용 YAML 3개 생성 |
| `deploy/sync_chart.py --check` | 원본 renderer·차트 blueprint·예시 YAML의 동기화 확인 |

기본 values는 HA 2 replica이며 auth 이미지와 기존 API audience를 반드시 입력합니다. `default`, `kam-system`, `kube-*`은 controller 대상에서 거부합니다. 비밀번호·개인키·계정 상태를 values나 Helm release에 넣지 않습니다.

## 1. 이미지와 CLI

```bash
python3 -m pip install -r requirements.txt
mkdir -p .tools artifacts "$HOME/.local/bin"
GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 go build -buildvcs=false -trimpath -o .tools/kiki-kam .
install -m 0755 .tools/kiki-kam "$HOME/.local/bin/kubectl-kam"
export PATH="$HOME/.local/bin:$PATH"
podman build -t localhost/kiki-kam-auth:local .
podman save --format oci-archive -o artifacts/kiki-kam-auth.tar localhost/kiki-kam-auth:local
```

실행 파일·이미지 tar는 Git에 넣지 않습니다. `localhost/kiki-kam-auth:local`을 **실제 Kubernetes 노드의 CRI 이미지 저장소**에 공급하세요. 워크스테이션 rootless Podman 저장소와 노드의 containerd/CRI-O 저장소는 다릅니다. containerd는 노드에서 `sudo ctr -n k8s.io images import /path/kiki-kam-auth.tar`를 사용할 수 있습니다. 기본 Python controller 이미지도 고정 digest로 접근 가능해야 하며 완전 오프라인이면 미리 공급하고 `controller.imagePullPolicy: Never`를 설정합니다.

CRI-O는 노드의 rootful containers/storage 설정이 CRI-O의 `root`·`runroot`·storage driver와 일치함을 확인한 뒤 다음처럼 가져올 수 있습니다. 터미널랩의 CRI-O 1.37.2 두 worker에서 이 경로와 실제 Pod 실행을 확인했습니다. 저장소 경로를 강제로 바꾸거나 CRI-O 데이터를 초기화하지 않습니다.

```bash
sudo skopeo copy oci-archive:/path/kiki-kam-auth.tar \
  containers-storage:localhost/kiki-kam-auth:local
```

이미지를 빌드했다면 Go를 호스트에 별도로 설치하지 않고 동일 이미지에서 CLI를 꺼낼 수도 있습니다.

```bash
container_id=$(podman create localhost/kiki-kam-auth:local)
podman cp "$container_id:/kam" .tools/kiki-kam
podman rm "$container_id"
install -m 0755 .tools/kiki-kam "$HOME/.local/bin/kubectl-kam"
```

운영용은 검토한 registry 이미지의 실제 `@sha256:...`를 `auth.image`에 입력하고 local 옵션을 끕니다. 로컬 태그를 기본 보안 정책에 자동 허용하지 않습니다.

## 2. 기존 API audience와 TLS

control plane의 `/etc/kubernetes/manifests/kube-apiserver.yaml`에서 기존 `--api-audiences`의 첫 값을 사용합니다. 그 플래그가 없으면 기존 `--service-account-issuer`를 사용합니다. 새로운 audience나 API 주소로 바꾸지 않습니다.

아래는 **설정 예시**입니다. 도메인·audience는 환경의 실제 값으로 교체하세요.

```yaml
# artifacts/site-values.yaml: 비밀 없이 이미지·audience·노출 방식만 설정
# 아래 audience는 예시이며 기존 API 값을 확인해야 합니다.
auth:
  audience: https://kubernetes.default.svc
  service:
    type: NodePort
    nodePort: 30443
controller:
  targets:
    - namespace: dev
      profiles: [view]
```

NodePort는 명시적으로 선택하는 예시이며 기본 Service는 ClusterIP입니다. 공개 방화벽을 자동으로 열지 않습니다. API 서버 호스트와 사용자에서 모두 도달하는 private IP/DNS·TLS 경로를 준비합니다. control plane의 host DNS가 cluster Service DNS를 해석한다고 가정하지 마세요. 워크스테이션의 임시 port-forward만으로 API 서버 webhook을 연결할 수는 없습니다.

```bash
python deploy/make_tls.py --out artifacts/kam-pki --hostname kam.example.internal
kubectl create namespace kam-system
kubectl create namespace dev
kubectl -n kam-system create secret tls kiki-kam-tls \
  --cert=artifacts/kam-pki/kam-server.crt --key=artifacts/kam-pki/kam-server.key
kubectl -n kam-system create configmap kiki-kam-webhook-ca \
  --from-file=ca.crt=artifacts/kam-pki/kam-ca.crt
```

기존 namespace·Secret·ConfigMap이 있으면 재생성하지 않고 관리자가 현재 내용을 확인합니다. 클러스터 CA와 별도 KAM CA를 사용합니다. CA private key는 노드나 Helm에 넣지 않습니다. Leaf는 90일 유효하며 `--renew`는 같은 CA를 유지합니다. TLS Secret 갱신 후 auth Deployment를 명시적으로 rollout restart하고 webhook 연결을 다시 확인합니다. CA·접속 URL 변경은 별도 단계적 migration이 필요합니다.

## 3. 계정 상태 최초 생성과 bootstrap

native 관리자 kubeconfig로 실행합니다. `ADMIN.conf`는 실제 기존 관리자 경로로 바꿉니다.

```bash
kubectl --kubeconfig ADMIN.conf -n kam-system get secret kiki-kam-identities
# 위 Secret이 없는 최초 설치에만 실행합니다.
kubectl --kubeconfig ADMIN.conf create -f deploy/bootstrap/identity-state.yaml
kubectl kam --kubeconfig ADMIN.conf bootstrap --username admin
```

bootstrap은 숨김 비밀번호 입력을 사용하며 기본 비밀번호가 없습니다. 상태 Secret은 `kubectl apply`, Helm 템플릿, install hook으로 초기화하지 않습니다. 재설치 시 bootstrap을 다시 수행하지 않습니다. Secret 백업에는 해시·세션 정보가 있으므로 암호화·접근 통제를 적용합니다.

## 4A. Helm 없이 YAML 적용

```bash
python deploy/render_install.py -f deploy/values-local.yaml -f artifacts/site-values.yaml \
  --output artifacts/install
kubectl apply --server-side -f artifacts/install/10-crd.yaml
kubectl wait --for=condition=Established crd/kamaccessgrants.access.kam.dustbox.kr --timeout=60s
kubectl apply --server-side --dry-run=server -f artifacts/install/20-auth.yaml -f artifacts/install/30-controllers.yaml
kubectl apply --server-side -f artifacts/install/20-auth.yaml -f artifacts/install/30-controllers.yaml
kubectl -n kam-system rollout status deployment/kiki-kam-auth --timeout=180s
```

출력 파일은 공개 설정과 controller 소스만 포함합니다. 기존 출력 덮어쓰기는 `--force`를 명시합니다. 대상 controller의 rollout도 확인하세요. 단일 노드 프로필은 replica 1·PDB minAvailable 0·분산 조건 완화이므로 장애 전환과 무중단 갱신을 보장하지 않습니다.

## 4B. 로컬 소스 Helm 차트 설치

```bash
helm lint ./charts/kiki-kam -n kam-system -f deploy/values-local.yaml -f artifacts/site-values.yaml
helm template kiki-kam ./charts/kiki-kam -n kam-system --include-crds \
  -f deploy/values-local.yaml -f artifacts/site-values.yaml > artifacts/helm-preview.yaml
helm upgrade --install kiki-kam ./charts/kiki-kam -n kam-system \
  -f deploy/values-local.yaml -f artifacts/site-values.yaml --wait --timeout 5m
```

Helm 4.3.1로 검사했습니다. 차트는 Helm v2 포맷이며 Helm 3의 실행 검증은 별도입니다. Helm과 YAML/Ansible 중 하나가 같은 Deployment·RBAC를 관리하도록 선택합니다. 기존 Ansible 설치 리소스를 Helm이 자동 인수하지 않습니다. `--take-ownership`으로 강제로 옮기지 말고 소유권 migration을 별도로 검토하세요.

CRD는 `crds/`에 있어 Helm uninstall로 삭제되지 않으며 Helm upgrade가 CRD 스키마를 자동 갱신하지 않습니다. 필요 시 검토한 `deploy/manifests/10-crd.yaml`을 별도로 적용합니다. namespace·외부 상태 Secret·TLS 자료도 차트의 삭제 대상이 아닙니다.

## 5. API webhook 연결과 로그인

차트는 호스트의 kube-apiserver static Pod를 수정하지 않습니다. duststack의 `kam-webhook` 전용 진입점은 Helm 소유의 리소스를 덮어쓰지 않고 mTLS webhook만 연결합니다. 기존 `kam-auth`는 Ansible이 auth/controller 설치까지 관리하는 대안입니다. 두 설치 관리 방식을 섞지 마세요.

```bash
# duststack checkout에서 실행. 비밀 없는 연결 변수는 개인 인벤토리에 둡니다.
bash setup-k8s.sh kam-webhook -i inventory/local-lab/hosts.yaml \
  -e kam_confirm_admin=true -e kam_auth_url=https://kam.example.internal:30443 \
  -e kam_auth_tls_dir=/private/kam-pki
```

모든 control plane을 사전 검사한 뒤 한 대씩 변경합니다. 기존 native 인증·API audience는 유지합니다. `--check`와 control plane 일부만 고르는 `--limit`는 거부합니다. 인증 자료가 바뀌면 bundle checksum이 static Pod에 반영되어 재시작을 유발합니다. API readiness와 새 mirror Pod UID·checksum을 확인하며 실패 시 원본 manifest와 dedicated TLS/config를 복구합니다. 새 복구 흐름은 로컬 단위·문법 검사를 거쳤지만 VM에서 실제 적용한 결과는 아직 없습니다.

```bash
kubectl kam login https://kam.example.internal:30443 --username admin \
  --server https://api.example.internal:6443 --ca-file artifacts/kam-pki/kam-ca.crt --api-ca-file cluster-ca.crt
kubectl kam user create alice
kubectl kam grant alice -n dev --profile view
```

## 갱신·삭제 경계

- upgrade 전 외부 계정 Secret을 백업합니다. 차트는 이 Secret을 소유하거나 초기화하지 않습니다.
- controller 소스 변경 시 template checksum으로 Pod를 갱신합니다. CRD/blueprint 변경 후 `python deploy/sync_chart.py`를 실행해 동기화하고 검사합니다.
- 생성한 디렉터리 전체에 `kubectl delete -f artifacts/install`을 실행하면 CRD까지 삭제할 수 있으므로 제거 방법으로 사용하지 않습니다.
- Helm 제거는 권한 회수 명령이 아닙니다. CRD·Grant·기존 Grant Binding은 남으며 controller가 사라지면 만료 조정도 멈춥니다. 권한 종료가 목적이면 먼저 Grant 회수와 native GC 완료를 확인합니다.
- auth 제거 전에 모든 API 서버에서 webhook 설정을 검토한 native 구성으로 복원하고 인증을 확인합니다. 최초 설치 때의 복구용 manifest는 kubelet 감시 디렉터리 밖에 보관합니다. Helm uninstall은 호스트 설정을 자동 복원하지 않습니다.
- 비밀번호·세션 회수는 기존 인증 캐시의 영향을 받습니다. 이미 열린 watch/stream 강제 종료는 구현하지 않았습니다.

## 로컬 검증

```bash
python deploy/sync_chart.py --check
RUN_CHART_VALIDATION=1 GOTOOLCHAIN=go1.26.10 bash tests/validate.sh
```

Helm은 공식 고정 버전·SHA-256으로 내려받거나 `HELM_BINARY`를 공급합니다. 실제 API/etcd에 Helm install·upgrade·uninstall을 실행하고 사용자 로그인·namespace RBAC·권한 회수와 외부 계정 상태·CRD·namespace 보존을 검사합니다. 이 환경에는 kubelet/scheduler가 없으므로 Pod scheduling·image pull·실제 Helm `--wait` 완료와 VM 장애 전환을 입증하지 않습니다. 결과는 `.tools/local-chart-result.json`, `.tools/package-api-result.json`에 기록합니다.

2026-11-02 로컬 실행에서 lint/render 5개 구성, 잘못된 설정 12가지 거부, 실제 Helm lifecycle·로그인 API 13개 검사를 통과했습니다. [실제 API 원문](local-package-api-result.json)을 확인하세요. 이 API/etcd 기록과 별도로 [터미널랩 실제 Pod·TLS·rollback 실증](HELM-LIVE.md)을 완료했고 양쪽 CI도 확인했습니다. 운영 registry 이미지 pull과 CA migration은 사이트별 검토가 필요합니다.
