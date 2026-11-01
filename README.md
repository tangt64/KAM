# KIKI KAM

기존 [tangt64/KAM](https://github.com/tangt64/KAM)의 Git 이력을 유지하는 Kubernetes 로그인·namespace 권한 관리 도구입니다. GitHub `tangt64/KAM`과 Gitea `dustbox/kiki-kam`에서 같은 소스를 관리합니다.

ID·비밀번호 → 전용 HTTPS 인증 서비스 → 단기 불투명 세션 → mTLS TokenReview → Kubernetes RBAC 순서로 동작합니다. OIDC 서버는 필요하지 않습니다. 계정은 Kubernetes 내장 User 리소스가 아니라 KAM 계정이며, namespace 권한은 `KamAccessGrant` CRD/controller가 조정합니다.

## 빌드와 kubectl 플러그인

Go 1.26.10, Python 3.12+, PyYAML 6.0.3, kubectl, OpenSSL을 사용합니다. 실행 파일과 인증서는 Git에 넣지 않습니다.

```bash
GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 go build -buildvcs=false -trimpath -o .tools/kiki-kam .
install -m 0755 .tools/kiki-kam "$HOME/.local/bin/kubectl-kam"
export PATH="$HOME/.local/bin:$PATH"
kubectl kam --help
```

Windows는 `GOOS=windows`로 빌드하고 사용자 PATH에 `kubectl-kam.exe`를 배치합니다. Unix 세션 캐시는 0600, 디렉터리는 0700입니다. Windows에서는 사용자 전용 ACL도 관리자가 확인해야 합니다. kubeconfig의 exec 경로에 설치한 실행 파일을 유지하세요.

## 설치

권장 설치 경로는 [duststack 연동 안내](https://github.com/tangt64/duststack-k8s-auto/blob/master/docs/KIKI-KAM.md)입니다. 기존 인증서·ServiceAccount 인증을 유지하고 API 서버를 한 대씩 변경합니다. 아래는 수동 설치 구성요소 설명입니다. 예시 도메인과 digest는 실제 환경 값으로 바꿔야 합니다.

1. 기존 관리 자격으로 `kam-system`과 대상 namespace를 준비합니다. 두 replica를 실행할 서로 다른 스케줄 가능한 노드가 필요합니다.
2. `podman build -t REGISTRY/kiki-kam-auth:0.2.0 .` 후 승인된 레지스트리에 push하고 manifest digest를 확인합니다. `deploy/render_auth.py --image REGISTRY/IMAGE@sha256:실제해시 --audience 기존APIaudience`로 렌더링합니다. 리뷰한 이미지를 쓰며 공개된 공식 KAM 이미지는 아직 없습니다.
3. `python deploy/make_tls.py --out artifacts/kam-pki --hostname kam.example.internal`로 별도 CA, 서버 인증서와 `kiki-kam-apiserver` mTLS 클라이언트 인증서를 만듭니다. 클러스터 CA를 재사용하지 않습니다. leaf는 90일, CA는 10년이며 `--renew`는 동일 CA로 leaf만 교체합니다. CA 키는 배포하지 않고 별도로 보호합니다.
4. TLS Secret `kiki-kam-tls`와 공개 클라이언트 CA ConfigMap `kiki-kam-webhook-ca`를 `kam-system`에 준비합니다. 검증된 HTTPS 경로에서 일반 로그인과 클라이언트 인증서를 전달하는 `/authenticate`가 모두 도달해야 합니다. TLS 종료 프록시가 mTLS 정보를 없애면 사용할 수 없습니다. 기본 Service는 ClusterIP이며 외부 라우팅을 자동 생성하지 않습니다.
5. `python deploy/render_auth.py --state-only | kubectl create -f -`로 계정 Secret을 최초 한 번만 만듭니다. 재설치에 `apply`하여 덮어쓰지 않습니다. `kubectl kam --kubeconfig ADMIN.conf bootstrap --username admin`으로 첫 계정을 초기화합니다. 기본 비밀번호는 없고 기존 native 관리 인증이 필요합니다.
6. 인증 Deployment를 적용하고 두 replica의 readiness를 확인합니다. API 서버에 전용 mTLS webhook kubeconfig를 설치하고 `--authentication-token-webhook-config-file=...`, `--authentication-token-webhook-version=v1`, `--authentication-token-webhook-cache-ttl=5s`를 추가합니다. 기존 `--api-audiences` 또는 service account issuer에서 얻은 audience를 auth 서비스에 전달합니다. 기존 native 인증 설정은 보존합니다. 실제 변경·백업·복구는 duststack playbook을 권장합니다.
7. `deploy/render.py --namespace dev`로 CRD/controller를 설치합니다. 기본 허용 프로필은 `view`이며 `edit`/`admin`은 명시적으로 설치 범위를 확장한 경우만 허용합니다.

## 로그인과 사용자 관리

아래는 **사용 예시**이며 특정 운영 환경에서 실행한 화면이 아닙니다. 비밀번호는 숨김 프롬프트로 입력합니다. 자동화는 `--password-stdin`을 사용하고 명령 인자·로그·Git에 비밀번호를 넣지 않습니다.

```bash
kubectl kam login https://kam.example.internal --username admin \
  --server https://api.example.internal:6443 \
  --ca-file kam-ca.crt --api-ca-file cluster-ca.crt
kubectl kam whoami
kubectl kam user create alice
kubectl kam user list
kubectl kam grant alice -n dev --profile view
kubectl kam get -n dev
kubectl kam permissions -n dev
kubectl kam namespace list
kubectl kam namespace use dev
kubectl kam user passwd alice
kubectl kam user revoke-sessions alice
kubectl kam user disable alice
kubectl kam user enable alice
kubectl kam user delete alice
kubectl kam logout
```

일반 사용자는 같은 login 명령으로 자신의 계정에 로그인하고 `kubectl get pods -n dev`, `kubectl kam passwd`, `whoami`, `logout`을 사용합니다. 최초 로그인은 실제 SelfSubjectReview의 username과 UID를 확인한 뒤 kubeconfig를 저장합니다. 비밀번호는 저장하지 않으며 kubeconfig는 세션 파일 경로를 참조하는 exec credential만 가집니다. 세션 파일에는 비밀 토큰이 있으므로 사용자만 읽도록 보호하세요.

계정 관리자는 사용자·세션과 Grant를 관리할 수 있지만 Kubernetes `cluster-admin`은 아닙니다. 일반 사용자는 namespace 이름/메타데이터 목록을 볼 수 있지만 다른 namespace의 Pod·Secret에는 접근할 수 없습니다. namespace 관리는 목록·현재 namespace 선택·namespace별 RBAC 부여/회수이며 namespace 생성·삭제는 기존 Kubernetes 관리자에게 남깁니다.

`grant/revoke`는 로그인 이름을 불변 내부 UID인 `kiki-kam:<ID>`로 변환합니다. 같은 이름으로 재생성해도 이전 권한을 물려받지 않습니다. `--expires-at 2026-12-01T00:00:00Z`로 Grant 만료를 지정할 수 있습니다. disable/delete CLI는 먼저 인증을 차단한 다음 동일 UID의 Grant를 정리합니다. 정리 실패는 오류로 반환하므로 관리자가 재시도해야 합니다. HTTP 계정 API만 직접 호출한 경우 Grant 정리는 별도입니다. 최후의 활성 계정 관리자는 삭제·비활성화할 수 없습니다.

## 운영 경계

- bcrypt 비밀번호는 12~72 UTF-8 바이트입니다. 세션 기본 1시간(설정 범위 5분~24시간), 사용자당 5개입니다. 비밀번호 변경·계정 비활성화·삭제·연결 변경은 기존 세션을 폐기합니다. 서비스의 세션 폐기와 API 서버 인증 캐시의 폐기는 구별됩니다.
- Kubernetes 1.37 실제 API 검사에서 비밀번호 초기화·로그아웃·계정 비활성화 후 기존 토큰 거부까지 약 10초가 걸렸습니다. webhook TTL 외에 API 서버의 외부 성공 캐시(기본 10초)가 존재합니다. 즉시 차단이나 고정된 최대 시간을 보장하지 않습니다. 이미 열린 watch/stream 강제 종료는 구현하지 않았습니다.
- 계정·세션 상태는 `kam-system/kiki-kam-identities` Secret 한 개에 저장합니다. auth SA는 이 Secret의 get/update만 가지며 resourceVersion CAS로 replica 간 충돌을 방지합니다. 별도 DB는 없고 소규모 사용(500개 계정, JSON 900KB 제한)을 대상으로 합니다. 삭제 계정 이력도 공간을 사용합니다. 대규모 도입 전에 별도 저장소가 필요합니다.
- etcd 저장 암호화, 관리자 접근 제한, Secret 백업과 복구를 운영자가 구성해야 합니다. 백업에는 해시·세션 정보가 있으므로 암호화하고 접근을 제한합니다. 재설치가 계정을 초기화하지 않지만 Secret을 삭제하면 로그인 상태를 잃습니다. native 관리 인증을 비상 접근으로 유지합니다.
- 로그인 제한은 replica별 IP/계정당 분당 20회입니다. 인터넷 공개 시 앞단의 공유 rate limit과 TLS 경로를 별도 검토합니다. 계정·세션 로그에 비밀번호나 토큰을 기록하지 않습니다.
- `kam-system`에 일반 사용자의 Pod 생성/edit/admin을 주지 않습니다. auth 서비스 장애 시 KAM 신규 인증은 실패하며 native 인증은 유지합니다. CRD 삭제는 권한 Binding의 GC를 유발할 수 있습니다. 외부 Binding으로 부여한 권한은 KAM이 회수하지 않습니다.

## 향후 OIDC

인증은 `Provider` 인터페이스, 검증된 외부 identity와 내부 UID 연결로 분리했습니다. 현재 기본 구현은 local 비밀번호뿐입니다. OIDC 연결은 **아직 구현되지 않았습니다**. 이후 issuer discovery/JWKS, 서명·issuer·audience·expiry, state/nonce/PKCE를 검증하는 provider와 CLI browser flow를 추가해야 합니다. 검증된 `(issuer, sub)`만 `user link USER --provider PROVIDER --subject IMMUTABLE_SUBJECT`로 명시적 연결합니다. 이메일·표시 이름 자동 연결은 하지 않으며 내부 UID와 기존 RBAC는 유지합니다. 단위 검사는 mock 외부 provider의 명시적 연결만 검증합니다.

## 테스트와 이력

```bash
python3 -m pip install -r requirements.txt
GOTOOLCHAIN=go1.26.10 bash tests/validate.sh
```

Go race 검사, 공식 Kubernetes 1.37.0 envtest 실제 API/etcd의 CRD·Lease·RBAC 검사, 비밀번호 로그인→exec credential→실제 사용자 API 호출과 폐기 검사를 실행합니다. `--as`를 사용하지 않습니다. 결과는 `.tools/auth-api-result.json`에 비밀 없이 저장합니다. 두 auth 프로세스가 같은 Secret을 공유하는 것도 검사합니다. [검증 기록](docs/VALIDATION.md)을 확인하세요. kubelet·scheduler·native GC·실제 Pod 배치와 VM HA는 이번 새 로그인 검사의 범위 밖입니다.

원래 명령은 `kam legacy user/group/sa ...`로 보존했습니다. [원본 README](docs/LEGACY.md)는 이력 참고이며 기존 logical User/RBAC 명령 자체가 로그인 계정을 생성하지는 않습니다. root `LICENSE`의 GPL-3.0 이력과, 독립 실행 Python controller의 `deploy/LICENSE` GPL-2.0을 유지합니다.
