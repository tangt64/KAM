# Helm·TLS 실제 클러스터 검증 — 2026-11-02

터미널랩의 Kubernetes/CRI-O 1.37.2, control plane 3대·worker 2대·LB 2대에서 로컬 소스 차트 0.1.0과 Helm 4.3.1을 실행했습니다. KAM 실행 소스는 `07f4f03ef2f0005abd995fc415efeb61f2e6662e`, 실증 도구는 duststack `d6ef7e1046c9f540f121f7566a40294060f1719a`입니다. [실증 원문](helm-live-result.json)과 [전체 절차·복구 경계·정리 원문](https://github.com/tangt64/duststack-k8s-auto/blob/614ef8c1a3cc23e5547966850acc1ce4336f9bbd/docs/KAM-HELM-LIVE.md)을 확인하세요.

- Helm `--wait` 실제 Pod 배포: auth 2개·controller 2개, 서로 다른 worker Ready.
- 실제 비밀번호 로그인·namespace Pod 조회 허용·Secret Forbidden·권한 회수, impersonation 미사용.
- 동일 CA의 server/client leaf 갱신, NodePort가 제공하는 인증서 지문 변경, 새 API mirror UID·Ready와 기존 사용자 세션 접근 확인.
- 잘못된 client key는 사전 거부하고 세 노드의 파일 해시를 유지.
- CP02에 실제 잘못된 API 옵션을 주입해 시작 실패·연결 거부를 관측한 뒤 manifest·CA·client cert/key·webhook을 이전 bytes로 복원. CP01은 갱신, CP03은 미변경. 원본 playbook 재실행으로 정상화.
- 없는 로컬 이미지의 Helm 갱신 실패 후 정상 이미지·Ready Pod로 rollback, 계정 Secret data 보존.
- Helm uninstall 후 외부 계정 Secret·CRD 보존을 확인하고, 별도 테스트 데이터 정리와 native API 원복을 완료.

아래는 실제 터미널과 실증 원문 열람 화면입니다. Pod 화면 상단에는 직전 장애 주입의 복구 메시지가 남아 있으며 아래 신규 Pod 행은 최종 실증의 배포 완료 시점입니다. TLS Ready 값은 갱신 완료 시점의 기록입니다. 17번은 GitHub에 게시한 실제 복구 원문입니다. 예상 실행 예시는 [설치 안내](LOCAL-INSTALL.md)의 코드 블록과 구분합니다.

![실제 Helm Pod 배치](https://raw.githubusercontent.com/tangt64/duststack-k8s-auto/614ef8c1a3cc23e5547966850acc1ce4336f9bbd/docs/screenshots/15-kam-helm-pods.jpg)

![실제 TLS 갱신](https://raw.githubusercontent.com/tangt64/duststack-k8s-auto/614ef8c1a3cc23e5547966850acc1ce4336f9bbd/docs/screenshots/16-kam-tls-renewal.jpg)

![실제 실패 후 복구](https://raw.githubusercontent.com/tangt64/duststack-k8s-auto/614ef8c1a3cc23e5547966850acc1ce4336f9bbd/docs/screenshots/17-kam-bundle-rollback.jpg)

테스트는 전용 랩에서만 수행합니다. 서버 TLS Secret은 Helm 외부 자원이며 노드별 client bundle 복구와 별도로 관리합니다. CA 교체·endpoint migration·기존 장기 watch/TCP 세션의 무중단 유지는 이번 범위가 아닙니다. API 재시작 구간에 별도 조회의 일시적 EOF/timeout도 관측했습니다.

실증 후 임시 SSH 키를 제거하고 전용 VM 7대를 중지했습니다. 기존 controller·CRD·CNI/CIDR/API VIP는 유지했습니다. 이 문서 변경은 검증한 runtime·차트 코드를 바꾸지 않습니다.
