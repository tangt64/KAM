# 2026-11-01 검증 기록

Go 1.26.10 race 검사와 공식 Kubernetes 1.37.0 envtest API/etcd 검사를 WSL Rocky-9에서 통과했습니다. [원문 결과](auth-api-result.json)는 자격증명을 제외한 실제 실행 기록입니다. 새 테스트의 10개 조건이 모두 통과했습니다.

- ID·비밀번호 로그인, SelfSubjectReview의 실제 UID, namespace RBAC 허용/거부와 권한 상승 거부 (`--as` 없음)
- exec credential·개인 캐시, auth 프로세스 2개의 동일 Secret CAS 공유
- auth SA의 단일 Secret 권한, 다른 Secret/Pod 접근 거부
- 비밀번호 변경·서버 로그아웃·비활성화 후 이전 세션 회수
- 재활성화·삭제/같은 이름 재생성으로 이전 권한이 복원되지 않음
- 실제 사용자 Grant 만료 후 접근 거부, 재설치 계정 보존
- 전용 mTLS 인증서 없는 webhook 호출 거부, 마지막 관리자 보존

이번 실행에서 비밀번호 초기화 9.192초, 로그아웃 10.101초, 비활성화 9.997초 후 API가 기존 자격을 거부했습니다. API 서버 외부 성공 캐시가 있어 webhook TTL 1초만으로 즉시 회수되지 않습니다. 운영 설치는 webhook TTL 5초이며 이 수치는 loopback의 측정값으로 운영 SLO가 아닙니다. 이미 열린 watch/stream 종료는 검사·구현하지 않았습니다.

기존 controller suite의 CRD/CEL, namespace bind, 중복 조정, Lease 경쟁·반납·인수, 상승 거부·만료도 통과했습니다. 실제 API를 실행하지만 kubelet·scheduler·controller-manager가 없으므로 Deployment의 server dry-run/apply는 Pod 실행·native GC·이미지 pull을 입증하지 않습니다. auth 프로세스 두 개의 상태 공유는 검사했으나 Pod/VM 장애 전환은 이번 범위 밖입니다. 기존 duststack HA 전용 랩은 재개하지 않았습니다.

컨테이너는 고정 Go builder digest와 scratch/nonroot로 빌드합니다. 레지스트리 push와 Kubernetes Pod rollout은 별도 배포 단계입니다. CI는 같은 tests/validate.sh를 실행하며 외부 클러스터 접근 자격을 요구하지 않습니다.
