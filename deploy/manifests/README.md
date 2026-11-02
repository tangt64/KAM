# 로컬 YAML

`10-crd.yaml`은 실제 CRD 정의입니다. 계정 초기 상태는 별도 `../bootstrap/identity-state.yaml`로 최초에만 create합니다.
실제 설치 리소스는 `python deploy/render_install.py -f deploy/values-local.yaml --audience 기존APIaudience --output artifacts/install`로 생성합니다.
생성 결과에는 비밀번호·TLS private key·계정 Secret이 없습니다. 자세한 순서는 [로컬 설치 안내](../../docs/LOCAL-INSTALL.md)를 따릅니다.
