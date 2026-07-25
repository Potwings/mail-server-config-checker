# QA Sheet: 다중 발신 IP 지원 (시트 02)

- 대상: http://localhost:8080 (bootRun, local 프로필)
- 범위: 진단 폼 쉼표 구분 다중 IP 입력, 상단 대상 IP 목록 표시, PTR/RBL 카드의 IP별 결과 표시, 입력 검증 에러(형식 오류·5개 초과)
- 사전 조건: 서버 기동, 외부 DNS 조회 가능
- 작성일: 2026-07-26

## Test Cases

| ID | Category | Test | Precondition | Steps | Expected | Result | Note |
|----|----------|------|--------------|-------|----------|--------|------|
| TC-02-001 | Display | 다중 IP 입력 안내 문구 | 서버 기동 | 1) `/` 접속 2) IP 입력창/힌트 확인 | placeholder에 "쉼표로 여러 개", 힌트에 최대 개수 안내가 표시된다 | Pass | QA 후 상한 5→20 완화, 힌트 문구 "최대 20개" 반영 확인 |
| TC-02-002 | Form | 단일 IP 진단 (회귀) | TC-02-001 | 1) domain `google.com`, ip `8.8.8.8` 2) 진단 | 대상 IP `8.8.8.8` — 사용자 입력. PTR/RBL evidence에 `[ip]` 태그가 없다 | Pass | FCrDNS `8.8.8.8 → dns.google → 8.8.8.8`, RBL 3사 미등재 |
| TC-02-003 | Form | 다중 IP 진단 | TC-02-001 | 1) domain `google.com`, ip `8.8.8.8, 1.1.1.1` 2) 진단 | 상단 메타에 "대상 IP: 8.8.8.8, 1.1.1.1 — 사용자 입력" 표시 | Pass | |
| TC-02-004 | Display | PTR 카드 IP별 결과 | TC-02-003 | 1) PTR 카드 상세 확인 | 두 IP 각각 `[8.8.8.8]`, `[1.1.1.1]` 태그로 FCrDNS 결과가 나열된다 | Pass | `[1.1.1.1] FCrDNS 확인: 1.1.1.1 → one.one.one.one → 1.1.1.1` |
| TC-02-005 | Display | RBL 카드 IP별 결과 | TC-02-003 | 1) RBL 카드 상세 확인 | 활성 RBL별로 두 IP의 등재 여부가 `[ip]` 태그로 나열되고, 비활성(Spamhaus) 안내는 1회만 표시된다 | Pass | 로컬 DQS 키 설정으로 Spamhaus 활성 — 3사 × 2IP = 6줄 확인. 비활성 1회 안내는 단위 테스트로 커버 |
| TC-02-006 | Data | API 다중 IP 파라미터 | TC-02-003 | 1) 네트워크 요청 확인 | `GET /api/v1/diagnose?domain=...&ip=...` 200, 응답 `targetIps`가 배열이다 | Pass | 200 + `targetIps` 배열 2개 (API 직접 호출로 확인) |
| TC-02-007 | Error | 다중 IP 중 형식 오류 | TC-02-001 | 1) domain `google.com`, ip `8.8.8.8,abc` 2) 진단 | 400 → 에러 박스 "IP 형식이 올바르지 않습니다: abc" | Pass | |
| TC-02-008 | Error | IP 개수 상한 초과 | TC-02-001 | 1) domain `google.com`, ip 상한+1개 입력 2) 진단 | 400 → 에러 박스 "IP는 최대 N개까지..." | Pass | 상한 5 기준 브라우저 확인 후, 상한 20 완화분은 API로 재검증(6개→200, 21개→400) |
| TC-02-009 | Form | 중복/공백 항목 정리 | TC-02-001 | 1) ip `8.8.8.8, 8.8.8.8,, 1.1.1.1` 2) 진단 | 중복·빈 항목이 제거되어 대상 IP가 `8.8.8.8, 1.1.1.1` 2개로 표시된다 | Pass | |
| TC-02-010 | Form | IP 미입력 시 MX 자동 도출 (회귀) | TC-02-001 | 1) domain `google.com`, ip 비움 2) 진단 | 대상 IP가 MX A 레코드에서 도출되어 표시된다 (worst-of 상태 정상) | Pass | A 레코드 5개 전부 대상 — PTR/RBL 모두 PASS |
| TC-02-011 | Error | 콘솔 JS 에러 없음 | 전체 시나리오 후 | 1) 새로고침 후 다중 IP 진단 재수행 2) 콘솔 에러 확인 | JS 예외가 없다 | Pass | 페이지 로드부터 추적 |

## Summary
- Total: 11
- Pass: 11
- Fail: 0
- Skip: 0
- Pass Rate: 100%
