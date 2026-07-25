# QA Test Sheet: M5.5 RBL 커버리지 확대 + Spamhaus DBL 도메인 RBL 검사

- **Date**: 2026-07-26
- **Tester**: Claude (automated)
- **Target URL**: http://localhost:8080
- **Scope**: M5.5 신규 기능 — IP RBL 프로바이더 3종(PSBL·Mailspike·Hostkarma) 추가 및 도메인 RBL(Spamhaus DBL) 검사 카드 신설. 기존 UI 회귀는 QA-20260725 시트에서 검증 완료이므로 신규 기능 중심으로 진행
- **Tool**: claude-in-chrome
- **환경 비고**: `application-local.yml`에 Spamhaus DQS 키 설정됨(bootRun 기본 local 프로필) → ZEN·DBL 실조회 활성. 실제 DNS 조회가 발생하므로 네트워크 상태에 결과가 좌우될 수 있음. RBL 등재 검증은 표준 테스트 포인트(IP `127.0.0.2`, 도메인 `dbltest.com`) 사용

## Test Cases

| ID | Category | Test Name | Precondition | Steps | Expected Result | Result | Note |
|----|----------|-----------|-------------|-------|----------------|--------|------|
| TC-02-001 | Display | 검사 카드 7개 렌더링 | 서버 기동 | 1) `/` 접속 2) domain `google.com` 진단 3) 카드 수 확인 | 기존 6개 + "도메인 RBL 등재 여부 (DBL)" 카드가 추가되어 7개 카드가 렌더링된다 | Pass | `PASS 6 / WARN 1`(WARN은 기존 관찰사항인 전파 검사 Anycast 오탐), `details` 7개 |
| TC-02-002 | Display | RBL 카드 신규 프로바이더 3종 표시 | TC-02-001 | 1) RBL 카드 상세 확인 | PSBL·Mailspike·Hostkarma 판정 라인이 표시되고, google.com 발신 IP 기준 3종 모두 "미등재"로 판정된다 | Pass | MX 도출 IP 5개 × 6프로바이더 = 30라인 전부 미등재 |
| TC-02-003 | Data | Spamhaus ZEN DQS 키 활성 | DQS 키 설정 | 1) RBL 카드에서 Spamhaus ZEN 라인 확인 | SKIP(키 미설정 안내)이 아니라 실제 판정(미등재)이 표시된다 | Pass | local 프로필로 키 로드 확인 |
| TC-02-004 | Display | DBL 카드 미등재 PASS + 접힘 | TC-02-001 | 1) 도메인 RBL 카드 상태·펼침 확인 2) 펼쳐서 상세 확인 | PASS 배지 + 기본 접힘, 상세에 "검사 대상 도메인: google.com"과 "Spamhaus DBL (DQS): 미등재"가 표시된다 | Pass | 접힌 상태 peek에 첫 evidence 노출도 확인, 713ms |
| TC-02-005 | Data | API 응답에 domain-rbl 포함 | TC-02-001 | 1) `/api/v1/diagnose` 응답 JSON 확인 | results 배열에 `checkId: "domain-rbl"` 항목이 있고 status가 PASS다 | Pass | checkIds: spf/dmarc/mx/ptr/rbl/domain-rbl/propagation, HTTP 200 |
| TC-02-006 | Data | DBL 등재 도메인 FAIL 판정 | 서버 기동 | 1) domain `dbltest.com` 진단 2) 도메인 RBL 카드 확인 | FAIL 배지 + 자동 펼침, "등재됨 — 스팸 도메인 [127.0.1.2]" evidence와 check.spamhaus.org 해제 가이드가 표시된다 | Pass | `open=true` 자동 펼침 확인. MX 없는 도메인이라 PTR/RBL은 SKIP(정상) |
| TC-02-007 | Data | RBL 테스트 IP 등재 판정 (worst-of FAIL) | 서버 기동 | 1) domain `google.com`, ip `127.0.0.2` 진단 2) RBL 카드 확인 | RBL 카드가 FAIL이 되고 신규 프로바이더(PSBL/Mailspike/Hostkarma) 중 1개 이상에서 "등재됨" + 리스트명이 표시된다 | Pass | 신규 3종 전부 등재 판정 — PSBL(스팸트랩), Mailspike(Z리스트+L3~L5), Hostkarma(블랙+브라운). 자동 펼침·개선 가이드 동반 확인 |
| TC-02-008 | Data | DQS 키 비노출 | TC-02-005, TC-02-006 | 1) 화면 텍스트·응답 JSON에서 키 문자열 검색 | DQS 키가 UI와 API 응답 어디에도 노출되지 않는다 | Pass | 미등재(google.com)·등재(dbltest.com) 응답 모두 키 문자열 미포함 |
| TC-02-009 | Error | 콘솔 JS 에러 없음 | 전체 시나리오 수행 후 | 1) 콘솔 에러 확인 | JS 예외가 없다 | Pass | 새로고침 후 전체 진단 재수행하여 로드 시점부터 캡처, 에러 0건 |

## Summary

- **Total**: 9
- **Pass**: 9
- **Fail**: 0
- **Skip**: 0
- **Pass Rate**: 100%

## Issues

| Test Case ID | Issue | Severity | Report |
|-------------|-------|----------|--------|
| - | 발견된 결함 없음 | - | - |

## Observations (결함 아님 — 제품 판단 필요)

- **Mailspike 리턴 코드 매핑 범위**: 테스트 IP(127.0.0.2) 조회 시 `127.0.0.13`이 "알 수 없는 리턴 코드"로 표시됐다. Mailspike 평판 코드는 L1(127.0.0.14)까지 존재하며 bl.mailspike.net 테스트 엔트리는 전체 코드를 반환한다. 알 수 없는 코드도 등재로 안전하게 처리되므로 결함은 아니지만, L2(127.0.0.13)·L1(127.0.0.14) 매핑 추가를 검토할 만하다.
- **DBL FAIL 도메인의 부수 효과**: dbltest.com처럼 MX가 없는 도메인은 PTR/RBL이 SKIP되어 DBL 결과만 남는다. 실사용 시나리오(정상 메일 도메인이 DBL에 등재)에서는 7개 카드가 모두 채워지므로 문제 없음.
