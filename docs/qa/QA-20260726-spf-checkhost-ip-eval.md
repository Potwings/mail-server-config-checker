# QA Test Sheet: SPF 발신 IP check_host 평가

- **Date**: 2026-07-26
- **Tester**: Claude (automated)
- **Target URL**: http://localhost:8080
- **Scope**: 발신 IP 입력 시 SPF check_host() 평가 — 미허용 IP FAIL, 허용 IP PASS, 미입력 시 안내 문구, 다중 IP worst-of 집계, 아코디언 동작

## Test Cases

| ID | Category | Test Name | Precondition | Steps | Expected Result | Result | Note |
|----|----------|-----------|-------------|-------|----------------|--------|------|
| TC-03-001 | Data | 미허용 IP 입력 시 SPF FAIL | 서버 실행 중 | 1) 접속 2) 도메인 gmail.com 입력 3) IP 1.2.3.4 입력 4) 진단 실행 | SPF 카드 FAIL, evidence에 "softfail — 이 IP는 SPF 허용 목록에 포함되지 않음", guidance에 ip4:<IP> 추가 안내 | Pass | `redirect=_spf.google.com` 체인 추적 후 `~all` 매칭 |
| TC-03-002 | Display | FAIL 카드 자동 펼침 | TC-03-001 실행 상태 | 1) SPF 카드 상태 확인 | FAIL 상태의 SPF 카드가 자동으로 펼쳐져 evidence가 보임 | Pass | |
| TC-03-003 | Data | 허용 IP 입력 시 SPF PASS | 서버 실행 중 | 1) 도메인 gmail.com 입력 2) IP 209.85.128.1 입력 3) 진단 실행 | SPF 카드 PASS, evidence에 "평가: pass (매칭: ip4:209.85.128.0/17)" | Pass | redirect → include 재귀 평가 정상 |
| TC-03-004 | Data | IP 미입력 시 레코드 린트만 + 안내 문구 | 서버 실행 중 | 1) 도메인 gmail.com 입력 2) IP 비움 3) 진단 실행 | SPF 카드에 "발신 서버 IP를 입력하면 ... 평가합니다" 안내 evidence 표시, MX 도출 IP로는 SPF 평가하지 않음 | Pass | MX 도출 IP는 PTR/RBL에만 사용됨 확인 |
| TC-03-005 | Data | 다중 IP worst-of 집계 및 [ip] 태그 | 서버 실행 중 | 1) 도메인 gmail.com 입력 2) IP "209.85.128.1, 1.2.3.4" 입력 3) 진단 실행 | SPF 카드 FAIL(worst-of), evidence에 [209.85.128.1] pass, [1.2.3.4] softfail 각각 태그 표시 | Pass | 초기 실행 시 IP 중복 표기 발견 → ISSUE-01 수정 후 재검증 Pass |
| TC-03-006 | Display | 입력 힌트 문구 갱신 확인 | 서버 실행 중 | 1) 메인 페이지 접속 2) IP 입력란 아래 힌트 확인 | "발신 IP를 입력하면 SPF 허용 여부(check_host)·PTR·RBL을 그 IP 기준으로 검사" 문구 표시 | Pass | |
| TC-03-007 | Error | 콘솔/네트워크 오류 없음 | TC-03-001~005 수행 후 | 1) 콘솔 메시지 확인 2) diagnose API 응답 코드 확인 | JS 콘솔 에러 없음, /api/v1/diagnose 200 응답 | Pass | |

## Summary

- **Total**: 7
- **Pass**: 7
- **Fail**: 0
- **Skip**: 0
- **Pass Rate**: 100%

## Issues

| Test Case ID | Issue | Severity | Report |
|-------------|-------|----------|--------|
| TC-03-005 | 다중 IP일 때 evidence에 IP가 중복 표기 (`[1.2.3.4] 발신 IP 1.2.3.4 평가: ...`) — 테스트 중 수정 완료 | Minor | [report](issues/TC-03-005-다중IP-중복표기/report.md) |
