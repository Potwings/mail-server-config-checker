# QA Test Sheet: 메일 서버 진단 웹 UI

- **Date**: 2026-07-25
- **Tester**: Claude (automated)
- **Target URL**: http://localhost:8080
- **Scope**: 1단계 진단 웹 UI 전체 — 도메인 입력 폼, `/api/v1/diagnose` 연동, 검사 결과 카드 렌더링, 아코디언 동작, 입력 검증/에러 처리
- **Tool**: claude-in-chrome (Playwright MCP 미제공 세션 — 동등 기능으로 대체)
- **환경 비고**: `SPAMHAUS_DQS_KEY` 미설정 → RBL 검사 중 Spamhaus는 SKIP 예상. 실제 DNS 조회가 발생하므로 네트워크 상태에 결과가 좌우될 수 있음

## Test Cases

| ID | Category | Test Name | Precondition | Steps | Expected Result | Result | Note |
|----|----------|-----------|-------------|-------|----------------|--------|------|
| TC-01-001 | Display | 초기 화면 렌더링 | 서버 기동 | 1) `/` 접속 2) 화면 확인 | 제목 "Mail Health Check", 도메인/IP 입력창, 진단 버튼, 안내 문구가 표시된다 | Pass | |
| TC-01-002 | Form | 정상 도메인 진단 | TC-01-001 | 1) domain에 `google.com` 입력 2) 진단 클릭 3) 결과 대기 | 6개 검사 카드(SPF/DMARC/MX/PTR/RBL/전파)가 렌더링되고 상단에 상태 칩 요약과 대상 IP·소요시간 메타가 표시된다 | Pass | `PASS 5 / WARN 1`, 대상 IP 142.251.169.27, 총 6460ms |
| TC-01-003 | Data | API 요청 파라미터 검증 | TC-01-002 | 1) 네트워크 요청 확인 | `GET /api/v1/diagnose?domain=google.com` 이 200으로 호출된다 | Pass | |
| TC-01-004 | Display | 상태 배지/소요시간 표시 | TC-01-002 | 1) 각 카드의 배지·elapsed 확인 | 카드마다 PASS/WARN/FAIL/SKIP/ERROR 배지와 `Nms` 소요시간이 표시된다 | Pass | |
| TC-01-005 | Display | 아코디언 기본 펼침 규칙 | TC-01-002 | 1) 각 카드의 open 상태 확인 | FAIL/ERROR/WARN 카드는 펼쳐지고, PASS/SKIP 카드는 접힌다 | Pass | 5개 상태 전부 확인(TC-01-016에서 FAIL/SKIP/ERROR 동시 검증) |
| TC-01-006 | Display | 접힌 카드 미리보기(peek) | TC-01-002 | 1) 접힌 PASS 카드 확인 | 접힌 상태에서 첫 evidence가 요약으로 보이고, 펼치면 숨겨진다 | Pass | |
| TC-01-007 | Navigation | 카드 클릭 토글 | TC-01-002 | 1) 접힌 PASS 카드 summary 클릭 2) 다시 클릭 | 클릭 시 상세(evidence 목록)가 펼쳐지고, 재클릭 시 접힌다 | Pass | 셰브런 회전·peek 숨김 동반 확인 |
| TC-01-008 | Display | 개선 가이드 노출 | 문제 상태 카드 존재 | 1) WARN/FAIL/SKIP 카드 상세 확인 | guidance가 있으면 "개선 가이드" 블록이 표시된다 | Pass | naver.com DMARC(p=none) WARN에서도 확인 |
| TC-01-009 | Data | Spamhaus DQS 키 미설정 처리 | 키 미설정 | 1) RBL 카드 상세 확인 | Spamhaus는 미등재로 오판하지 않고 SKIP + 키 발급 안내가 표시된다 | Pass | "건너뜀 — DQS 키 미설정" + 발급 URL 노출. Barracuda/SpamCop만 미등재 판정 |
| TC-01-010 | Form | 발신 IP 직접 입력 | TC-01-001 | 1) domain `google.com`, ip `8.8.8.8` 입력 2) 진단 | 대상 IP가 `8.8.8.8`, 출처가 "사용자 입력"으로 표시된다 | Pass | FCrDNS `8.8.8.8 → dns.google → 8.8.8.8` 확인 |
| TC-01-011 | Error | 잘못된 도메인 형식 | TC-01-001 | 1) domain에 `not a domain` 입력 2) 진단 | 결과 카드 대신 빨간 에러 박스에 안내 메시지가 표시된다 | Pass | 400 + "도메인 형식이 올바르지 않습니다: not a domain" |
| TC-01-012 | Error | 잘못된 IP 형식 | TC-01-001 | 1) domain `google.com`, ip `999.1.1.1` 2) 진단 | 400 응답 → 에러 박스가 표시된다 | Pass | "IP 형식이 올바르지 않습니다: 999.1.1.1" |
| TC-01-013 | Form | URL 붙여넣기 정규화 | TC-01-001 | 1) domain에 `https://google.com/mail` 입력 2) 진단 | 호스트만 추출해 `google.com`으로 진단된다 | Pass | 200 + 결과 메타에 `google.com` |
| TC-01-014 | Form | 빈 도메인 제출 차단 | TC-01-001 | 1) domain 비우고 진단 클릭 | HTML required로 제출이 차단되고 API 호출이 없다 | Pass | 네이티브 툴팁 "이 입력란을 작성하세요." |
| TC-01-015 | Display | 진단 중 로딩 표시 | TC-01-001 | 1) 진단 클릭 직후 버튼 확인 | 버튼이 비활성화되고 스피너가 표시된다 | Pass | 완료 후 "진단" 라벨로 복원 확인 |
| TC-01-016 | Error | 존재하지 않는 도메인 | TC-01-001 | 1) domain에 미등록 도메인 입력 2) 진단 | 앱이 깨지지 않고 FAIL/ERROR 상태 카드로 결과가 렌더링된다 | Pass | `FAIL 3 / SKIP 2 / ERROR 1`, "PTR/RBL 대상 IP 확인 불가" |
| TC-01-017 | Error | 콘솔 JS 에러 없음 | 전체 시나리오 수행 후 | 1) 콘솔 에러 확인 | JS 예외가 없다 | Pass | 새로고침 후 전체 진단 재수행하여 로드 시점부터 캡처 |
| TC-01-018 | Display | 좁은 뷰포트 레이아웃 | TC-01-002 | 1) 창을 모바일 폭으로 축소 2) 확인 | 폼이 줄바꿈되고 가로 스크롤 없이 카드가 표시된다 | Pass | clientWidth 486px, scrollWidth 486px (오버플로 없음) |

## Summary

- **Total**: 18
- **Pass**: 18
- **Fail**: 0
- **Skip**: 0
- **Pass Rate**: 100%

## Issues

| Test Case ID | Issue | Severity | Report |
|-------------|-------|----------|--------|
| - | 발견된 결함 없음 | - | - |

## Observations (결함 아님 — 제품 판단 필요)

- **DNS 전파 검사의 Anycast 오탐 가능성**: `google.com` 진단에서 A 레코드가 `1/7 리졸버 일치`로 WARN이 났다. Google처럼 GeoDNS/Anycast로 리졸버마다 다른 A를 회신하는 도메인은 전파가 완료된 상태여도 항상 WARN이 된다. 현재 가이드 문구는 "전파 진행 중일 수 있습니다"로만 안내하고 Quad9 변조 가능성만 언급한다. 다중 A 응답을 집합으로 비교하거나, 불일치 리졸버가 과반인 경우 Anycast 가능성을 가이드에 덧붙이는 개선을 검토할 만하다.
- **DNS 전파 검사가 전체 소요시간을 지배**: 총 6.4초 중 전파 검사가 6.45초로, 나머지 5개 검사 합계(약 0.9초)의 7배다. 리졸버 7곳 중 SK Broadband가 매번 무응답이라 타임아웃까지 대기한다. 리졸버별 병렬화 또는 무응답 리졸버 조기 제외를 검토할 만하다.
