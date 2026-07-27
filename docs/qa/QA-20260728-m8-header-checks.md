# QA 시트 — M8 헤더 기반 검사 + 이관 항목

- **작성일**: 2026-07-28
- **대상**: http://localhost:8080 (bootRun, local 프로필)
- **범위**: M8 신규 검사(DKIM·DMARC Alignment·헤더 품질·MTA-STS/TLS-RPT·HELO/PTR·RBL IPv6)의 UI 노출
- **사전 조건**: 실메일 수신 인프라 없이 수집 디렉터리(`C:/mailcheck-dev/incoming`)에 픽스처 디렉터리를 수동 적재해 인테이크를 구동. DNS/HTTP 조회는 실 네트워크 사용 — 검사 상태값(PASS/FAIL)은 대상 도메인의 실제 DNS에 따르므로, 본 QA는 **카드 렌더링·문구·evidence 노출**을 검증 기준으로 한다
- **픽스처**:
  - A(IPv4): client_ip `8.8.8.8`, helo `dns.google`(PTR과 일치), MAIL FROM/From `user@gmail.com`, DKIM 서명 없음, 표준 헤더 완비
  - B(IPv6): client_ip `2001:4860:4860::8888`, Message-ID 없는 eml (헤더 품질 FAIL 유도)
  - C(IPv6 재검증): B와 동일 IP, 정상 헤더 — 이슈 수정 후 재검증용

## 테스트 케이스

| ID | 카테고리 | 테스트명 | 테스트 단계 | 기대 결과 | 결과 | 비고 |
|---|---|---|---|---|---|---|
| TC-01-001 | UI | 발급 화면 검사 항목 문구 | 초기 화면 진입 | 검사 항목 나열에 DKIM·DMARC Alignment·MTA-STS/TLS-RPT·헤더 품질 포함, "(DKIM 예정)" 문구 없음 | Pass | 11개 항목 전부 표기 확인 |
| TC-01-002 | 기능 | 주소 발급 | "테스트 주소 발급하기" 클릭 | check-{uuid}@ 주소와 대기 화면 표시, URL이 /?s={id}로 변경 | Pass | 카운트다운(23시간 59분) 정상 |
| TC-01-003 | 기능 | 픽스처 A 인테이크 | incoming에 픽스처 A 적재 후 폴링 대기 | 결과 카드(DIAGNOSED) 자동 생성 | Pass | 총 11개 검사, 1039ms |
| TC-01-004 | UI | 신규 검사 카드 렌더링 | 픽스처 A 카드 펼침 | DKIM / DMARC Alignment / 헤더 품질 / MTA-STS·TLS-RPT 카드가 기존 카드와 함께 표시 | Pass | 4종 모두 렌더링. DMARC 카드에 외부 리포트 승인 evidence(google.com←gmail.com)도 확인 |
| TC-01-005 | 기능 | HELO/PTR 일치 evidence | PTR 카드 확인 | "HELO(dns.google)와 PTR 호스트명 일치" evidence 표시 | Pass | 실 DNS FCrDNS 왕복 + HELO 일치 |
| TC-01-006 | 기능 | DKIM 서명 없음 FAIL | DKIM 카드 확인 | FAIL 상태 + "DKIM-Signature 헤더가 없음" evidence + 가이드, 문제 카드 자동 펼침 | Pass | |
| TC-01-007 | 기능 | RBL IPv6 존 제외 표시 | 픽스처 B 적재 후 RBL 카드 확인 | IPv6 미지원 존 제외 evidence(Barracuda/SpamCop 등 나열), ZEN은 nibble 조회 수행 | Pass | ZEN(DQS) nibble 실조회 "미등재", 미지원 존 5개 나열. **수행 중 PTR IPv6 오탐 결함 발견 → 이슈 기록·수정** |
| TC-01-008 | 기능 | 헤더 품질 FAIL | 픽스처 B의 헤더 품질 카드 확인 | Message-ID 부재 FAIL evidence + 가이드 표시 | Pass | |
| TC-01-009 | 안정성 | 콘솔/네트워크 오류 | 전 과정에서 콘솔·네트워크 확인 | JS 콘솔 에러 없음, API 4xx/5xx 없음 | Pass | 폴링 GET 전부 200, 새로고침 세션 복원 정상 |
| TC-01-010 | 재검증 | IPv6 FCrDNS 오탐 수정 확인 | 수정 배포 후 픽스처 C 적재 | PTR 카드 통과(FCrDNS 왕복 확인) | Pass | 카드 #3 PTR 통과. 기존 카드 #2는 수정 전 결과 그대로 보존(append-only) |

## 발견 이슈

| 이슈 | 내용 | 상태 |
|---|---|---|
| [TC-01-007-IPv6-FCrDNS-표기비교-오탐](issues/TC-01-007-IPv6-FCrDNS-표기비교-오탐/report.md) | IPv6 FCrDNS 왕복 비교가 문자열 비교라 압축/완전 표기 차이로 오탐 FAIL — `PtrCheck`에 RFC 5952 정규형 비교 도입으로 수정, 단위 테스트 추가 | 수정·재검증 완료 |

## Summary
- Total: 10
- Pass: 10
- Fail: 0 (발견 결함 1건은 세션 내 수정 후 재검증 Pass)
- Skip: 0
- Pass Rate: 100%
