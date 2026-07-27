# QA Test Sheet: M7 실메일 파이프라인

- **Date**: 2026-07-27
- **Tester**: Claude (automated)
- **Target URL**: http://localhost:8080
- **Scope**: 유니크 주소 발급 → 수집 디렉터리 폴링 → 자동 진단 → 결과 카드 UI (M7 전 범위)
- **환경**: Windows 로컬 E2E (Postfix 불필요) — `C:/mailcheck-dev/incoming` 수집 디렉터리에 합성 픽스처 투입(임시 경로에 쓴 뒤 rename = infra §3.2 계약 모사), `local` 프로필
- **픽스처 기준**: From/MAIL FROM 도메인 `gmail.com`, 공인 IP `209.85.220.41/42`(Google 발신망) · 미허용 IP `1.2.3.4` · 사설 IP `192.168.0.10`

## Test Cases

| ID | Category | Test Name | Precondition | Steps | Expected Result | Result | Note |
|----|----------|-----------|-------------|-------|----------------|--------|------|
| TC-04-001 | Display | 랜딩 화면 — 주소 발급 진입점, 구 입력 폼 제거 | 서버 실행 중 | 1) `/` 접속 2) 화면 요소 확인 | "테스트 주소 발급" 버튼 표시, 도메인/IP 입력 폼·힌트 없음 | Pass | 구 진입점 흔적 없음 |
| TC-04-002 | Function | 주소 발급 API 및 주소 형식 | TC-04-001 | 1) 발급 버튼 클릭 2) 네트워크 응답 확인 | `POST /api/v1/sessions` 201, `address` = `check-{uuid}@mail-check.yonggeon.kr`, 화면에 주소 표시 | Pass | POST 201 확인 |
| TC-04-003 | Function | 발급 후 공유 URL로 치환 | TC-04-002 | 1) 주소창 URL 확인 | `/?s={세션id}` 로 replaceState (히스토리 추가 없음) | Pass | history.length 증가 없음 |
| TC-04-004 | Display | 메일 대기 상태 안내 | TC-04-002 | 1) 메일 미투입 상태에서 화면 확인 | "메일 대기 중" 스피너/안내 표시 (침묵 금지) | Pass | 카드 생성 후에는 "추가 메일 대기 중"으로 전환 |
| TC-04-005 | Function | 주소 복사 버튼 | TC-04-002 | 1) 복사 버튼 클릭 2) 클립보드 확인 | 발급 주소가 클립보드에 복사, 피드백 표시 | Skip | `navigator.clipboard.writeText`가 자동화 컨텍스트에서 영구 pending(권한 granted인데도 미해결) — 환경 제약, 수동 확인 필요 |
| TC-04-006 | Function | 정상 메일 투입 → 진단 카드 자동 출현 | 발급 완료 | 1) 발급 토큰으로 정상 픽스처(공인 IP, From 유효) 투입 2) 최대 15초 대기 | 폴링으로 카드 자동 추가, 상태 DIAGNOSED, 7개 검사 카드 렌더 | Pass | 투입 후 폴 주기(5s)+UI 폴링(4s) 내 출현 |
| TC-04-007 | Data | SPF 평가 도메인이 MAIL FROM 기준 | TC-04-006 | 1) SPF 카드 evidence 확인 | evidence에 "(MAIL FROM 기준)" 및 실제 세션 IP 기준 평가 결과 표시 | Pass | "SPF 평가 도메인: gmail.com (MAIL FROM 기준)" + "발신 IP 209.85.220.41 평가: pass (매칭: ip4:209.85.128.0/17)" |
| TC-04-008 | Display | 검사 카드 아코디언 (PASS 접힘 / 문제 상태 펼침) | TC-04-006 | 1) 각 검사 카드 상태·펼침 여부 확인 | PASS/SKIP 접힘, FAIL/ERROR/WARN 자동 펼침 | Pass | PASS SPF 접힘, WARN DMARC·DNS전파 / FAIL SPF·PTR 자동 펼침 |
| TC-04-009 | Data | 메일 세션 정보 표시 (접속 IP·HELO·MAIL FROM) | TC-04-006 | 1) 카드 헤더/요약 확인 | meta.json의 client_ip·helo·mail_from·From 도메인이 카드에 표시 | Pass | "수신 … · 발신 IP … · MAIL FROM … · HELO …" 및 제목에 From 도메인 |
| TC-04-010 | Error | 사설 IP 발신 → REJECTED_PRIVATE_IP note 카드 | 발급 완료 | 1) client_ip=192.168.0.10 픽스처 투입 2) 대기 | 진단 미실행, 안내 note 카드 표시(내부망 경유 안내문) | Pass | "메일 #3 — 진단 불가 (내부망 발신)", 검사 카드 없음 |
| TC-04-011 | Error | From 헤더 추출 실패 → FAILED note 카드 | 발급 완료 | 1) From 헤더 없는 eml 픽스처 투입 2) 대기 | FAILED 상태 note 카드 표시(표준 From 헤더 안내) | Pass | "메일 #4 — 진단 실패" + 안내문 |
| TC-04-012 | Function | 다중 발송 누적 (append-only, 열림 상태 보존) | TC-04-006 이후 | 1) 검사 카드 하나 펼침 2) 추가 픽스처 투입 3) 갱신 후 확인 | 새 카드가 추가되고 기존 카드 열림/닫힘 상태 유지 | Pass | 카드 5건 누적, 펼쳐둔 #1 SPF 카드 열림 유지 |
| TC-04-013 | Error | 작성 중 디렉터리(`.` 시작) 무시 | 서버 실행 중 | 1) `.tmp-xxx` 디렉터리 투입 2) 대기 | 카드 미생성, 처리 이력 미기록(무시) | Pass | processed.log에 미기록 — 완결 후 재시도 가능 상태 유지 |
| TC-04-014 | Error | 미발급 토큰 수신자 → 진단 없이 스킵 | 서버 실행 중 | 1) rcpt_to를 임의 주소로 한 픽스처 투입 2) 대기 | 카드 미생성, 로그에 "매칭되지 않는 수신자" info | Pass | info 로그 + processed.log 기록(재처리 방지) |
| TC-04-015 | Error | meta.json 손상 → 스킵, 폴러 생존 | 서버 실행 중 | 1) 깨진 meta.json 픽스처 투입 2) 이후 정상 픽스처 투입 | 손상 건은 warn 후 스킵, 이후 정상 건은 정상 진단(폴 루프 중단 없음) | Pass | warn + mark 후 다음 건(QA0008AFTER) 정상 카드 생성 |
| TC-04-016 | Function | 앱 재시작 후 결과 유지 + 미재처리 | 카드 2건 이상 존재 | 1) 서버 종료 2) 재기동 3) `/?s={id}` 접속 | 기존 카드 그대로 조회, 기처리 메일 재진단 안 됨(중복 카드 없음) | Pass | 재기동 후에도 카드 5건 그대로, 중복 0 |
| TC-04-017 | Function | 공유 URL 재접속 (새 탭) | TC-04-016 | 1) 새 탭에서 `/?s={id}` 접속 | 발급 생략, 주소 재표시, 기존 결과 렌더 + 폴링 재개 | Pass | 발급 영역 숨김, 카드 5건 렌더 |
| TC-04-018 | Error | 존재하지 않는 세션 ID → 404 처리 | 서버 실행 중 | 1) `/?s=00000000-0000-0000-0000-000000000000` 접속 | 404 `{"error":...}`, 화면에 오류 박스 (JS 크래시 없음) | Pass | 최초 실행 시 **빈 "테스트 주소" 박스 잔존** 발견 → ISSUE 수정 후 재검증 Pass |
| TC-04-019 | Error | 콘솔/네트워크 오류 없음 | 전 케이스 수행 후 | 1) 콘솔 메시지 확인 2) 세션 API 응답 코드 확인 | JS 콘솔 에러 없음, `/api/v1/sessions` 200/201 정상 | Pass | 폴링 GET 70건 전부 200, POST 201, 콘솔 에러 0 |
| TC-04-020 | Error | 세션 TTL 만료 후 도착한 메일 스킵 | 발급 완료 | 1) received_at을 세션 만료 이후(+2일)로 한 픽스처 투입 2) 대기 | 카드 미생성, info 로그 + 처리 이력 기록 | Pass | "세션 TTL 만료 후 도착한 메일 — 건너뜀" 로그, 카드 5건 유지 |
| TC-04-021 | Display | 만료 세션 조회 시 배너 표시 + 폴링 중지 | 세션 파일 expiresAt을 과거로 설정 | 1) 해당 세션 URL 조회 2) 이후 네트워크 요청 관찰 | 만료 배너 표시, 결과는 계속 열람 가능, 폴링 중지 | Pass | 배너 노출 후 10초간 세션 API 요청 0건 |

## Summary

- **Total**: 21
- **Pass**: 20
- **Fail**: 0 (실행 중 발견 1건은 수정 후 재검증 Pass)
- **Skip**: 1
- **Pass Rate**: 95.2% (Skip 제외 시 100%)

## Issues

| Test Case ID | Issue | Severity | Report |
|-------------|-------|----------|--------|
| TC-04-018 | 존재하지 않는 세션 URL 접근 시 빈 "테스트 주소: [복사]" 박스가 남아 노출 — 테스트 중 수정 완료 | Minor | [report](issues/TC-04-018-세션없음-빈주소박스노출/report.md) |

## 미커버 항목 (후속)

- **복사 버튼 실동작** (TC-04-005): 자동화 환경의 클립보드 API 제약으로 Skip — 수동 확인 필요
- **실서버 스모크**: 외부 메일 서버에서 실제 발송 → 수집 → 카드 생성 (m7-plan §검증 3, 배포 후 수행)
- **RCPT 시점 토큰 검증**(M6 잔여): 현재는 catch-all 수신 후 인테이크가 "토큰 미매칭"으로 스킵 (TC-04-014에서 동작 확인)
