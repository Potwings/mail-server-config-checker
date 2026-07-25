# mail-server-config-checker

도메인 입력만으로 SPF / DMARC / PTR(FCrDNS) / RBL / MX / DNS 전파를 한 번에 진단하는 메일 서버 설정 점검 도구.
기준 문서: PRD v1.2 (`C:\Users\ygk07\Downloads\mail-health-check-prd.md`) — **DKIM은 1단계 범위에서 제외**(2단계 실메일 모드 전담).

## 빌드 / 실행 / 테스트

```bash
./gradlew build          # 전체 빌드 + 테스트
./gradlew test           # 테스트만
./gradlew :checker-web:bootRun   # 웹 서버 실행 (기본 8080)
```

- JDK 17 toolchain (Gradle이 로컬 JDK 17 자동 감지 — PATH의 java는 11이지만 무관)
- Spring Boot 3.5.3, dnsjava 3.6.3, Guava(PSL용), JUnit 5 + Mockito + AssertJ

## 모듈 구조

- **checker-core** — 검사 엔진. 웹 레이어와 완전 분리(재사용 전제). Spring 의존성 없음.
  - `api` — `Check`(검사 단위 인터페이스), `CheckResult`(PASS/WARN/FAIL/SKIP/ERROR + evidence + guidance), `CheckContext`
  - `dns` — `DnsQueryService`(dnsjava 추상화 — 검사 코드는 dnsjava를 직접 만지지 않음, 테스트는 이걸 mock), `DnsJavaQueryService`(리졸버 지정 쿼리 지원)
  - `engine` — `CheckEngine`(CompletableFuture 병렬 + 검사별 타임아웃 격리), `TargetIpResolver`(PTR/RBL 대상 IP: 사용자 입력 > MX A 레코드 도출)
  - `check.*` — 검사 구현체 (spf / dmarc / mx / ptr / rbl / propagation)
- **checker-web** — Spring Boot REST API + 정적 UI. 코어 빈 조립만 담당.
  - `GET /api/v1/diagnose?domain=...&ip=(선택)` — 진단 실행. 입력 검증은 `InputValidator`(URL 붙여넣기/IDN 허용)
  - UI: `resources/static/index.html` (vanilla JS, 프레임워크 없음). 검사 카드는 `<details>` 아코디언 — PASS/SKIP은 접힘, 문제 상태(FAIL/ERROR/WARN)는 자동 펼침
  - 주의: bootRun을 백그라운드로 띄웠다 중단하면 자식 java 프로세스가 고아로 남아 8080을 점유할 수 있음 — `Get-NetTCPConnection -LocalPort 8080`으로 확인 후 종료
  - 설정: `application.yml` — 타임아웃, RBL 활성화, 전파 검사 리졸버 목록
  - 비밀값(Spamhaus DQS 키): 로컬은 `application-local.yml`(gitignore 대상, 템플릿은 `application-local.yml.example`), 배포는 `SPAMHAUS_DQS_KEY` 환경변수. `bootRun`은 build.gradle에서 기본 `local` 프로필로 실행

## 설계 규칙 (PRD에서 온 불변 조건)

- 검사 추가 = `Check` 구현체 추가만으로 끝나야 함
- RBL은 `RblProvider` 인터페이스 경유 — 소스 교체/상업 전환 대비, 첫 커밋부터 유지
- **RBL 응답 해석 시 오류 코드(Spamhaus 127.255.255.x)를 "미등재"로 절대 오판하지 말 것**
- Spamhaus는 DQS 키 필수, 키 없으면 SKIP + 발급 안내 (키는 절대 응답 evidence에 노출 금지 — 쿼리명에 키가 포함되므로 `provider.name()`만 evidence에 사용)
- DMARC는 조직 도메인 폴백(RFC 7489 §6.6.3, Guava PSL) 필수
- 검사 코드는 `DnsQueryService`만 사용 (단위 테스트에서 네트워크 금지)

## 커밋 규칙 (사용자 전역 규칙)

- 커밋 메시지: 기술 범위 + 기능 변화 함께, 본문은 `-` 불릿
- Co-Authored-By 넣지 않음
- git 명령 실행 전 설명 제공
