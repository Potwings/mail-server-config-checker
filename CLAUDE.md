# mail-server-config-checker

테스트 메일 1통 발송으로 SPF / DKIM / DMARC / PTR(FCrDNS) / RBL / MX / DNS 전파를 한 번에 진단하는 메일 서버 설정 점검 도구.
기준 문서: PRD v1.4 (저장소 루트 `mail-health-check-prd.md`) — **실메일 단일 진입점**(2026-07-26 결정, **M7에서 구현 완료** 2026-07-27): 유니크 주소 발급(`check-{uuid}@mail-check.yonggeon.kr`) → 사용자가 테스트 메일 발송 → 수집 디렉터리 폴링 → 세션 정보(접속 IP·HELO·MAIL FROM)와 원문 From 도메인 추출 → 검사 엔진 자동 실행 → 결과 페이지(발송 건별 카드 누적, 폴링 갱신). 기존 도메인/IP 입력 폼과 `GET /api/v1/diagnose` API는 **제거됨**. 수신 인프라 계약은 `infra-work.md` §3, M7 구현 계획은 `m7-plan.md`. 서비스 대상은 구축 완료되어 발송 가능한 메일 서버(구축 전 사전 검증·타사 도메인 조회는 목적 외). M8 잔여: DKIM 검증, HELO/PTR 일치, DMARC alignment, 헤더 품질 — 이를 위해 `message.eml`과 수집 디렉터리는 보존(`MailResult.incomingDir`).

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
  - `engine` — `CheckEngine`(CompletableFuture 병렬 + 검사별 타임아웃 격리). (`TargetIpResolver`는 M7에서 제거 — client_ip 상시 확보로 MX 폴백 사장, 필요 시 git 이력에서 복원)
  - `check.*` — 검사 구현체 (spf / dmarc / mx / ptr / rbl / domain-rbl / propagation)
    - SPF: 레코드 린트(`SpfRecordParser`+`SpfLookupCounter`)는 항상 수행, `ipsUserProvided`가 true일 때만 `SpfEvaluator`가 RFC 7208 `check_host()` 평가 추가(미허용 IP = FAIL). **실메일 세션(`CheckContext.MailSession`)이 있으면** 평가 도메인은 MAIL FROM 도메인(bounce면 HELO, HELO도 리터럴이면 ERROR — `resolveSpfDomain`), 매크로 `%{s}`/`%{l}`/`%{o}`/`%{h}`는 실제 세션 값으로 확장(`SpfEvaluator.SmtpSession`). 세션이 없으면 기존대로 합성 발신자 postmaster@도메인 + `%{h}` 스킵. `%{p}`는 항상 평가 제외
    - IP RBL 존: Spamhaus ZEN(DQS), Barracuda, SpamCop, PSBL, Mailspike, Hostkarma — Hostkarma는 white(1)/yellow(3)/NOBL(5) 코드가 "미등재", black(2)/brown(4)만 등재
    - 도메인 RBL: `DomainRblCheck` + `DomainRblProvider`(Spamhaus DBL — ZEN과 동일 DQS 키 재사용, `127.0.1.x` 매핑, `127.0.1.255`·`127.255.255.x`는 오류 코드)
- **checker-mail** — 실메일 파이프라인(Spring 없음, `checker-core` 의존). 패키지 `io.github.potwings.mailcheck.mail`:
  - `json/MailJson`(공용 ObjectMapper — 미지 필드 무시), `meta/MailMeta`+`MailMetaParser`(infra §3.3 미러; IO 오류=일시 재시도, 매핑 오류=`MailIntakeException` 영구), `eml/FromHeaderExtractor`(mime4j-dom 0.8.11 헤더 전용 lenient 파싱, 실패는 `Optional.empty()`), `util/Domains`(정규화, invalid→null)·`IpClassifier`(사설/루프백/링크로컬/ULA/파싱불가→비공인 fail-safe)
  - `session/` — `DiagnosisSession`·`MailResult`(status: `DIAGNOSED|REJECTED_PRIVATE_IP|FAILED` + note + report)·`FileSessionStore`(`{data-dir}/sessions/{uuid}.json`, temp+ATOMIC_MOVE, 손상 파일은 warn 후 없는 것 취급; 토큰 `check-{uuid}`→파일 직접 도출), `intake/ProcessedLog`(append-only 재처리 방지 — 처리→기록 사이 크래시 시 최대 카드 1건 중복 허용)
  - `intake/MailIntakeService.pollOnce()` — 절대 throw 안 함. 판정 사다리: `.`디렉터리 무시(infra §3.2) → 기처리 제외 → meta 손상=영구 스킵 / IO 오류=재시도 → 토큰 미매칭=진단 없이 mark(catch-all 스팸) → TTL 만료(received_at 기준)=스킵 → 사설 IP=`REJECTED_PRIVATE_IP` 카드(엔진 미실행) → From 추출 실패=`FAILED` 카드 → 진단=`DIAGNOSED`(예외 시 `FAILED`). 수집 디렉터리는 읽기 전용, 삭제·이동 금지
- **checker-web** — Spring Boot REST API + 정적 UI. 빈 조립 + `@Scheduled` 폴러 + REST만.
  - `POST /api/v1/sessions` → 201 `{id, address, createdAt, expiresAt, expired, mails:[]}` / `GET /api/v1/sessions/{id}` → 동일 스키마(404는 `{"error":...}`). `expired: true`는 수신 매칭만 중단됐다는 뜻 — 결과는 계속 조회 가능
  - 조립: `MailPipelineConfig`(@EnableScheduling, checker-mail 빈), `IntakeScheduler`(`mailcheck.intake.enabled` 조건부, `poll-interval` fixedDelay), 기존 `CheckerConfig`(검사 빈)
  - UI: `resources/static/index.html` (vanilla JS, 프레임워크 없음). 주소 발급 → `/?s={id}`로 URL 교체 → 4초 폴링, `queueId` 키 append-only 카드(열림/닫힘 보존). 검사 카드는 `<details>` 아코디언 — PASS/SKIP은 접힘, 문제 상태(FAIL/ERROR/WARN)는 자동 펼침. REJECTED/FAILED는 note 카드
  - 주의: bootRun을 백그라운드로 띄웠다 중단하면 자식 java 프로세스가 고아로 남아 8080을 점유할 수 있음 — `Get-NetTCPConnection -LocalPort 8080`으로 확인 후 종료
  - 설정: `application.yml` — 타임아웃, RBL 활성화, 전파 검사 리졸버 목록, `mailcheck.intake.{enabled, incoming-dir, data-dir, mail-domain, poll-interval, session-ttl}` (로컬 개발은 `application-local.yml`에서 Windows 경로로 override — 템플릿 참고)
  - 비밀값(Spamhaus DQS 키): 로컬은 `application-local.yml`(gitignore 대상, 템플릿은 `application-local.yml.example`), 배포는 `SPAMHAUS_DQS_KEY` 환경변수. `bootRun`은 build.gradle에서 기본 `local` 프로필로 실행

## 운영 노트 (M7)

- 앱 실행 계정을 `maildiag` 그룹에 추가해야 수집 디렉터리를 읽을 수 있음(`usermod -aG maildiag <user>` 후 재로그인 — infra §3.5). `data-dir`(기본 `./data`)에는 쓰기 권한 필요
- 세션 파일·수집 디렉터리 정리 정책은 미정 — M6 잔여(보관 기간·삭제 주체)와 함께 결정
- 주소 발급 rate limit 없음 — 알려진 잔여, 추후 보강
- RCPT 시점 토큰 검증은 M6 잔여 — 그 전까지 catch-all 스팸은 인테이크가 "토큰 미매칭"으로 스킵

## 설계 규칙 (PRD에서 온 불변 조건)

- 검사 추가 = `Check` 구현체 추가만으로 끝나야 함
- RBL은 `RblProvider` 인터페이스 경유 — 소스 교체/상업 전환 대비, 첫 커밋부터 유지. 도메인 RBL도 동일하게 `DomainRblProvider` 경유
- **RBL 응답 해석 시 오류 코드(Spamhaus 127.255.255.x)를 "미등재"로 절대 오판하지 말 것**
- Spamhaus는 DQS 키 필수, 키 없으면 SKIP + 발급 안내 (키는 절대 응답 evidence에 노출 금지 — 쿼리명에 키가 포함되므로 `provider.name()`만 evidence에 사용)
- DMARC는 조직 도메인 폴백(RFC 7489 §6.6.3, Guava PSL) 필수
- 검사 코드는 `DnsQueryService`만 사용 (단위 테스트에서 네트워크 금지)
- PTR/RBL은 다중 대상 IP를 지원 — 검사 카드는 1개 유지, IP별 결과는 evidence에 나열(다중일 때만 `[ip]` 태그), 상태는 worst-of 집계, guidance는 실패 유형별 1회만

## 커밋 규칙 (사용자 전역 규칙)

- 커밋 메시지: 기술 범위 + 기능 변화 함께, 본문은 `-` 불릿
- Co-Authored-By 넣지 않음
- git 명령 실행 전 설명 제공
