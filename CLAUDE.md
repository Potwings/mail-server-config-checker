# mail-server-config-checker

테스트 메일 1통 발송으로 SPF / DKIM / DMARC(+alignment) / PTR(FCrDNS·HELO) / RBL / MX / DNS 전파 / MTA-STS·TLS-RPT / 헤더 품질을 한 번에 진단하는 메일 서버 설정 점검 도구.
기준 문서: PRD v1.6 (저장소 루트 `mail-health-check-prd.md`) — **실메일 단일 진입점**(2026-07-26 결정, **M7에서 구현 완료** 2026-07-27): 유니크 주소 발급(`check-{uuid}@mail-check.yonggeon.kr`) → 사용자가 테스트 메일 발송 → 수집 디렉터리 폴링 → 세션 정보(접속 IP·HELO·MAIL FROM)와 원문 From 도메인 추출 → 검사 엔진 자동 실행 → 결과 페이지(발송 건별 카드 누적, 폴링 갱신). 기존 도메인/IP 입력 폼과 `GET /api/v1/diagnose` API는 **제거됨**. 수신 인프라 계약은 `infra-work.md` §3, M7 구현 계획은 `m7-plan.md`. 서비스 대상은 구축 완료되어 발송 가능한 메일 서버(구축 전 사전 검증·타사 도메인 조회는 목적 외). **M8 구현 완료**(2026-07-28): DKIM 서명 검증(jDKIM)·HELO/PTR 일치·DMARC alignment 실검증·헤더 품질 + 구 PR #1 이관 4건(DMARC 외부 리포트 승인·제네릭 PTR 경고·MTA-STS/TLS-RPT·RBL IPv6) — 이관 판정 기록은 `m8-backlog.md`. eml 기반 검사를 위해 `message.eml`과 수집 디렉터리는 계속 보존(`MailResult.incomingDir`), 원문 접근은 `CheckContext.emlPath`. **남은 작업은 전부 서버(홈서버) 측** — M6 잔여(unbound·RCPT 토큰 검증 등)와 M9 배포 스모크. 서버 세션용 작업 목록은 `server-work-todo.md`(서비스 개요 포함, 서버에서 clone하여 사용).

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
    - IP RBL 존: Spamhaus ZEN(DQS), Barracuda, SpamCop, PSBL, Mailspike, Hostkarma — Hostkarma는 white(1)/yellow(3)/NOBL(5) 코드가 "미등재", black(2)/brown(4)만 등재. **IPv6 대상 지원**(M8): nibble 역순(RFC 3596) 조회, `RblProvider.supportsIpv6()`가 false인 존은 IPv6 주소를 건너뛰고 evidence에 제외 사유 표시(현재 ZEN만 지원)
    - **RBL 해제 안내**: 등재(LISTED) 시 각 provider가 `RblVerdict.guidance`로 존별 해제 절차를 반환 — ZEN은 서브리스트별(SBL/CSS/XBL/DROP/PBL, XBL 4~7·PBL 10~11은 안내 공유), 나머지 존은 해제 요청 URL·자동 해제 조건 1줄. `RblCheck`/`DomainRblCheck`가 중복 제거(LinkedHashSet) 후 guidance로 노출. **존당 1줄 유지** — 단계별(3~5줄) 확장은 사용자가 반려(2026-08-02)
    - 도메인 RBL: `DomainRblCheck` + `DomainRblProvider`(Spamhaus DBL — ZEN과 동일 DQS 키 재사용, `127.0.1.x` 매핑, `127.0.1.255`·`127.255.255.x`는 오류 코드). 악용된 정상 도메인(102~106)은 웹 취약점 점검 guidance, 직접 등재(2~6)는 원인 활동 정리 guidance — 코드 범위로 판정(과거 문자열 매칭 제거)
    - PTR(M8 확장): FCrDNS에 더해 **제네릭/동적 호스트명 경고**(IP 옥텟 정/역순 포함, dynamic/pool/dsl 등 토큰 매칭 — 부분 문자열 오탐 방지 위해 토큰 단위)와 **HELO/PTR 일치 검사**(세션 있을 때 — 불일치·주소 리터럴 HELO는 WARN)
    - DMARC(M8 확장): **외부 리포트 수신 승인 검증**(RFC 7489 §7.1) — rua/ruf 수신 도메인이 타 조직(PSL 기준)이면 `<정책도메인>._report._dmarc.<수신도메인>` TXT 확인, 부재 시 WARN
    - `check.tlspolicy`(M8): `TlsPolicyCheck` — MTA-STS(`_mta-sts` TXT + HTTPS 정책 파일 fetch·파싱, 정책 mx와 실제 MX 대조, enforce 불일치 FAIL) + TLS-RPT(`_smtp._tls` TXT) 통합 카드. HTTP는 `PolicyFetcher` 인터페이스 경유(`HttpPolicyFetcher`: 리다이렉트 금지·타임아웃·64KB 상한) — 단위 테스트 네트워크 금지 유지
- **checker-mail** — 실메일 파이프라인(Spring 없음, `checker-core` 의존). 패키지 `io.github.potwings.mailcheck.mail`:
  - `json/MailJson`(공용 ObjectMapper — 미지 필드 무시), `meta/MailMeta`+`MailMetaParser`(infra §3.3 미러; IO 오류=일시 재시도, 매핑 오류=`MailIntakeException` 영구), `eml/FromHeaderExtractor`(mime4j-dom 0.8.11 헤더 전용 lenient 파싱, 실패는 `Optional.empty()`), `util/Domains`(정규화, invalid→null)·`IpClassifier`(사설/루프백/링크로컬/ULA/파싱불가→비공인 fail-safe)
  - `session/` — `DiagnosisSession`·`MailResult`(status: `DIAGNOSED|REJECTED_PRIVATE_IP|FAILED` + note + report)·`FileSessionStore`(`{data-dir}/sessions/{uuid}.json`, temp+ATOMIC_MOVE, 손상 파일은 warn 후 없는 것 취급; 토큰 `check-{uuid}`→파일 직접 도출), `intake/ProcessedLog`(append-only 재처리 방지 — 처리→기록 사이 크래시 시 최대 카드 1건 중복 허용)
  - `check/`(M8) — **eml 원문이 필요한 검사들** (jDKIM 0.5 의존이 있어 core가 아닌 이 모듈에 배치, `CheckContext.emlPath`로 원문 접근, 없으면 SKIP):
    - `check.dkim` — `DkimCheck`(실서명 검증 + 키 린트: RSA <1024 FAIL/<2048 WARN, ed25519 별도 분기, `p=` 빈값=폐기 FAIL, `t=y` WARN, 서명 헤더 없음=FAIL), `DkimVerificationSupport`(jDKIM 래핑 — alignment 검사와 공유), `DnsQueryServiceKeyRetriever`(공개키 조회를 `DnsQueryService` 경유로 — 테스트는 DNS mock + `DKIMSigner`로 실서명 생성)
    - `check.dmarc` — `DmarcAlignmentCheck`(SPF identity=MAIL FROM/bounce는 HELO, `SpfEvaluator` 재평가 + 검증 통과 DKIM `d=`를 From 도메인과 aspf/adkim 모드로 대조 — 둘 중 하나라도 「pass+정렬」이면 pass. DMARC 레코드 없으면 참고용 표시)
    - `check.header` — `HeaderQualityCheck`(To 누락 WARN, Message-ID/Date 부재 FAIL(정상 MTA면 자동 부여) + 형식 WARN, 콜론 뒤 공백 누락·비표준 헤더 라인·중복 헤더 WARN — 원문 헤더 블록 직접 파싱, mail-tester 벤치마킹)
  - `intake/MailIntakeService.pollOnce()` — 절대 throw 안 함. 판정 사다리: `.`디렉터리 무시(infra §3.2) → 기처리 제외 → meta 손상=영구 스킵 / IO 오류=재시도 → 토큰 미매칭=진단 없이 mark(catch-all 스팸) → TTL 만료(received_at 기준)=스킵 → 사설 IP=`REJECTED_PRIVATE_IP` 카드(엔진 미실행) → From 추출 실패=`FAILED` 카드 → 진단=`DIAGNOSED`(예외 시 `FAILED`). 수집 디렉터리는 읽기 전용, 삭제·이동 금지
- **checker-web** — Spring Boot REST API + 정적 UI. 빈 조립 + `@Scheduled` 폴러 + REST만.
  - `POST /api/v1/sessions` → 201 `{id, address, createdAt, expiresAt, expired, mails:[]}` / `GET /api/v1/sessions/{id}` → 동일 스키마(404는 `{"error":...}`). `expired: true`는 수신 매칭만 중단됐다는 뜻 — 결과는 계속 조회 가능
  - 조립: `MailPipelineConfig`(@EnableScheduling, checker-mail 빈 — DKIM/alignment/헤더 품질 검사 빈 포함), `IntakeScheduler`(`mailcheck.intake.enabled` 조건부, `poll-interval` fixedDelay), 기존 `CheckerConfig`(검사 빈 — `TlsPolicyCheck` 포함, `mailcheck.mta-sts-http-timeout` 기본 5s)
  - UI: `resources/static/index.html` (vanilla JS, 프레임워크 없음). 주소 발급 → `/?s={id}`로 URL 교체 → 4초 폴링, `queueId` 키 append-only 카드(열림/닫힘 보존). 검사 카드는 `<details>` 아코디언 — PASS/SKIP은 접힘, 문제 상태(FAIL/ERROR/WARN)는 자동 펼침. REJECTED/FAILED는 note 카드. 세션 복원 실패(404·네트워크 오류)는 `backToIssue()`로 세션 영역을 되돌리고 발급 화면 복귀 — 빈 주소 박스가 남지 않게
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
