# M7 — 실메일 파이프라인 구현 계획

작성일: 2026-07-27 · 기준 문서: PRD v1.4 (`mail-health-check-prd.md`), 수신 인프라 계약 (`infra-work.md` §3)

## Context

PRD v1.4에서 실메일 단일 진입점으로 전환이 확정됐다(도메인/IP 입력 폼 폐지). M6 수신 인프라(Postfix pipe → `/var/lib/maildiag/incoming/<ts>-<queueid>/{message.eml, meta.json}`)는 구축·검증 완료 상태(계약: `infra-work.md` §3). M7은 이 수집물을 소비하는 애플리케이션 파이프라인이다:

**유니크 주소 발급 → 사용자가 테스트 메일 발송 → 수집 디렉터리 폴링 → 도메인/IP 추출 → 기존 CheckEngine 자동 실행 → 결과 페이지(발송 건별 카드 누적, 폴링 갱신)**. 기존 `GET /api/v1/diagnose?domain=&ip=` API와 입력 폼은 제거한다.

**사용자 확정 결정**: ① 세션·결과 저장은 파일 기반 JSON(DB 없음, 재시작 내구성 필수) ② SPF 실세션 확장(MAIL FROM 도메인 기준 평가 + `%{h}` 실값)을 M7에 포함.

M8(DKIM 검증, HELO/PTR 일치, DMARC alignment, 헤더 품질)은 범위 외 — 단 `message.eml` 원본과 수집 디렉터리는 보존해 M8을 막지 않는다.

## 아키텍처 결정

| 항목 | 결정 |
|---|---|
| 모듈 | 신규 **`checker-mail`** (Spring 없음, `checker-core` 의존): meta/eml 파싱, 추출, 사설IP 판별, 세션 저장, 인테이크 서비스. `checker-web`은 빈 조립 + `@Scheduled` 폴러 + REST만 (PRD §5 "메일 파싱·세션 관리 모듈 별도") |
| meta.json/세션 JSON | Jackson (checker-mail에 jackson-bom 2.19.1 — Boot 3.5.3 관리 버전과 정렬) |
| From: 헤더 파싱 | **Apache mime4j-dom 0.8.x** (헤더 전용 lenient 파싱; display name/quoted/folding/group 처리). M8의 jDKIM이 mime4j 기반이라 스택 충돌 없음. jakarta.mail 불채택 |
| 세션 파일 | `{data-dir}/sessions/{uuid}.json` — 세션 + 메일별 결과 내장. 토큰 `check-{uuid}` → local part에서 세션 파일 직접 도출(인덱스 불필요). 쓰기는 temp + ATOMIC_MOVE |
| 처리 이력 | `{data-dir}/processed.log` append-only(디렉터리명 1줄) — 재시작 후 재처리 방지. 처리→기록 사이 크래시 시 최악 카드 1건 중복(허용, 문서화) |
| 결과 갱신 | 클라이언트 폴링 4s, 공유 URL `/?s={id}` (정적 html 유지) |
| 사설 IP/실패 표현 | 메일 엔트리에 `status: DIAGNOSED \| REJECTED_PRIVATE_IP \| FAILED` + `note`. 유사 리포트 만들지 않음 |
| TTL | `session-ttl: 24h` — **수신 매칭 기준**(만료 후 도착 메일은 스킵). 결과는 계속 보존, GET은 `expired: true` 플래그로 응답 |
| 수집 디렉터리 | 앱은 읽기 전용(권한 계약 infra §3.5), 삭제·이동 안 함. `MailResult.incomingDir`로 M8 재열람 대비 |

## WI-1: checker-core — CheckContext 확장 + SPF 실세션 평가

1. `api/CheckContext.java`: 5번째 컴포넌트 `MailSession mailSession` 추가.
   - `record MailSession(String mailFrom, String helo)` (중첩 record) — `bounce()`(mailFrom null/blank), `mailFromDomain()`(마지막 `@` 뒤, 없으면 null).
   - 기존 3-arg/4-arg 생성자는 `null` 세션으로 위임 → **기존 테스트 무수정**.
2. `check/spf/SpfEvaluator.java` (`SpfEvaluator.java:50` evaluate):
   - `record SmtpSession(String sender, String helo)` 추가. 4-arg 오버로드 `evaluate(ip, domain, terms, session)`; 기존 3-arg는 null 위임(합성 postmaster + `%{h}` 스킵 유지).
   - `State`에 session 보관, 매크로 확장만 변경: `%{s}`→실제 sender, `%{l}`/`%{o}`→sender 분해, `%{h}`→실제 HELO(없으면 기존 스킵 노트). `%{p}`는 계속 제외.
3. `check/spf/SpfCheck.java` (`SpfCheck.java:47`, `SpfCheck.java:120`):
   - `resolveSpfDomain(ctx, builder)`: 세션 없음→`ctx.domain()`(기존 동작); 세션 있음→MAIL FROM 도메인(evidence "SPF 평가 도메인: … (MAIL FROM 기준)"); bounce→HELO 도메인(evidence 명시); bounce+HELO가 유효 호스트명 아님(`[리터럴]` 등)→ERROR 반환.
   - TXT 조회·lint·`counter.count`·`evaluator.evaluate` 모두 spfDomain 사용. `evaluateSenderIps`에서 세션 있으면 `SmtpSession` 구성(sender = mailFrom 또는 `postmaster@<helo>`, RFC 7208 §2.4). 게이트는 기존 `ipsUserProvided` 유지(인테이크가 true로 설정).
4. 테스트 추가: `SpfEvaluatorTest`(`%{h}` exists 매칭, `%{s}/%{l}/%{o}` 실값, 세션 없으면 기존 스킵), `SpfCheckTest`(MAIL FROM 도메인 lint, bounce→HELO, bounce+리터럴→ERROR).

체크포인트: `./gradlew :checker-core:test`

## WI-2: checker-mail 모듈 — 파싱·추출

1. `settings.gradle`에 `include 'checker-mail'`. `checker-mail/build.gradle`: `java-library`, `api project(':checker-core')`, jackson-databind+jsr310(bom 2.19.1), mime4j-dom 0.8.x, slf4j-api; 테스트 스택은 core와 동일(JUnit5/Mockito/AssertJ).
2. 패키지 `io.github.potwings.mailcheck.mail`:
   - `json/MailJson`: 공용 `ObjectMapper`(JavaTimeModule, `FAIL_ON_UNKNOWN_PROPERTIES` off — 수집기 스키마 추가 대비).
   - `meta/MailMeta`: infra §3.3 미러 record(`@JsonProperty("received_at")` 등 명시 매핑), `rcptLocalPart()` 헬퍼.
   - `meta/MailMetaParser`: `parse(Path)` — IO 오류=일시(재시도), 매핑 오류=영구 구분(`MailIntakeException`).
   - `eml/FromHeaderExtractor`: mime4j 헤더 전용 파싱 → 첫 From mailbox → 도메인 정규화. 콘텐츠 문제는 `Optional.empty()`(throw 금지).
   - `util/Domains.normalize`: 웹 `InputValidator.normalizeDomain` 로직 이관(IDN.toASCII + HOSTNAME 검증, URL 스트립 제외, invalid→null).
   - `util/IpClassifier.isNonPublic`: RFC1918/루프백/링크로컬/any/IPv6 ULA + 파싱 불가 → true(fail-safe).
3. **합성 픽스처만** 사용(공개 레포 — PRD §6.8, 실측 샘플 복사 금지): `example.com`/`203.0.113.x`/`192.168.0.10` 기반 eml·meta 변형(display name, quoted, folding, IDN, From 없음, bounce, 사설 IP, 미지 필드).

체크포인트: `./gradlew :checker-mail:test`

## WI-3: checker-mail — 세션 저장소

1. `session/MailResultStatus`(enum), `session/MailResult`(record: queueId, incomingDir, receivedAt, clientIp, helo, mailFrom, fromDomain, status, note, `DiagnosisReport report`), `session/DiagnosisSession`(record: id, address, createdAt, expiresAt, mails).
2. `session/SessionStore`(interface): `create()`, `find(id)`, `findByLocalPart(localPart)`, `appendResult(id, result)`.
3. `session/FileSessionStore(Path dataDir, String mailDomain, Duration ttl, ObjectMapper, Clock)`: synchronized, temp+ATOMIC_MOVE, 손상 파일은 warn 후 empty. `DiagnosisReport`/`CheckResult`는 record라 Jackson 네이티브 직렬화(core 무수정).
4. `intake/ProcessedLog(Path file)`: 기동 시 로드, `contains`/`markProcessed`(append).
5. 테스트: `@TempDir` 왕복, 재기동 시뮬레이션(새 인스턴스로 재로드), findByLocalPart 경계(비 check- 접두, 비 uuid), 손상 파일.

체크포인트: `./gradlew :checker-mail:test`

## WI-4: checker-mail — MailIntakeService

`intake/MailIntakeService(Path incomingDir, MailMetaParser, FromHeaderExtractor, SessionStore, ProcessedLog, CheckEngine, Clock)` — `pollOnce()`는 절대 throw 안 함. 디렉터리 나열 → `.` 시작 무시(원자적 rename 계약, infra §3.2) → 처리 이력 제외 → 이름순 처리, 건별 try/catch.

`handle(dir)` 판정 사다리(일시 IO 오류만 미기록 리턴→다음 폴에 재시도, 나머지는 전부 `markProcessed`):
1. meta.json 파싱 실패(영구) → warn + mark.
2. 토큰 미매칭(catch-all 스팸 — RCPT 검증은 M6 잔여) → **info 로그 + mark, 진단 금지**.
3. TTL 만료(received_at 기준, 파싱 실패 시 now) → info + mark, 카드 없음.
4. 사설 IP → `REJECTED_PRIVATE_IP` 카드(note = infra §6.1 안내문), **엔진 미실행**.
5. From 도메인 추출 실패 → `FAILED` 카드(사용자가 대기 중이므로 침묵 금지).
6. 진단: `new CheckContext(fromDomain, List.of(clientIp), "SMTP 세션 접속 IP", true, new MailSession(mailFrom, helo))` → `engine.diagnose` → `DIAGNOSED` 카드. 예외 시 `FAILED` 카드.

테스트: mock `CheckEngine` + `ArgumentCaptor`로 컨텍스트 검증(happy path/bounce), 닷 디렉터리·기처리·미매칭·만료·사설IP·엔진 예외·meta 손상 케이스.

체크포인트: `./gradlew :checker-mail:test`

## WI-5: checker-web — 조립·API·구 진입점 제거

**삭제**: `web/api/DiagnoseController.java`, `web/api/InputValidator.java`(+각 테스트 — 도메인 정규화 케이스는 `DomainsTest`로 이관), `engine/TargetIpResolver.java`(+테스트, `CheckerConfig`의 빈 — client_ip 상시 확보로 MX 폴백 사장, git으로 복원 가능). **유지**: `ApiExceptionHandler`(`{"error":...}` 형태 재사용).

1. `checker-web/build.gradle`: `implementation project(':checker-mail')`.
2. `MailcheckProperties`에 `Intake(boolean enabled, String incomingDir, String dataDir, String mailDomain, Duration pollInterval, Duration sessionTtl)` 추가.
3. 신규 `web/config/MailPipelineConfig`(`@EnableScheduling`): MailMetaParser/FromHeaderExtractor/FileSessionStore(→`SessionStore`, `MailJson.mapper()` 사용)/ProcessedLog/MailIntakeService 빈.
4. 신규 `web/intake/IntakeScheduler`(`@ConditionalOnProperty mailcheck.intake.enabled`, `@Scheduled(fixedDelayString="${mailcheck.intake.poll-interval:5s}")` → `pollOnce()` try/catch).
5. 신규 `web/api/SessionController` (`/api/v1/sessions`):
   - `POST` → 201 `{id, address, createdAt, expiresAt, expired:false, mails:[]}`
   - `GET /{id}` → 200 동일 스키마(mails에 `MailResult` 그대로 — `report`는 기존 `render()`가 소비하던 `DiagnosisReport` 형태); 미존재 → 404 `{"error":"세션을 찾을 수 없습니다"}`.
6. `application.yml`: `mailcheck.intake.{enabled:true, incoming-dir:/var/lib/maildiag/incoming, data-dir:./data, mail-domain:mail-check.yonggeon.kr, poll-interval:5s, session-ttl:24h}`. `application-local.yml.example`: Windows 개발용 경로(`C:/mailcheck-dev/...`) 예시 추가.
7. 테스트: `SessionControllerTest`(`@WebMvcTest` + `@MockitoBean SessionStore` — 파이프라인 빈 미로딩이라 파일시스템 불요): POST 주소 형식, GET에 DIAGNOSED(report 포함)+REJECTED(note) 혼재, 404.

체크포인트: `./gradlew build`

## WI-6: UI 재작성 (`static/index.html`)

기존 CSS 변수·아코디언 카드·`render(report)` 최대한 재사용, 단일 정적 페이지 유지.
- 랜딩: "테스트 주소 발급" 버튼 → POST → 주소 + 복사 버튼 + 발송 안내(다중 서버는 같은 주소로 각각 발송) → `history.replaceState('/?s={id}')`.
- 로드 시 `?s=` 있으면 발급 생략, 폴링 재개(주소 재표시).
- 폴링 4s: mails 비면 "메일 대기 중" 스피너(PRD §3.5 — 침묵 금지). `queueId` 키 기반 **append-only 렌더링**(열림/닫힘 상태 보존). DIAGNOSED→기존 아코디언, REJECTED/FAILED→note 카드. `expired:true`→만료 배너 + 폴링 중지. 404→오류 박스.
- 도메인/IP 폼·힌트·기존 submit 핸들러 제거.

## WI-7: 문서

- `CLAUDE.md`: 모듈 구조에 checker-mail 추가, 삭제된 API/폼, 세션 API·intake 설정 키, "전환 전 상태" 문구 갱신.
- 운영 노트(문서만): 앱 실행 계정 `maildiag` 그룹 추가 필요(infra §3.5), `data-dir` 쓰기 권한, 세션 파일·수집 디렉터리 정리 정책은 M6 잔여와 함께 결정. 주소 발급 rate limit 부재는 알려진 잔여(추후 보강).

## 검증

1. `./gradlew build` — 3개 모듈 전체 그린(코어 기존 테스트 무수정 = 하위 호환 증명).
2. **Windows 수동 E2E** (Postfix 불필요): `C:\mailcheck-dev\incoming` 생성, local 프로필 경로 설정 → `bootRun` → 주소 발급 → 합성 픽스처 디렉터리를 발급 토큰으로 rcpt 수정해 투입 → ~5초+폴링 내 카드 출현, SPF evidence에 "(MAIL FROM 기준)" 확인 → 사설 IP 픽스처로 거부 카드 확인 → `.tmp-` 디렉터리·미지 토큰 무시 확인 → **앱 재시작 후 결과 유지 + 미재처리 확인** → `/?s={id}` 새 브라우저 접근.
3. **서버 스모크**: jar 배포(운영 경로 설정, maildiag 그룹), 웹에서 발급, 외부 메일서버에서 실발송 → 수 초 내 카드. 기존 3개 샘플 디렉터리는 미매칭 토큰 스킵 로그 확인.
