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
  - `engine` — `CheckEngine`(CompletableFuture 병렬 + 검사별 타임아웃 격리), `TargetIpResolver`(PTR/RBL 대상 IP **목록**: 사용자 입력(다중) > 최우선 MX의 A/AAAA 레코드 전부, 사설/예약 IP는 제외)
  - `net` — `IpRanges`(사설/예약 대역 분류 — 문서화 대역(TEST-NET, 2001:db8::/32)은 테스트 관례상 의도적으로 허용)
  - `check.*` — 검사 구현체 (spf / dmarc / mx / ptr / rbl / domain-rbl / tlspolicy / propagation)
    - IP RBL 존: Spamhaus ZEN(DQS), Barracuda, SpamCop, PSBL, Mailspike, Hostkarma — Hostkarma는 white(1)/yellow(3)/NOBL(5) 코드가 "미등재", black(2)/brown(4)만 등재
    - IPv6 대상 IP: `RblProvider.supportsIpv6()`가 true인 존(현재 Spamhaus ZEN)만 nibble 역순(RFC 3596)으로 조회, 미지원 존은 evidence에 제외 사유 표시
    - 도메인 RBL: `DomainRblCheck` + `DomainRblProvider`(Spamhaus DBL — ZEN과 동일 DQS 키 재사용, `127.0.1.x` 매핑, `127.0.1.255`·`127.255.255.x`는 오류 코드)
    - DMARC: 조직 도메인 폴백 외에 **외부 리포트 수신 승인**(rua/ruf가 타 조직이면 `<정책도메인>._report._dmarc.<수신도메인>` TXT 확인, RFC 7489 §7.1) 검증
    - PTR: FCrDNS 외에 제네릭/동적 호스트명 휴리스틱(IP 옥텟 포함, dynamic/pool/dsl 등 토큰) WARN
    - `tlspolicy` — `TlsPolicyCheck`(MTA-STS RFC 8461 + TLS-RPT RFC 8460 단일 카드). HTTPS 정책 파일은 `PolicyFetcher` 인터페이스 경유(`HttpPolicyFetcher`가 실구현, 리다이렉트 금지) — 테스트는 이걸 mock. 미설정은 WARN(권장 사항), TXT만 있고 정책 파일 fetch 실패는 FAIL
- **checker-web** — Spring Boot REST API + 정적 UI. 코어 빈 조립만 담당.
  - `GET /api/v1/diagnose?domain=...&ip=(선택)` — 진단 실행. `ip`는 쉼표 구분 다중 입력 가능(최대 20개 — Spamhaus DQS 쿼터/쿼리 증폭 방어용 상한, 중복 제거). 입력 검증은 `InputValidator`(URL 붙여넣기/IDN 허용, 사설/예약 IP는 400 + 사유 안내)
  - UI: `resources/static/index.html` (vanilla JS, 프레임워크 없음). 검사 카드는 `<details>` 아코디언 — PASS/SKIP은 접힘, 문제 상태(FAIL/ERROR/WARN)는 자동 펼침
  - 주의: bootRun을 백그라운드로 띄웠다 중단하면 자식 java 프로세스가 고아로 남아 8080을 점유할 수 있음 — `Get-NetTCPConnection -LocalPort 8080`으로 확인 후 종료
  - 설정: `application.yml` — 타임아웃(DNS/검사/MTA-STS HTTP), RBL 활성화, 전파 검사 리졸버 목록
  - 비밀값(Spamhaus DQS 키): 로컬은 `application-local.yml`(gitignore 대상, 템플릿은 `application-local.yml.example`), 배포는 `SPAMHAUS_DQS_KEY` 환경변수. `bootRun`은 build.gradle에서 기본 `local` 프로필로 실행

## 설계 규칙 (PRD에서 온 불변 조건)

- 검사 추가 = `Check` 구현체 추가만으로 끝나야 함
- RBL은 `RblProvider` 인터페이스 경유 — 소스 교체/상업 전환 대비, 첫 커밋부터 유지. 도메인 RBL도 동일하게 `DomainRblProvider` 경유
- **RBL 응답 해석 시 오류 코드(Spamhaus 127.255.255.x)를 "미등재"로 절대 오판하지 말 것**
- Spamhaus는 DQS 키 필수, 키 없으면 SKIP + 발급 안내 (키는 절대 응답 evidence에 노출 금지 — 쿼리명에 키가 포함되므로 `provider.name()`만 evidence에 사용)
- DMARC는 조직 도메인 폴백(RFC 7489 §6.6.3, Guava PSL) 필수
- 검사 코드는 `DnsQueryService`만 사용 (단위 테스트에서 네트워크 금지). 유일한 예외인 MTA-STS 정책 fetch도 `PolicyFetcher` 인터페이스 경유로 동일 원칙 적용
- PTR/RBL은 다중 대상 IP를 지원 — 검사 카드는 1개 유지, IP별 결과는 evidence에 나열(다중일 때만 `[ip]` 태그), 상태는 worst-of 집계, guidance는 실패 유형별 1회만

## 커밋 규칙 (사용자 전역 규칙)

- 커밋 메시지: 기술 범위 + 기능 변화 함께, 본문은 `-` 불릿
- Co-Authored-By 넣지 않음
- git 명령 실행 전 설명 제공
