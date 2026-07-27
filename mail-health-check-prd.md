# PRD — 메일 서버 설정 진단 도구 (Mail Health Check)

- **버전**: v1.6 (2026-07-28, **구 PR #1 커버리지 확대 항목의 M8 이관 반영** — M7 전환으로 기반(도메인/IP 입력 폼·`InputValidator`·`TargetIpResolver`)을 잃어 PR을 닫고 항목별 판정을 `m8-backlog.md`에 기록. 검사 항목 표에 DMARC 외부 리포트 승인·제네릭 PTR 경고·RBL IPv6를 명시하고, MTA-STS/TLS-RPT를 부가(후순위)에서 독립 검사 항목으로 승격)
  - v1.5 (2026-07-28, **M7 실메일 파이프라인 구현 완료 반영** — 구현 중 확정 사항 문서화: 파일 기반 세션 저장(DB 없음), 결과 페이지 폴링 갱신, 세션 TTL 24h(수신 매칭 기준·만료 후 결과 열람 유지), jSPF 불채택(자체 구현 유지), SMTP 수신은 pipe 방식 확정)
  - v1.4 (2026-07-26, **실메일 단일 진입점으로 전환** — 도메인/IP 입력 폼을 폐지하고 테스트 메일 수신 기반 자동 진단으로 개편. 기존 1단계/2단계 구도 폐지, DNS 검사 엔진은 수신 파이프라인이 자동 호출하는 내부 구현으로 흡수)
- **작성 목적**: 개인 개발 → 사내 도입 경로의 메일 서버 설정 진단 도구 개발 기준 문서
- **상태**: 개발 진행 중 — DNS 검사 엔진(구 M1~M5.5) + 실메일 파이프라인(M7: 주소 발급→수집 폴링→자동 진단→결과 누적, QA 완료) 구현 완료. 남은 것: 서버 배포 스모크(M9 일부 선행), M6 잔여(unbound·RCPT 토큰 검증 등), M8(헤더 기반 검사 + 구 PR #1 이관 항목 — `m8-backlog.md`)

---

## 1. 배경 및 문제 정의

신규 고객사 오픈·장애 대응 시 엔지니어가 SPF/DKIM/DMARC/PTR 설정과 RBL 등재 여부를 `dig`·외부 사이트(MXToolbox 등)로 매번 수동 점검해야 하는 반복 비효율이 존재한다.

**해결하려는 문제**: 사용자가 자신의 메일 서버에서 테스트 메일 1통을 발송하면, 그 메일과 SMTP 세션에서 확보한 정보(발신 IP, HELO, MAIL FROM, DKIM 서명 등)로 메일 서버 설정의 정상 여부를 한 번에 자동 진단한다.

**핵심 사용자**: 사내 메일 운영자·엔지니어 (1차), 추후 외부 공개 가능성 열어둠 (범용 도구로 설계)

**서비스 대상**: **구축 완료되어 발송 가능한 메일 서버**. 진단에 필요한 입력(발신 전용 IP, DKIM 셀렉터, HELO 명)은 사용자가 정확히 알기 어렵거나 DNS로 열거가 불가능한 값들인데, 실메일을 수신하면 전부 자동으로 확보된다.

### 실메일 단일 진입점 결정 근거 (v1.4)

- 발신 IP 수동 입력, DKIM 셀렉터 열거 불가, HELO 확인 불가 등 정적 검사의 구조적 한계가 실메일 수신으로 모두 해소됨
- 진입점이 2개(도메인 입력 폼 + 실메일)면 사용자가 "무엇을 언제 써야 하는지" 혼란 — 단일 흐름으로 통일
- 도메인 입력형 정적 진단이 유용한 시나리오(서버 구축 전 DNS 사전 검증, 메일 발송을 요청할 수 없는 타사 도메인 조회)는 **서비스 목적 밖으로 명시적으로 제외**
- 발송 자체가 불가능한 서버(아웃바운드 25 차단, 큐 고장)는 DNS 정책 문제가 아닌 서버 운영 문제로 서비스 소관 아님

## 2. 목표 / 비목표

### 목표
- **테스트 메일 1통 발송 → 전 항목 자동 진단**: 항목별 PASS / WARN / FAIL + 사유를 한 화면에 제공, 입력할 것은 없음
- 단순 레코드 존재 확인이 아닌 **RFC 기준 검증** (RFC 7208 / 6376 / 7489) — 레코드 린트 + 실제 세션 기준 판정을 모두 제공
- 검사 엔진을 독립 모듈로 설계하여 재사용 가능하게 (온보딩 진단 API 등)
- 사내 배포 후 실사용 지표 확보 (점검 시간 단축, 사용자 수)

### 비목표 (하지 않는 것)
- **도메인 입력형 정적 진단 진입점** (v1.4에서 제거 결정) — 구축 전 사전 검증·타사 도메인 조회는 서비스 목적 외. 검사 엔진 자체는 내부 구현으로 전부 유지되므로, 필요 시 별도 도구로 재노출하는 비용은 낮음
- SMTP 라이브 체크의 **능동 아웃바운드 검사** (상대 서버 25번 접속 / 배너 / 오픈 릴레이) — 홈서버 아웃바운드 25 차단으로 범위 제외. 단, 우리가 **수신자**로서 세션에서 수동적으로 관찰 가능한 정보(발신 서버의 STARTTLS 사용 여부 등)는 부가 항목 후보
- 회사 고유 로직·고객 데이터 포함 — 공개 레포 전제의 범용 도구이므로 절대 미포함
- SpamBreaker 제품 기능으로의 통합
- 상업 서비스화 (단, RBL provider 추상화로 전환 가능성은 열어둠)
- **종합 점수(mail-tester식 N/10 단일 스코어) 산출** — 항목 간 가중치 설계가 복잡하고 근거 없는 수치는 오해 소지가 있어 제외. 항목별 PASS/WARN/FAIL 상태 표시를 유지
- **메일 콘텐츠/대량 발송 품질 검사** (List-Unsubscribe 헤더, HTML·multipart 구성, 단축 URL, 이미지 등) — 본 서비스는 뉴스레터 발송 테스트가 아니라 **메일 서버 설정 정상여부 진단**이 목적이므로 범위에서 제외 (mail-tester류 도구와의 포지셔닝 차이)

## 3. 진단 흐름 (단일 진입점)

1. **웹 접속 → 유니크 수신 주소 발급**: `check-{uuid}@mail-check.yonggeon.kr` (수신 도메인 확정 2026-07-26) + 결과 페이지 세션 생성
2. **사용자가 자신의 메일 서버에서 해당 주소로 테스트 메일 발송** — 메일 서버가 여러 대면 같은 주소로 각 서버에서 여러 번 발송 (발송 건별로 결과 카드 누적)
3. **Postfix(진단 전용 smtpd)가 수신 → pipe transport → 수집기가 파일 적재** (구축·검증 완료 2026-07-26, 연동 계약은 저장소 `infra-work.md`): 세션 값(접속 IP·HELO·MAIL FROM 등)은 pipe 매크로로 `meta.json`에 직접 확보(Received 헤더 파싱 불필요), 원본은 `message.eml`로 바이트 무손상 보존(우리 Postfix의 Received 1줄만 추가 — DKIM 검증에 무해). STARTTLS 여부는 최상단 Received의 `with ESMTPS`로 판별(`meta.json`의 `client_protocol`은 TLS 미반영). 그 아래 외부 Received 헤더는 위조 가능하므로 사용 금지
4. **도메인·IP 자동 추출 → 검사 엔진 자동 실행** (아래 추출 규칙)
5. **결과 페이지 자동 갱신**: 수신 즉시 진단 실행, 발송 건별 결과 표시. 미수신 상태는 "메일 대기 중"으로 표기 (발송 실패 원인 진단은 범위 외이나, 침묵 대신 대기 상태를 명시해 오해 방지)

### 도메인/IP 추출 규칙

- **진단 기준 도메인** = `From:` 헤더 도메인 (사용자 관점의 "우리 도메인") — DMARC/MX/전파/도메인 RBL 검사 대상
- **SPF 평가 도메인** = MAIL FROM(envelope) 도메인 (RFC 7208 기준). MAIL FROM이 비었으면(bounce) HELO 도메인
- From 도메인 ≠ MAIL FROM 도메인이면 DMARC alignment 검사에서 드러남 (아래 표 참조)
- **검사 대상 IP** = 해당 세션의 실제 접속 IP (발송 건마다 1개 — 다중 서버는 발송 횟수로 커버)

## 4. 검사 항목

| 검사 항목 | 상세 요구사항 |
|---|---|
| **SPF** | 레코드 린트는 항상 수행: `v=spf1` TXT 파싱, 중복 레코드 = permerror, include 재귀 포함 **10-lookup 제한 카운팅**(ptr/exists도 카운트 포함), void lookup ≤ 2, `+all` 과허용 경고, 종단 `-all`/`~all` 확인. **RFC 7208 `check_host()` 완전 평가**: 실제 세션 정보(접속 IP, HELO, MAIL FROM)를 확보하므로 `%{s}`/`%{l}`/`%{o}`/`%{h}` 매크로를 **실값으로 확장** — 합성 발신자(postmaster@도메인) 대체나 세션 전용 매크로 평가 제외가 불필요 (단 `%{p}`는 deprecated 매크로로 평가 제외 유지 — RFC 7208 §7.3도 사용 비권장). SPF 평가 도메인은 MAIL FROM 도메인, bounce면 HELO 도메인(HELO가 주소 리터럴 등 비호스트명이면 ERROR). 메커니즘(a/mx/ip4/ip6/include/exists/ptr/all)과 redirect를 재귀 평가해 pass/softfail/fail/neutral 판정, 미허용 IP는 FAIL + `ip4:` 추가 안내 |
| **DKIM** | `DKIM-Signature` 헤더에서 셀렉터 직접 추출 → `{selector}._domainkey.{domain}` TXT 조회 + **실제 서명 검증**. 키 검증 포함 — 키 길이(RSA 기준 1024 최소 / 2048 권장, `k=ed25519`이면 RSA 기준 미적용 별도 분기), `p=` 유효성(빈 값 = 키 폐기), `t=y` 테스트 모드 감지. 서명 헤더 자체가 없으면 FAIL(발신 서버 DKIM 미설정) |
| **DMARC** | `_dmarc.{domain}` TXT. 레코드 부재 시 **조직 도메인(Organizational Domain) 폴백 재조회** (RFC 7489 §6.6.3, Public Suffix List 필요). `p=`(none/quarantine/reject) 정책 강도, `sp=`, `rua`/`ruf`, `pct`, `adkim`/`aspf`. **실메일 기반 alignment 실검증**: SPF alignment(MAIL FROM 도메인 vs From 도메인, aspf 모드 반영) + DKIM alignment(서명 `d=` vs From 도메인, adkim 모드 반영) — 레코드 존재 ≠ 실제 통과를 구분해 판정. **외부 리포트 수신 승인 검증(RFC 7489 §7.1)**: `rua`/`ruf` 수신 주소가 타 조직 도메인이면 `<정책도메인>._report._dmarc.<수신도메인>` TXT 존재 확인 — 없으면 WARN(리포트가 조용히 폐기되는 상태) |
| **PTR / FCrDNS** | 세션 접속 IP의 PTR 존재 + **Forward-Confirmed**(PTR → 호스트명 → A → 동일 IP 복귀) 양방향 검증. **HELO/EHLO 명과 PTR 호스트명 일치 검사** 포함 (세션에서 HELO 직접 확보). **제네릭/동적 호스트명 경고**: FCrDNS가 성립해도 호스트명에 IP 옥텟이 포함되거나 `dynamic`/`pool`/`dsl` 등 ISP 기본 패턴이면 WARN(수신측이 스팸 신호로 취급) |
| **RBL** | 세션 접속 IP를 옥텟 역순 + zone 조회, `127.0.0.x` 리턴 코드 → 등재 리스트 매핑. 대상: Spamhaus ZEN(DQS 키), Barracuda(조회 IP 사전 등록 필요 — 제약 3 참조), SpamCop, PSBL(`psbl.surriel.com`), Mailspike(`bl.mailspike.net`), Hostkarma(white/yellow/NOBL 코드는 미등재, black/brown만 등재). 추가 후보: Spamrats, blocklist.de, manitu — 사전 등록 불필요·무료 조회 가능한 존부터 순차 추가. SORBS는 폐기됨(제약 2)으로 제외. **IPv6 대상 지원**: 세션 접속 IP가 IPv6이면 nibble 역순(RFC 3596)으로 조회, 미지원 존은 결과에 제외 사유 표시 |
| **도메인 RBL (Spamhaus DBL)** | IP가 아닌 **도메인 자체의 블랙리스트 등재 여부** — `{domain}.{DQS키}.dbl.dq.spamhaus.net` 조회, `127.0.1.x` 리턴 코드 매핑(spam/phish/malware/abused-legit 구분). 기존 ZEN용 DQS 키 재사용. mail-tester 등 기존 도구는 IPv4 블랙리스트만 검사하므로 차별화 항목. 오류 코드(`127.255.255.x`)를 "미등재"로 오판 금지 규칙 동일 적용 |
| **MX / DNS 배포** | MX 존재·우선순위, MX 호스트의 A/AAAA 정상 해석, **MX exchange 호스트명이 CNAME(alias)이면 RFC 5321 §5.1 / RFC 2181 §10.3 위반** 감지 |
| **DNS 전파 (다중 리졸버)** | 레코드 변경 직후 리졸버 캐시로 인한 오판 방지. **권한 네임서버(NS 직접 조회)를 기준값**으로 두고, 다중 리졸버에서 동일 레코드(SPF/DMARC/MX/A)를 병렬 조회 → 기준값과 비교. 조회 대상: 글로벌 공용(Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS 208.67.222.222) + **국내 통신사(KT 168.126.63.1, SK브로드밴드 219.250.36.130, LG U+ 164.124.101.2)** — 사내·국내 고객사의 실제 수신 환경은 통신사 DNS를 타는 경우가 많아 국내 전파 확인이 실용적으로 중요. 전파율(N/M 리졸버 일치), 불일치 리졸버 목록, 각 응답의 TTL 잔여 시간 표시. 전체 일치 = PASS, 일부 불일치 = WARN(전파 진행 중) + 예상 완료 시점 안내. 엣지케이스: Quad9는 멀웨어 도메인에 차단 응답을 주므로 차단 도메인이면 전파 불일치로 오판 가능 — 인지하고 처리 |
| **헤더 품질** | mail-tester 벤치마킹(2026-07-26) — 실제 감점의 주요인이 SPF/DKIM이 아닌 헤더 품질이었음: `To:` 누락(MISSING_HEADERS), 헤더 간격/형식 오류(HDRS_MISSP), `Message-ID`·`Date` 존재와 형식 검증 — 정상 설정된 MTA/submission이라면 자동 부여되는 헤더이므로 부재 = 서버 설정 문제의 신호. 콘텐츠 품질 검사(List-Unsubscribe, HTML 구성 등)는 비목표로 제외 |
| **MTA-STS / TLS-RPT** | MTA-STS(RFC 8461): `_mta-sts.{domain}` TXT + `https://mta-sts.{domain}/.well-known/mta-sts.txt` 정책 파일 fetch·파싱, 정책의 `mx` 패턴과 실제 MX 대조(`mode=enforce`인데 불일치면 FAIL). TLS-RPT(RFC 8460): `_smtp._tls.{domain}` TXT. HTTP 조회는 `PolicyFetcher` 추상화 경유 — 단위 테스트 네트워크 금지 원칙 유지 |
| **부가 (후순위)** | 발신 세션 STARTTLS 사용 여부 관찰(수신자 입장의 수동 관찰 — 능동 검사 아님), BIMI, DANE-TLSA, DNSSEC, MIME 파싱 + 스팸 스코어(SpamAssassin) 옵션 |

**출력**: 항목별 `PASS / WARN / FAIL` + 판정 사유(evidence) + 개선 가이드. 발송 건별 결과 카드 누적(다중 서버 지원)

## 5. 기술 스택 / 아키텍처

| 영역 | 선택 | 비고 |
|---|---|---|
| 백엔드 | Java / Spring Boot | |
| DNS | **dnsjava** (org.xbill.DNS) | 커스텀 리졸버 지정(DQS), 레코드 타입·타임아웃 제어 필수라 `InetAddress` 불가 |
| SPF | **자체 구현** (jSPF 불채택 — M2~M7에서 파서·lookup 카운터·check_host 평가기 완성) | 매크로 확장·10-lookup/void 카운팅·실세션 평가까지 자체 구현으로 커버, 단위 테스트로 엣지케이스 고정 |
| DKIM | Apache James **jDKIM** (M8 예정) | 서명 검증에 사용. mime4j 기반이라 M7의 From 파싱(mime4j-dom)과 스택 일치 |
| SMTP 수신 | **기존 운영 중인 Postfix 연동** (홈서버) | **pipe transport로 확정**(M6) — 세션 값을 명령행 인자로, 원본을 stdin으로 수집기에 전달해 파일 적재. 미발급 주소의 RCPT 단계 거부는 Postfix policy service(`check_recipient_access`)로 앱에 위임 가능(M6 잔여). 릴레이 금지 유지 |
| 메일 파싱 | Apache **mime4j-dom** | From: 헤더 전용 lenient 파싱 (display name/quoted/folding/group). jakarta.mail 불채택 |
| 세션·결과 저장 | **파일 기반 JSON** (DB 없음) | `{data-dir}/sessions/{uuid}.json` — 토큰 `check-{uuid}`에서 파일 직접 도출(인덱스 불필요), temp+ATOMIC_MOVE로 재시작 내구성. 재처리 방지는 append-only `processed.log` |
| 동시성 | `CompletableFuture` 병렬 실행 | 검사 항목별 개별 타임아웃 격리 — 한 항목이 늘어져도 전체 안 죽게 |
| 캐싱 | DNS TTL 기반 캐시 | RBL은 짧게 |
| 배포 | **Beelink 홈서버 직접 수신 확정** (2026-07-26 인바운드 25 수신 테스트 완료) | 웹은 기존 Cloudflare Tunnel 유지, SMTP는 홈 회선 인바운드 25 직접 수신. 잔여 리스크는 제약 5 참조 |

### 설계 원칙
- 각 검사를 `Check` 인터페이스로 추상화 → `CheckResult { status, evidence }` — **검사 엔진(checker-core)은 v1.3까지의 자산을 그대로 유지**, 실메일 파이프라인이 추출한 도메인·IP·세션 정보로 자동 호출
- **RBL은 `RblProvider` 인터페이스로 추상화** — 소스 교체·상업 전환(Spamhaus 유료 구독) 대비. 도메인 RBL도 `DomainRblProvider`로 동일
- 검사 엔진은 웹/SMTP 수신 레이어와 분리된 독립 모듈로 — 수신 파이프라인도 엔진과 분리(메일 파싱·세션 관리 모듈 별도)
- **리졸버 전략을 검사 종류별로 분리**: 일반 레코드 전파 검사는 다중 공용 리졸버 + 권한 NS 직접 조회, **RBL 조회는 반드시 DQS 경유(공용 리졸버 금지)**. dnsjava의 리졸버 지정 기능으로 검사별 리졸버를 주입하는 구조로

## 6. 핵심 제약 및 리스크 (반드시 반영)

1. **Spamhaus는 공용 리졸버(8.8.8.8, 1.1.1.1) 쿼리를 차단** → `127.255.255.254` 에러를 "미등재"로 오판 위험. **무료 DQS 키 발급 필수**, 조회 형식 `{ip역순}.{DQS키}.zen.dq.spamhaus.net`. **KT 인프라도 차단 대상**이므로 자체 리졸버로도 안심 불가 → DQS 방식 확정
2. **SORBS는 2024.6 폐기** — RBL 목록에서 제외. AHBL도 사망. 낡은 튜토리얼의 목록 복붙 금지
3. **Barracuda(b.barracudacentral.org)는 조회하는 DNS 서버 IP의 무료 사전 등록 필수** — 미등록 IP는 응답을 주지 않아 "미등재"로 오판 위험(Spamhaus와 같은 유형의 함정). 서버 IP 변경 시 등록 무효화 → IP 변경 감지 + 재등록 절차 필요. **주의: 이 리스크는 메일 발신 여부와 무관** — 검사 엔진이 Barracuda 존을 DNS 조회하는 행위 자체에 대한 제약이므로, 수신 전용 구성이어도 홈서버 유동 IP(2026-07-26 확정)에서는 실존. 미응답 시 반드시 ERROR/SKIP으로 처리해 "미등재" 오판 차단(구현 시 필수 검증 항목)
4. **DKIM 셀렉터는 DNS 열거 불가** — brute-force 프로빙은 커버율이 낮아 채택하지 않음. 실메일의 `DKIM-Signature` 헤더에서 셀렉터를 추출하는 현 구조가 유일하게 신뢰 가능한 방식 (실메일 단일 진입점 결정의 근거 중 하나)
5. **수신 인프라가 서비스 전체의 단일 진입점 = 단일 장애점** — **홈서버 직접 수신으로 확정**(2026-07-26 인바운드 25 수신 테스트 완료, 기존 운영 중인 Postfix가 수신 담당). Cloudflare Tunnel은 HTTP 전용이므로 웹만 터널 경유, SMTP는 홈 회선 인바운드 직접 수신. 회선은 **유동 IP 확정**이며 MX 대상 호스트명의 **DDNS는 구현 완료**(2026-07-26). Cloudflare Tunnel은 IP 은닉 목적이 아니라(MX로 IP 공개됨) **웹 공격 표면 축소(80/443 미개방, 앱은 localhost 바인딩)·엣지 TLS·IP 변경 내성** 목적으로 유지 확정. 잔여 리스크: (a) 유동 IP로 인한 **Barracuda 조회 등록 무효화**(제약 3 — 수신 전용 여부와 무관, 검사 엔진의 RBL 조회 문제), (b) 회선/정전 장애 = 수신 불가 — 장애 장기화 시 이전 경로로 VPS 올인원(Hetzner CX22급, 월 ~€4.5) 검토 완료(2026-07 시세)
6. **홈서버 아웃바운드 25번 차단** (KT 등 국내 ISP) — 능동 SMTP 라이브 체크는 범위 제외 근거 (수신은 제약 5의 인프라로 해소)
7. **수신 주소 악용/스팸 유입 방어** — 발급되지 않았거나 만료된 uuid 주소는 RCPT 단계에서 즉시 거부, 세션(발급 주소)에 TTL 적용, 메시지 크기 상한, 발신 IP당 rate limit. 수신 서버는 릴레이 절대 금지(수신 전용)
8. **공개 레포 보안** — 커밋 히스토리 포함 사내 정보(내부 서버 주소, 고객사 정보, SpamBreaker 로직) 유입 금지. 히스토리는 삭제로 안 지워짐

## 7. 비기능 요구사항

- 진단 응답: 메일 수신 시점부터 병렬 실행 기준 수 초 이내 목표 (항목별 타임아웃으로 상한 보장, 수집 디렉터리 폴링 주기 5s + 결과 페이지 폴링 4s)
- 결과 페이지는 수신·진단 완료를 자동 반영 — **클라이언트 폴링(4s)으로 확정**(M7). 발송 건별 카드는 append-only 렌더링(수신 순서 유지, 열림 상태 보존), 공유 URL `/?s={id}`로 재접근 가능
- 검사 항목 추가가 쉬운 구조 (`Check` 구현체 추가만으로 확장)
- RBL fan-out에 rate limit 적용
- 발급 주소 세션 TTL: **24h, 수신 매칭 기준으로 확정**(M7) — 만료 후 도착한 메일은 진단하지 않고 스킵, 이미 쌓인 결과는 계속 열람 가능(`expired` 플래그로 표시). 주소 발급 자체의 rate limit은 미구현(알려진 잔여)

## 8. 성공 지표

| 지표 | 목표 |
|---|---|
| 코어 완성 | 테스트 메일 발송 → 전 항목 자동 진단이 실제 도메인 대상으로 동작 |
| 점검 시간 | 수동 점검 X분 → 도구 Y초 (실측하여 기록) |
| 실사용 | 사내 엔지니어 N명 사용, 진단 X건 |
| 공개 준비 | 코어 완성 + README 정돈 후 GitHub 링크 공개 가능 상태 |

> 이 프로젝트는 이력서에서 유일하게 정량 지표가 없는 항목 — 위 숫자 확보가 마지막 보강 과제.

## 9. 마일스톤

1. ~~**M1**: 프로젝트 스캐폴딩 + `Check`/`RblProvider` 인터페이스 + dnsjava 연동~~ ✅
2. ~~**M2**: SPF 검사 (10-lookup 카운팅, 중복/과허용 판정)~~ ✅
3. ~~**M3**: DMARC + MX/DNS 배포 검사~~ ✅
4. ~~**M4**: RBL (Spamhaus DQS 키 발급 → ZEN + Barracuda + SpamCop, 리턴 코드 매핑)~~ ✅
5. ~~**M5**: PTR/FCrDNS + 결과 UI~~ ✅ (배포는 M9로 이동)
6. ~~**M5.5**: RBL 커버리지 확대(PSBL·Mailspike·Hostkarma) + Spamhaus DBL 도메인 검사 + SPF check_host 평가~~ ✅
7. **M6**: 수신 인프라 — **핵심 구축·검증 완료**(2026-07-26, 상세·연동 계약은 `infra-work.md`): `mail-check.yonggeon.kr` MX 구성, 진단 전용 Postfix smtpd 분리, pipe→수집기(원본+세션 파일 적재), 외부 수신·릴레이 차단·원본 무손상 검증. **잔여**: RBL 조회 정상화 — Spamhaus(ZEN·DBL)는 DQS로 해결(키 발급 완료 2026-07-27), 비-Spamhaus 존(Barracuda·SpamCop·PSBL·Mailspike·Hostkarma)용 unbound 재귀 리졸버 설치(포워딩 모드 금지) + Barracuda 조회 IP 등록, RCPT 시점 토큰 검증(policy service), 주소 발급/세션 관리(웹), 처리분 정리 정책, postscreen·인증서
8. ~~**M7**: 실메일 파이프라인 — 수신 원문·세션 정보 → 도메인/IP 추출 → 기존 검사 엔진 자동 실행 → 결과 페이지(발송 건별 누적). **기존 도메인/IP 입력 폼 및 `?domain=&ip=` API 제거**~~ ✅ (2026-07-27 구현·QA 완료, 계획서 `m7-plan.md`: 신규 `checker-mail` 모듈 + `POST/GET /api/v1/sessions` API + 폴링 UI + SPF 실세션 평가. 사설 IP(헤어핀 NAT)는 진단 거부 카드, 미발급 토큰은 스킵. 서버 배포 스모크는 M9에서)
9. **M8**: 헤더 기반 검사 — DKIM 서명 검증(jDKIM), HELO/PTR 일치, DMARC alignment 실검증, 헤더 품질. **+ 구 PR #1 이관 항목**(M7 전환으로 기반을 잃어 재구현 — 판정·원본 커밋은 `m8-backlog.md`): DMARC 외부 리포트 승인·제네릭 PTR 경고·MTA-STS/TLS-RPT는 그대로 이식, RBL IPv6는 범위 축소 재작성, 사설 IP 입력 검증은 M7 `IpClassifier`가 대체해 폐기
10. **M9**: 배포 + 사내 공유, 실사용 지표 수집 시작
