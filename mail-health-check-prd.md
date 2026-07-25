# PRD — 메일 서버 설정 진단 도구 (Mail Health Check)

- **버전**: v1.3 (2026-07-26, mail-tester 벤치마킹 반영 — RBL 확대·DBL 추가, 2단계 헤더 품질 검사 추가. 콘텐츠/대량 발송 품질 검사는 서비스 목적과 달라 제외)
- **작성 목적**: 개인 개발 → 사내 도입 경로의 메일 서버 설정 진단 도구 개발 기준 문서
- **상태**: 개발 착수 전 (진행 중 프로젝트)

---

## 1. 배경 및 문제 정의

신규 고객사 오픈·장애 대응 시 엔지니어가 SPF/DKIM/DMARC/PTR 설정과 RBL 등재 여부를 `dig`·외부 사이트(MXToolbox 등)로 매번 수동 점검해야 하는 반복 비효율이 존재한다.

**해결하려는 문제**: 도메인만 입력하면 메일 서버 설정의 정상 여부를 한 번에 진단하는 도구를 제공하여, 수동 점검에 소요되는 시간을 제거한다.

**핵심 사용자**: 사내 메일 운영자·엔지니어 (1차), 추후 외부 공개 가능성 열어둠 (범용 도구로 설계)

## 2. 목표 / 비목표

### 목표
- 도메인 입력 → 항목별 PASS / WARN / FAIL + 사유를 한 화면에 제공
- 단순 레코드 존재 확인이 아닌 **RFC 기준 검증** (RFC 7208 / 6376 / 7489)
- 검사 엔진을 독립 모듈로 설계하여 재사용 가능하게 (온보딩 진단 API 등)
- 사내 배포 후 실사용 지표 확보 (점검 시간 단축, 사용자 수)

### 비목표 (현 단계에서 하지 않는 것)
- SMTP 라이브 체크 (25번 배너 / STARTTLS / 오픈 릴레이) — 홈서버 아웃바운드 25 차단으로 후순위, 필요 시 별도 VPS 워커로 분리
- 회사 고유 로직·고객 데이터 포함 — 공개 레포 전제의 범용 도구이므로 절대 미포함
- SpamBreaker 제품 기능으로의 통합
- 상업 서비스화 (단, RBL provider 추상화로 전환 가능성은 열어둠)
- **종합 점수(mail-tester식 N/10 단일 스코어) 산출** — 항목 간 가중치 설계가 복잡하고 근거 없는 수치는 오해 소지가 있어 제외. 항목별 PASS/WARN/FAIL 상태 표시를 유지
- **메일 콘텐츠/대량 발송 품질 검사** (List-Unsubscribe 헤더, HTML·multipart 구성, 단축 URL, 이미지 등) — 본 서비스는 뉴스레터 발송 테스트가 아니라 **메일 서버 설정 정상여부 진단**이 목적이므로 범위에서 제외 (mail-tester류 도구와의 포지셔닝 차이)

## 3. 단계별 범위

### 1단계 — DNS 정적 검사 MVP (입력 = 도메인, 선택적으로 서버 IP)

| 검사 항목 | 상세 요구사항 |
|---|---|
| **SPF** | `v=spf1` TXT 파싱. 중복 레코드 = permerror. include 재귀 포함 **10-lookup 제한 카운팅**(ptr/exists도 카운트 포함), void lookup ≤ 2. `+all` 과허용 경고. 종단 `-all`/`~all` 확인. **발신 IP 입력 시 RFC 7208 `check_host()` 평가 수행** (2026-07-26 범위 이동 — 도메인+IP만으로 평가 가능하므로 1단계 소관): 메커니즘(a/mx/ip4/ip6/include/exists/ptr/all)과 redirect를 재귀 평가해 해당 IP의 pass/softfail/fail/neutral 판정, 미허용 IP는 FAIL + `ip4:` 추가 안내. 다중 IP는 PTR/RBL과 동일한 worst-of 집계. 매크로는 `%{i}`/`%{d}`/`%{v}` 및 합성 발신자(postmaster@도메인) 기반 `%{s}`/`%{l}`/`%{o}` 확장 — `%{h}`(HELO) 등 세션 전용 매크로가 든 메커니즘만 평가 제외 후 명시. IP 미입력 시 레코드 린트만 수행하고 IP 입력을 안내(MX 도출 IP는 수신용이므로 SPF 평가에 사용하지 않음) |
| **DMARC** | `_dmarc.{domain}` TXT. 레코드 부재 시 **조직 도메인(Organizational Domain) 폴백 재조회** (RFC 7489 §6.6.3, Public Suffix List 필요) — 서브도메인 입력 시 필수 동작. `p=`(none/quarantine/reject) 정책 강도, `sp=`, `rua`/`ruf`, `pct`, `adkim`/`aspf` alignment 모드(r/s) |
| **PTR / FCrDNS** | 서버 IP의 PTR 존재 + **Forward-Confirmed**(PTR → 호스트명 → A → 동일 IP 복귀) 양방향 검증. **검사 대상 IP 출처**: 기본은 MX 호스트의 A 레코드에서 도출, 선택 입력으로 IP 직접 지정 허용. 단 MX IP는 수신 서버 기준이므로 **발신 전용 IP가 분리된 구성에서는 한계** — 결과에 "MX IP 기준 검사" 명시, 근본 해결은 2단계 헤더 추출. HELO 일치 검사는 SMTP 세션 필요 → **2단계로 이동** |
| **RBL** | IP 옥텟 역순 + zone 조회, `127.0.0.x` 리턴 코드 → 등재 리스트 매핑. 검사 대상 IP는 PTR 검사와 동일 기준(MX 도출 + 선택 직접 입력). 대상: Spamhaus ZEN(DQS 키), Barracuda(조회 IP 사전 등록 필요 — 제약 3 참조), SpamCop. **커버리지 확대 후보**(mail-tester는 23개 리스트 검사 — 2026-07-26 벤치마킹): PSBL(`psbl.surriel.com`), Mailspike(`bl.mailspike.net`), Hostkarma (+ Spamrats, blocklist.de, manitu) — 사전 등록 불필요·무료 조회 가능한 존부터 순차 추가. SORBS는 폐기됨(제약 2)으로 목록에서 제외 |
| **도메인 RBL (Spamhaus DBL)** | IP가 아닌 **도메인 자체의 블랙리스트 등재 여부** 검사 — `{domain}.{DQS키}.dbl.dq.spamhaus.net` 조회, `127.0.1.x` 리턴 코드 매핑(spam/phish/malware/abused-legit 구분). 기존 ZEN용 DQS 키 재사용. mail-tester 등 기존 도구는 IPv4 블랙리스트만 검사하므로 차별화 항목. 오류 코드(`127.255.255.x`)를 "미등재"로 오판 금지 규칙 동일 적용 |
| **MX / DNS 배포** | MX 존재·우선순위, MX 호스트의 A/AAAA 정상 해석, **MX exchange 호스트명이 CNAME(alias)이면 RFC 5321 §5.1 / RFC 2181 §10.3 위반** 감지 |
| **DNS 전파 (다중 리졸버)** | 레코드 변경 직후 리졸버 캐시로 인한 오판 방지. **권한 네임서버(NS 직접 조회)를 기준값**으로 두고, 다중 리졸버에서 동일 레코드(SPF/DMARC/MX/A)를 병렬 조회 → 기준값과 비교. 조회 대상: 글로벌 공용(Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS 208.67.222.222) + **국내 통신사(KT 168.126.63.1, SK브로드밴드 219.250.36.130, LG U+ 164.124.101.2)** — 사내·국내 고객사의 실제 수신 환경은 통신사 DNS를 타는 경우가 많아 국내 전파 확인이 실용적으로 중요. 전파율(N/M 리졸버 일치), 불일치 리졸버 목록, 각 응답의 TTL 잔여 시간 표시. 전체 일치 = PASS, 일부 불일치 = WARN(전파 진행 중) + 예상 완료 시점 안내. 엣지케이스: Quad9는 멀웨어 도메인에 차단 응답을 주므로 차단 도메인이면 전파 불일치로 오판 가능 — 인지하고 처리 |
| **부가 (후순위)** | MTA-STS(TXT + 정책 파일 fetch), TLS-RPT, BIMI, DANE-TLSA, DNSSEC |

**출력**: 항목별 `PASS / WARN / FAIL` + 판정 사유(evidence) + 개선 가이드

### 2단계 — 실메일 검사 모드

- 유니크 수신 주소(`check-{uuid}@service`) 발급 → 사용자가 테스트 메일 발송 → 수신 서버에서 원문 파싱
- **DKIM 검사는 2단계 전담**: `DKIM-Signature` 헤더에서 셀렉터 직접 추출 → `{selector}._domainkey.{domain}` TXT 조회 + 실제 서명 검증. 키 검증 포함 — 키 길이(RSA 기준 1024 최소 / 2048 권장, `k=ed25519`이면 RSA 기준 미적용 별도 분기), `p=` 유효성(빈 값 = 키 폐기), `t=y` 테스트 모드 감지
- `Received-SPF` / `Authentication-Results` 헤더로 **실제 pass/fail** 확인 (레코드 존재 ≠ 실제 통과)
- 발신 IP를 헤더에서 추출 → PTR/RBL 검사에 자동 사용 (사용자가 IP를 몰라도 됨, 1단계 MX IP 기준 검사의 한계 해소)
- `Received` 헤더에서 HELO/EHLO 명 추출 → PTR 호스트명 일치 검사 (1단계에서 이동 — DNS 정적 검사로는 불가능한 항목)
- 세션 정보(접속 IP, HELO) 확보로 SPF 세션 전용 매크로(`%{h}` 등)까지 **완전 평가** 가능 (1단계 check_host 평가에서 유일하게 제외되는 부분의 해소) — 2단계는 1단계의 대체가 아니라 실메일 기반의 별개 검증 기능
- MIME 파싱 + 스팸 스코어(SpamAssassin) 옵션
- **헤더 품질 검사** (2026-07-26 mail-tester 벤치마킹 — 실제 감점의 주요인이 SPF/DKIM이 아닌 헤더 품질이었음): `To:` 누락(MISSING_HEADERS), 헤더 간격/형식 오류(HDRS_MISSP), `Message-ID`·`Date` 존재와 형식 검증 — 정상 설정된 MTA/submission이라면 자동 부여되는 헤더이므로 부재 = 서버 설정 문제의 신호. 콘텐츠 품질 검사(List-Unsubscribe, HTML 구성 등)는 서비스 목적과 달라 비목표로 제외
- 필요 인프라: 수신 도메인 + MX + 파서 (SpamBreaker 수신 파서 자산의 패턴 재활용 가능 — 단, 코드 자체는 미포함)

## 4. 기술 스택 / 아키텍처

| 영역 | 선택 | 비고 |
|---|---|---|
| 백엔드 | Java / Spring Boot | |
| DNS | **dnsjava** (org.xbill.DNS) | 커스텀 리졸버 지정(DQS), 레코드 타입·타임아웃 제어 필수라 `InetAddress` 불가 |
| SPF/DKIM 파싱 | Apache James **jSPF** / **jDKIM** 재사용 | 매크로 확장·lookup 카운팅 직접 구현 시 엣지케이스 지옥. jDKIM은 2단계에서 사용 |
| 동시성 | `CompletableFuture` 병렬 실행 | 검사 항목별 개별 타임아웃 격리 — 한 항목이 늘어져도 전체 안 죽게 |
| 캐싱 | DNS TTL 기반 캐시 | RBL은 짧게 |
| 배포 | Beelink 홈서버 + Cloudflare Tunnel | |

### 설계 원칙
- 각 검사를 `Check` 인터페이스로 추상화 → `CheckResult { status, evidence }`
- **RBL은 `RblProvider` 인터페이스로 추상화** — 소스 교체·상업 전환(Spamhaus 유료 구독) 대비. MVP 첫 커밋부터 적용 (나중 리팩터링은 비용 큼)
- 검사 엔진은 웹 레이어와 분리된 독립 모듈로
- **리졸버 전략을 검사 종류별로 분리**: 일반 레코드 전파 검사는 다중 공용 리졸버 + 권한 NS 직접 조회, **RBL 조회는 반드시 DQS 경유(공용 리졸버 금지)**. dnsjava의 리졸버 지정 기능으로 검사별 리졸버를 주입하는 구조로

## 5. 핵심 제약 및 리스크 (반드시 반영)

1. **Spamhaus는 공용 리졸버(8.8.8.8, 1.1.1.1) 쿼리를 차단** → `127.255.255.254` 에러를 "미등재"로 오판 위험. **무료 DQS 키 발급 필수**, 조회 형식 `{ip역순}.{DQS키}.zen.dq.spamhaus.net`. **KT 인프라도 차단 대상**이므로 자체 리졸버로도 안심 불가 → DQS 방식 확정
2. **SORBS는 2024.6 폐기** — RBL 목록에서 제외. AHBL도 사망. 낡은 튜토리얼의 목록 복붙 금지
3. **Barracuda(b.barracudacentral.org)는 조회하는 DNS 서버 IP의 무료 사전 등록 필수** — 미등록 IP는 응답을 주지 않아 "미등재"로 오판 위험(Spamhaus와 같은 유형의 함정). 홈서버 회선이 유동 IP면 등록이 무효화될 수 있으므로 IP 변경 감지 + 재등록 절차 필요
4. **DKIM 셀렉터는 DNS 열거 불가** — brute-force 프로빙은 커버율이 낮아 채택하지 않음. **DKIM 검사는 1단계에서 제외**, 2단계 실메일 헤더 파싱으로만 수행
5. **1단계 PTR/RBL은 MX IP 기준** — 발신 전용 IP가 분리된 구성에서는 실제 발신 평판과 다를 수 있음. 결과 화면에 검사 기준 IP를 명시하고, 발신 IP 검증은 2단계에서 해소
6. **홈서버 아웃바운드 25번 차단** (KT 등 국내 ISP) — SMTP 라이브 체크는 범위 제외, 추후 VPS 워커 분리
7. **공개 레포 보안** — 커밋 히스토리 포함 사내 정보(내부 서버 주소, 고객사 정보, SpamBreaker 로직) 유입 금지. 히스토리는 삭제로 안 지워짐

## 6. 비기능 요구사항

- 전체 진단 응답: 병렬 실행 기준 수 초 이내 목표 (항목별 타임아웃으로 상한 보장)
- 검사 항목 추가가 쉬운 구조 (`Check` 구현체 추가만으로 확장)
- RBL fan-out에 rate limit 적용

## 7. 성공 지표

| 지표 | 목표 |
|---|---|
| 코어 완성 | 1단계 SPF/DMARC + RBL 검사가 실제 도메인 대상으로 동작 |
| 점검 시간 | 수동 점검 X분 → 도구 Y초 (실측하여 기록) |
| 실사용 | 사내 엔지니어 N명 사용, 진단 X건 |
| 공개 준비 | 코어 완성 + README 정돈 후 GitHub 링크 공개 가능 상태 |

> 이 프로젝트는 이력서에서 유일하게 정량 지표가 없는 항목 — 위 숫자 확보가 마지막 보강 과제.

## 8. 마일스톤

1. **M1**: 프로젝트 스캐폴딩 + `Check`/`RblProvider` 인터페이스 + dnsjava 연동
2. **M2**: SPF 검사 (jSPF 연동, 10-lookup 카운팅, 중복/과허용 판정)
3. **M3**: DMARC + MX/DNS 배포 검사
4. **M4**: RBL (Spamhaus DQS 키 발급 → ZEN + Barracuda + SpamCop, 리턴 코드 매핑)
5. **M5**: PTR/FCrDNS + 결과 UI + Beelink/Cloudflare Tunnel 배포 → **사내 공유, 실사용 지표 수집 시작**
6. **M5.5**: RBL 커버리지 확대(PSBL·Mailspike·Hostkarma 등) + Spamhaus DBL 도메인 검사
7. **M6 (2단계)**: 실메일 모드 (수신 주소 발급 → 헤더 파싱 → DKIM 검증 포함 실검증 + 헤더 품질 검사)
