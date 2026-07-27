# 메일 진단 서비스 — 수신 인프라 구축 내역

작성일: 2026-07-26
대상 서버: `yonggeon` (Ubuntu 24.04.4 LTS)
용도: 테스트 메일 1통을 실제로 수신해 SMTP 세션 정보와 원본 메시지를 확보하는 수집 계층

---

## 1. 개요

이 서버는 원래 **발신 전용**(send-only) Postfix 구성이었다. 이번 작업으로 **진단용 메일 수신**
경로를 추가했다. 기존 발신 기능(뉴스레터 등)은 그대로 유지된다.

핵심 설계 원칙 두 가지:

1. **원본 무손상** — 수신 메시지는 바이트 단위로 보존한다. 우리가 헤더를 추가·삭제·재작성하면
   DKIM 검증이 깨져 **오진**이 발생한다.
2. **세션 정보 포착** — 발신 IP, HELO, envelope MAIL FROM은 SMTP 세션에서만 얻을 수 있고
   DNS 조회로는 알아낼 수 없다. 이 값들이 진단의 필수 입력이다.

---

## 2. 아키텍처

```
고객사 메일서버
   │ SMTP :25
   ▼
공유기 (172.30.1.254) ── 포트포워딩 ──▶ 172.30.1.11:25
   │
   ▼
Postfix smtpd (진단 전용 인스턴스)
   │  · milter 미부착 (원본 보존)
   │  · relay_domains = mail-check.yonggeon.kr 만 수락
   │  · 그 외 수신자는 554 거부
   ▼
diag pipe transport
   │  세션 값을 명령행 인자로, 메시지 원본을 stdin으로 전달
   ▼
/opt/maildiag/bin/ingest  (Python, maildiag 권한)
   │
   ▼
/var/lib/maildiag/incoming/<수신시각>-<큐ID>/
      ├── message.eml   원본 바이트
      └── meta.json     SMTP 세션 값
   │
   ▼
[Spring 진단 서비스]  ← 여기서 소비
```

---

## 3. 연동 계약 (Spring 서비스가 알아야 할 것)

### 3.1 디렉터리 구조

```
/var/lib/maildiag/incoming/
└── 20260726T101226Z-C51241200F0/
    ├── message.eml     수신 원본 (Postfix의 Received 헤더 1줄만 추가됨)
    └── meta.json       SMTP 세션에서 확보한 값
```

디렉터리명 형식: `{UTC ISO8601 compact}-{Postfix queue id}`
동일 이름 충돌 시 `.1`, `.2` 접미사가 붙는다.

### 3.2 완결성 판단 — 중요

수집기는 임시 디렉터리에 파일을 모두 쓴 뒤 **원자적으로 rename** 한다.
따라서 **`incoming/` 아래에 보이는 디렉터리는 항상 완결 상태**다.
작성 중인 디렉터리는 `.` 으로 시작하는 이름을 가지므로, 폴링 시 다음을 지킬 것:

- `.` 으로 시작하는 항목은 **무시**
- 추가 안전장치가 필요하면 `meta.json` 존재 여부를 완결 표시로 사용

### 3.3 `meta.json` 스키마

```json
{
  "received_at":      "2026-07-26T10:12:26.972133+00:00",
  "queue_id":         "C51241200F0",
  "client_ip":        "15.164.45.50",
  "client_hostname":  "smtp1.sec.crinity.com",
  "client_port":      "35850",
  "client_protocol":  "ESMTP",
  "helo":             "smtp1.sec.crinity.com",
  "mail_from":        "test@sec.crinity.com",
  "rcpt_to":          "test123@mail-check.yonggeon.kr",
  "original_rcpt_to": "test123@mail-check.yonggeon.kr",
  "size_reported":    "673",
  "size_actual":      621
}
```

**신뢰 등급 — 진단 로직 작성 시 반드시 구분할 것**

| 필드 | 출처 | 신뢰도 | 비고 |
|---|---|---|---|
| `client_ip` | TCP 연결에서 관찰 | **신뢰 가능** | SPF·PTR·RBL의 입력값 |
| `client_port` | TCP 연결에서 관찰 | 신뢰 가능 | |
| `client_protocol` | SMTP 대화 | 신뢰 가능 | `SMTP` / `ESMTP`. **TLS 여부는 반영되지 않는다** — STARTTLS 세션도 `ESMTP`로 기록됨(실측, 샘플 `C5124...`). TLS 판별은 최상단 `Received:` 헤더의 `with ESMTPS`로 할 것 |
| `client_hostname` | 역방향 DNS 조회 결과 | **조건부** | 발신자가 자기 PTR을 통제한다. 반드시 정방향 재확인(FCrDNS)할 것. PTR 없으면 `unknown` |
| `helo` | 발신자가 **주장**한 값 | **검증 대상** | 임의 문자열. 검증 항목이지 근거가 아님 |
| `mail_from` | envelope 발신자 (`MAIL FROM`) | **검증 대상** | SPF 판정 입력. 본문 `From:` 헤더와 **다를 수 있음** |
| `rcpt_to` | 우리가 수락한 수신자 | 신뢰 가능 | 테스트 토큰 추출용 |
| `size_reported` | 발신자가 `SIZE`로 선언 | 참고 | `size_actual`과 불일치 가능 (정상) |
| `size_actual` | 수집기가 실제 측정 | 신뢰 가능 | 바이트 수 |

`size_reported`와 `size_actual`이 다른 것은 정상이다. 전자는 SMTP 확장에서 발신자가 선언한
추정치이고, 후자는 최종 저장된 바이트 수다.

### 3.4 `message.eml` 취급

- 수신 원본에 **Postfix의 `Received:` 헤더 1줄만** 추가된다.
- `Return-Path`, `Delivered-To`, `Authentication-Results`, `X-Original-To`는 **추가되지 않는다**
  (검증 완료).
- **최상단 `Received:` 헤더만 신뢰할 것.** 그 아래 `Received` 헤더들은 발신측이 생성한 것이므로
  위조 가능하다. 참고 정보로만 사용한다.
- DKIM 검증은 이 파일을 그대로 입력으로 쓰면 된다. 헤더 추가는 DKIM에 영향을 주지 않는다
  (서명 이후 최상단에 붙는 헤더는 `h=` 목록에 없어 무시됨).

### 3.5 파일 접근 권한 — 연동 전 필수 조치

```
/var/lib/maildiag/          drwxr-x---  maildiag:maildiag
/var/lib/maildiag/incoming/ drwxr-x---  maildiag:maildiag
```

Spring 애플리케이션 실행 계정이 읽을 수 있어야 한다. 권장 방식:

```bash
# Spring 앱 실행 계정을 maildiag 그룹에 추가
usermod -aG maildiag <spring_app_user>
# 세션 재로그인 또는 서비스 재시작 필요
```

읽기 전용으로 충분하다. **수집 디렉터리를 애플리케이션이 삭제·이동하려면 쓰기 권한이 별도로
필요**하므로, 처리 완료분 정리 정책을 정할 때 함께 결정할 것.

---

## 4. 서버 구성 상세

### 4.1 Postfix — `main.cf` 변경분

```
inet_interfaces          = 127.0.0.1, [::1], 172.30.1.11
relay_domains            = mail-check.yonggeon.kr
transport_maps           = hash:/etc/postfix/transport
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
```

- `mydestination`은 **빈 값 유지** (로컬 배달 없음)
- `reject_unauth_destination`은 릴레이 시도를 `554`(영구)로 거부한다. 변경 전 기본값
  `defer_unauth_destination`은 `450`(일시)이었고, 둘 다 릴레이는 동일하게 차단한다.
  영구 거부로 바꾼 이유는 스팸 봇의 무한 재시도를 끊기 위함.

`/etc/postfix/transport`:
```
mail-check.yonggeon.kr    diag:
```
(수정 후 `postmap /etc/postfix/transport` 필수)

### 4.2 Postfix — `master.cf` 변경분

smtpd를 인터페이스별로 분리했다.

```
# 로컬 제출용 — OpenDKIM이 서명한다
127.0.0.1:smtp inet n    -       y       -       -       smtpd
[::1]:smtp inet  n       -       y       -       -       smtpd

# 진단 수신용 — 인터넷에서 도달. milter 없음, 헤더 재작성 없음
172.30.1.11:smtp inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/diag
  -o smtpd_milters=
  -o receive_override_options=no_address_mappings,no_header_body_checks
```

수집기로 넘기는 전송:

```
diag      unix  -       n       n       -       10      pipe
  flags=Xq user=maildiag null_sender=
  argv=/opt/maildiag/bin/ingest
    --client-ip ${client_address} --client-hostname ${client_hostname}
    --client-port ${client_port} --client-protocol ${client_protocol}
    --helo ${client_helo} --mail-from ${sender} --rcpt ${recipient}
    --original-rcpt ${original_recipient} --queue-id ${queue_id} --size ${size}
```

- `flags`에 `D`(Delivered-To)·`R`(Return-Path)를 **넣지 않았다** — 메시지 변형 방지
- `argv`는 셸을 거치지 않고 `execve`로 실행되므로, `${client_helo}` 같은 발신자 통제 문자열에
  셸 메타문자가 있어도 명령 주입이 불가능하다
- 로그는 `postfix/diag` 태그로 분리된다

### 4.3 수집기

`/opt/maildiag/bin/ingest` (Python 3, 실행 계정 `maildiag`)

- 실패 시 **`EX_TEMPFAIL`(75)** 로 종료 → Postfix가 재시도한다.
  수집 실패가 발신자에게 반송으로 되돌아가는 것(**backscatter**)을 막기 위함.
- 인자는 전부 외부 통제 값이므로 경로 조립 전 문자 집합을 좁힌다.

### 4.4 OpenDKIM 변경

```
Mode  s      # 기본값 sv → s (서명 전용). 수신 검증 비활성화
```

`/etc/opendkim/trusted.hosts` — 도메인 와일드카드 제거:

```
127.0.0.1
localhost
::1
```

**변경 이유**: OpenDKIM은 메일 주소가 아니라 **접속 클라이언트**(`InternalHosts`) 기준으로
서명/검증을 가른다. 기존에 `yonggeon.kr`, `*.yonggeon.kr`이 들어 있었는데, 이는 접속 호스트의
**역방향 DNS 이름**으로 매칭된다. 25번을 인터넷에 열면 PTR을 조작 가능한 상대가 내부 호스트로
간주되어 **우리 DKIM 키로 서명된 메일**을 얻을 수 있다.

수신 검증을 끈 이유는 진단 엔진이 직접 검증해야 하기 때문이다. OpenDKIM의
`Authentication-Results` 헤더는 결과를 한 줄로 요약해 **진단에 필요한 세부 사유를 담지 못한다**
(body hash 실패 vs header hash 실패 구분, 키 길이, 셀렉터 조회 원문, `t=y`/`x=` 플래그 등).

발신 서명은 정상 동작함을 회귀 테스트로 확인했다.

### 4.5 계정 / 경로

| 항목 | 값 |
|---|---|
| 시스템 계정 | `maildiag` (uid 996, nologin) |
| 수집기 | `/opt/maildiag/bin/ingest` (root:root 0755) |
| 수집 경로 | `/var/lib/maildiag/incoming/` (maildiag:maildiag 0750) |
| 로그 | `/var/log/mail.log` (`postfix/diag` 태그) |

---

## 5. DNS 구성

| 레코드 | 값 | 비고 |
|---|---|---|
| `mail-check.yonggeon.kr` | `MX 1 mail.yonggeon.kr.` | 진단 메일 수신 도메인 |
| `mail.yonggeon.kr` | `A 175.197.104.119` | 발신 정체성 겸 MX 대상. ddclient가 갱신 |
| `yonggeon.kr` (apex) | Cloudflare Email Routing | **건드리지 말 것** — 개인 메일 수신 경로 |

- `yonggeon.kr` SPF: `v=spf1 include:_spf.mx.cloudflare.net a:mail.yonggeon.kr ~all`
  → `a:mail.yonggeon.kr`이 이 서버의 발신을 인가하는 **유일한** 메커니즘이므로 삭제 금지
- DDNS: `ddclient` (cloudflare protocol) 가 `home.yonggeon.kr, mail.yonggeon.kr` 갱신 중.
  `mail-check`는 A 레코드가 없고 MX만 있으므로 DDNS 대상이 아니다.
- 향후 진단 수신부를 다른 서버로 분리하면 그때 `mail-check`에 자체 A 레코드를 부여할 것.

---

## 6. 진단 엔진 개발 시 확인된 사항

실제 수신 샘플로 검증하며 확인한 내용이다.

### 6.1 사설 IP 감지가 필수다

진단 대상 메일서버가 **같은 내부망**에 있으면, 공유기의 헤어핀 NAT(NAT loopback)가
출발지 주소를 자기 것으로 바꿔치기한다. 실제로 관측된 값:

```json
"client_ip": "172.30.1.254",      // 공유기 LAN 주소
"client_hostname": "_gateway"
```

이 상태로 진단하면 SPF·PTR·RBL·DMARC가 **전부 오판**된다. 사설 IP는 어떤 SPF에도 인가되지
않고, 역방향 DNS도 없기 때문이다.

**대응**: `client_ip`가 RFC 1918 대역(`10/8`, `172.16/12`, `192.168/16`) 또는 루프백이면
리포트를 생성하지 말고 다음과 같이 안내한다.

> 이 메일은 내부망을 거쳐 도착해 발신 IP를 확인할 수 없습니다.
> 진단 대상 서버와 다른 네트워크에서 다시 보내주세요.

PRD상 주 사용자가 "사내 메일 운영자"이므로, 진단 대상과 이 서비스가 같은 사내망에 있는
상황은 **예외가 아니라 흔한 경우**다.

### 6.2 DKIM 미설정은 "헤더 부재"로만 판별된다

DKIM이 설정되지 않은 발신자는 `DKIM-Signature` 헤더가 아예 없다. OpenDKIM류의 검증기는
이런 메일에 `Authentication-Results` 헤더조차 붙이지 않으므로(`AlwaysAddARHeader` 기본 false),
**외부 검증기에 의존하면 가장 흔한 고장 케이스에서 신호가 0이 된다.**
반드시 원본에서 헤더 존재 여부를 직접 확인할 것.

### 6.3 RBL 조회 — 현재 리졸버로는 Spamhaus 사용 불가

```
$ dig +short 2.0.0.127.zen.spamhaus.org A
127.255.255.254
```

`127.0.0.2`는 모든 DNSBL이 "항상 등재됨"으로 응답하는 규약상 테스트 IP다. 그런데 정상 코드
(`127.0.0.2`~`127.0.0.11`) 대신 `127.255.255.254`가 돌아왔다 — **공용 리졸버 경유 조회 거부**를
뜻하는 에러 코드다. 이 서버는 systemd-resolved가 `1.1.1.1`/`8.8.8.8`로 포워딩하는데
Spamhaus는 이를 차단한다.

**위험**: `127.255.255.254`도 A 레코드 응답이므로, NXDOMAIN 여부만 보는 코드는 이를
**"등재됨(FAIL)"으로 오판**한다. 전건 오탐이 발생한다.

**대응 (택 1)**
1. `unbound`를 로컬 **재귀** 리졸버로 설치 (포워딩 모드가 아니어야 함)
2. Spamhaus DQS 무료 키를 발급받아 전용 존 사용

어느 쪽이든 **반환 코드를 화이트리스트 방식으로 파싱**할 것. DNSBL마다 정책이 다르다
(Spamcop은 같은 조건에서 정상 응답 `127.0.0.2`를 반환했다).

### 6.4 검증된 진단 절차

실제 샘플에 수동으로 적용해 결과를 확인한 순서다.

| 검사 | 입력 | 방법 |
|---|---|---|
| PTR | `client_ip` | 역방향 조회 |
| FCrDNS | PTR 결과 | 정방향 재조회 후 `client_ip`와 일치 확인 |
| HELO | `helo`, PTR 결과 | 일치 여부 및 FQDN 형식 검사 |
| SPF | `client_ip`, `mail_from` 도메인 | RFC 7208 `check_host()` |
| DKIM | `message.eml` | 원본 파싱 후 직접 검증 |
| DMARC | `From:` 도메인 | `_dmarc.<도메인>` → 없으면 조직 도메인으로 폴백, 정렬 판정 |
| RBL | `client_ip` | 6.3 참조 |
| TLS | `message.eml` 최상단 `Received:` | `with ESMTPS`면 STARTTLS 사용. `client_protocol`은 TLS를 반영하지 않으므로 쓰지 말 것 (3.3 참조) |

DMARC는 레코드가 없을 때 **조직 도메인으로 폴백**해야 한다. 실제 샘플에서
`_dmarc.sec.crinity.com`은 없었고 `_dmarc.crinity.com`의 `p=none`이 적용되는 상황이었다.

---

## 7. 검증 완료 항목

| 항목 | 결과 |
|---|---|
| 외부 포트 25 도달 | 해외 다수 노드에서 TCP 연결 및 SMTP 배너 수신 확인 |
| 진단 도메인 수신 | 실제 외부 메일서버(Crinity)에서 수신 성공 |
| 릴레이 차단 | 외부 도메인 수신자에 `554 5.7.1 Relay access denied` |
| 원본 헤더 보존 | `Date`·`Message-Id`·`DKIM-Signature` 무손상, 오염 헤더 0건 |
| 세션 값 포착 | `client_ip`·`helo`·`mail_from` 정확히 확보 |
| 발신 서명 회귀 | OpenDKIM 변경 후에도 `DKIM-Signature` 정상 부착 |

---

## 8. 알려진 제약

1. **`Date`/`Message-Id` 자동 추가 — 자체 테스트에서만 발생**
   cleanup의 누락 헤더 추가는 접속 클라이언트가 `local_header_rewrite_clients`
   (기본값 `permit_inet_interfaces` — 이 서버 자신의 IP)에 매칭될 때만 일어난다.
   **외부에서 온 진단 메일은 헤더가 없어도 추가되지 않음을 실측으로 확인했다**
   (`C5124...`: `Message-Id` 없음 유지, `5388A...`: `Date` 없음 유지).
   따라서 서버 자신에서 보내는 자체 테스트(127.0.0.1 또는 172.30.1.11 발)만
   헤더가 추가되어 외부 수신과 다르게 보이니, 픽스처 제작 시 유의할 것.

2. **catch-all 상태**
   `mail-check.yonggeon.kr` 앞으로 오는 **모든** 주소를 수락한다. 스팸이 유입되면 디스크에
   그대로 쌓인다. RCPT 시점 토큰 검증 도입 전까지는 보관 용량을 감시할 것.
   현재 구조는 수집기가 항상 성공하므로 반송을 만들지 않아 backscatter 위험은 없다.

3. **TLS 인증서가 자체 서명(snakeoil)**
   STARTTLS는 동작하지만 인증서 검증은 실패한다. 발신자 대부분이 opportunistic TLS라
   배달에는 지장이 없다.

4. **공인 IP 유동 가능성**
   KT 회선이며 ddclient가 구동 중이다. IP 변경 시 `mail.yonggeon.kr` A 레코드가 갱신되고
   MX가 이를 따라간다. ddclient 실패 시 수신이 중단되므로 실패 알림 구성 권장.
   (실제 갱신 실패 사례가 로그에 1건 있었다 — 일시적 이름 해석 실패)

5. **역방향 DNS(PTR) 없음**
   `175.197.104.119`에 PTR이 없다. 수신에는 무관하나 이 서버가 **발신**할 때는 감점 요인이다.

---

## 9. 남은 작업

우선순위 순.

1. **`unbound` 설치** — RBL 조회 정상화. 미조치 시 RBL 항목이 전건 오탐 (6.3 참조)
2. **RCPT 시점 토큰 검증** — `check_recipient_access` 또는 policy service로 유효 토큰만 수락.
   스팸 유입 차단 및 진단 세션 관리
3. **Spring 서비스 연동** — 3장의 계약 기준. 권한 부여(3.5) 선행 필요
4. **처리 완료분 정리 정책** — 보관 기간, 삭제 주체 결정
5. **`postscreen` 도입** — MX 공개 후 스캐너 트래픽 차단.
   실제로 오픈 프록시 스캐너 접속이 관측됨 (`94.154.43.36`)
6. **Let's Encrypt 인증서** — snakeoil 대체

~~7. `postfix check`의 `libnss*.so differ` 경고 정리~~ — **해결 확인됨** (2026-07-26 재검:
`postfix check` 경고 없음, chroot 내 `libnss*` 사본이 시스템 원본과 바이트 일치)

---

## 10. 부록 — 실제 수집 샘플

`/var/lib/maildiag/incoming/` 에 3건 보관 중이며 개발용 픽스처로 사용 가능하다.

| 디렉터리 | 특징 | 용도 |
|---|---|---|
| `20260726T100606Z-5388A1200F0` | 헤어핀 NAT, `client_ip=172.30.1.254` | 사설 IP 감지 로직 테스트 |
| `20260726T100750Z-981601200F0` | 동일 | 동일 |
| `20260726T101226Z-C51241200F0` | 정상 외부 발신, DKIM 미설정 | 기준선 + DKIM FAIL 케이스 |

정상 샘플(`C5124...`)에 대한 수동 진단 결과:

| 항목 | 판정 | 근거 |
|---|---|---|
| PTR | PASS | `15.164.45.50` → `smtp1.sec.crinity.com` |
| FCrDNS | PASS | 정방향 재확인 시 원래 IP로 복귀 |
| HELO | PASS | PTR과 일치 |
| SPF | PASS | `v=spf1 ip4:15.164.45.50 ... -all` 명시 매칭 |
| TLS | PASS | 최상단 `Received:`에 `with ESMTPS` (meta.json의 `client_protocol`은 `ESMTP`로 기록됨 — 3.3 참조) |
| RBL | 미등재 | Spamcop 기준 (Spamhaus 조회 불가) |
| DKIM | **FAIL** | `DKIM-Signature` 헤더 없음 |
| DMARC | WARN | 조직 도메인의 `p=none` 적용, `rua=` 없음 |

---

## 11. 백업 위치

원복이 필요할 경우 참조.

```
/etc/postfix/main.cf.bak-20260726-163710
/etc/postfix/master.cf.bak-20260726-163710
/etc/opendkim/trusted.hosts.bak-20260726-163710
/etc/opendkim.conf.bak-20260726-140742
```
