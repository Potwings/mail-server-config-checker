# 서버 세션 작업 목록

## 서비스 개요 (서버 세션용 배경)

테스트 메일 1통으로 SPF/DKIM/DMARC/PTR/RBL 등을 진단하는 웹 서비스. 구조:
사용자가 유니크 주소(`check-{uuid}@mail-check.yonggeon.kr`) 발급 → 테스트 메일 발송 →
이 서버의 Postfix가 수신, pipe transport로 `/opt/maildiag/bin/ingest`가
`/var/lib/maildiag/incoming/`에 원문(`message.eml`)+세션 정보(`meta.json`) 적재 →
Spring Boot 앱(`checker-web`)이 디렉터리를 폴링해 검사 자동 실행 → 웹 결과 페이지 표시.
수신 인프라(Postfix·수집기)는 구축 완료, **앱은 아직 이 서버에 배포되지 않음**(로컬 QA만 완료).
앱 빌드는 이 저장소에서 `./gradlew build`(JDK 17 필요 — 배포 작업과 요구사항 동일).

홈서버(Beelink, `mail-check.yonggeon.kr` 수신 호스트)에서 진행할 작업 정리.
근거 문서: `infra-work.md` §9(남은 작업)·§6.3(RBL 리졸버)·§3.5(권한), PRD v1.6 M6 잔여·M9.
작성일: 2026-08-02. 우선순위 순.

## 1. unbound 재귀 리졸버 설치 — RBL 조회 정상화 (최우선)

- **왜**: 현재 systemd-resolved가 `1.1.1.1`/`8.8.8.8`로 포워딩 → 공용 리졸버 차단 정책이 있는 RBL 존에서 오류 코드가 반환됨. Spamhaus는 DQS 키로 해결됐지만(2026-07-27 발급), **비-Spamhaus 존(Barracuda·SpamCop·PSBL·Mailspike·Hostkarma)은 미조치 시 오탐 위험** (`infra-work.md` §6.3)
- 할 일:
  - [ ] `unbound`를 **재귀 모드**로 설치 (포워딩 모드 금지 — 포워딩이면 설치 의미 없음)
  - [ ] 앱(또는 시스템)의 RBL 조회가 unbound를 경유하도록 리졸버 설정
  - [ ] Barracuda는 조회 IP 등록 필요 (barracudacentral.org에 공인 IP `175.197.104.119` 등록)
  - [ ] 검증: `dig +short 2.0.0.127.b.barracudacentral.org` → `127.0.0.2` 정상 코드 확인 (에러 코드 `127.255.255.x`가 아닌지). SpamCop·PSBL·Mailspike·Hostkarma도 동일하게 테스트 IP로 확인

## 2. Spring 앱 배포 + 스모크 테스트 (M9 선행)

- **왜**: M7·M8까지 로컬 QA만 완료. 실서버 end-to-end 검증 필요
- 할 일:
  - [ ] JDK 17 설치 확인, 앱 빌드 산출물 배치
  - [ ] 실행 계정을 `maildiag` 그룹에 추가: `usermod -aG maildiag <spring_app_user>` 후 재로그인 (`infra-work.md` §3.5 — 수집 디렉터리 읽기는 그룹 권한으로 충분, 삭제·이동 금지)
  - [ ] `data-dir`(세션 저장소) 경로 생성 + 쓰기 권한 부여
  - [ ] 환경변수 `SPAMHAUS_DQS_KEY` 설정 (프로덕션은 local 프로필 아님 — yml에 키 노출 금지)
  - [ ] `application.yml` 프로덕션 값 확인: `mailcheck.intake.{incoming-dir=/var/lib/maildiag/incoming, data-dir, mail-domain=mail-check.yonggeon.kr, poll-interval, session-ttl}`
  - [ ] systemd 서비스 유닛 작성(재부팅 자동 시작), 웹은 기존 Cloudflare Tunnel 라우팅에 연결
  - [ ] **스모크**: 주소 발급 → 외부 메일서버(Gmail 등)에서 실메일 발송 → 카드 자동 생성 확인, RBL 카드가 오탐 없이 표시되는지 확인(1번 완료 전제)

## 3. RCPT 시점 토큰 검증 — catch-all 스팸 차단

- **왜**: 현재 모든 주소를 수락(catch-all)해 스팸이 디스크에 그대로 쌓임 (`infra-work.md` §8.2). 인테이크의 "토큰 미매칭 스킵"은 임시 방어일 뿐
- 할 일:
  - [ ] Postfix `check_recipient_access` 또는 policy service로 유효 토큰(`check-{uuid}`, 세션 파일 존재 + TTL 유효)만 RCPT 단계에서 수락
  - [ ] 앱의 세션 저장소(`{data-dir}/sessions/`)를 조회하는 방식 결정 — policy service가 파일 직접 확인 vs 앱에 HTTP 질의
  - [ ] 미발급 주소는 5xx 거부(수집 전 차단이므로 backscatter 없음) 확인

## 4. 처리 완료분 정리 정책 결정·적용

- **왜**: 수집 디렉터리는 앱이 읽기 전용(eml 재검사를 위해 보존 필요 — `MailResult.incomingDir`), 세션 파일도 무한 축적. 보관 기간·삭제 주체 미정 (M6 잔여)
- 할 일:
  - [ ] 보관 기간 결정 (예: 세션 TTL 24h + 여유 → 7일)
  - [ ] 삭제 주체 결정 (서버 cron/systemd-timer가 유력 — 앱은 수집 디렉터리 쓰기 권한 없음)
  - [ ] 세션 JSON(`{data-dir}/sessions/`)과 수집 디렉터리(`incoming/`) 정리 주기 일치시킬 것 — eml이 먼저 지워지면 결과 카드의 원문 근거가 사라짐
  - [ ] RCPT 검증(3번) 도입 전까지는 디스크 사용량 감시

## 5. postscreen 도입 — 스캐너 트래픽 차단

- **왜**: MX 공개 후 실제 오픈 프록시 스캐너 접속 관측됨(`94.154.43.36`)
- 할 일:
  - [ ] 진단 전용 smtpd에 postscreen 적용 (수신 지연이 진단 UX에 주는 영향 — after-220 테스트는 첫 수신을 지연시킴 — 검토 후 수준 결정)
  - [ ] 적용 후 정상 실메일 수신 회귀 확인

## 6. Let's Encrypt 인증서 — snakeoil 대체

- **왜**: STARTTLS는 동작하나 인증서 검증 실패 상태. 배달 지장은 없지만 정식 인증서로 교체
- 할 일:
  - [ ] `mail.yonggeon.kr` 대상 certbot 발급 + Postfix `smtpd_tls_cert_file`/`key_file` 교체
  - [ ] 자동 갱신(deploy hook에서 postfix reload) 구성

## 7. (권장) 운영 안정화 잔여

- [ ] **ddclient 실패 알림** — KT 유동 IP. 갱신 실패 시 수신 전면 중단되는데 실제 실패 사례 1건 관측됨 (`infra-work.md` §8.4)
- [ ] **발신용 PTR** — `175.197.104.119`에 PTR 없음. 수신에는 무관하나 이 서버가 발신할 때 감점 요인 (§8.5). KT 회선이라 설정 불가할 수 있음 — 확인만
- [ ] 배포 후 실사용 지표 수집 방법 결정 (M9 — 접속/진단 건수 로그 등)

---

## 서버 세션이 아닌, 저장소 측 잔여 (참고)

- 주소 발급 rate limit (M9 전후 보강)
- 3번 방식에 따라 policy service 연동 코드가 필요할 수 있음