# M8 백로그 — 실메일 전환(M7)으로 이관된 검사 항목

작성일: 2026-07-28 · 기준: PRD v1.4, `m7-plan.md`

## 배경

M7이 도메인/IP 입력 폼과 `GET /api/v1/diagnose`를 제거하면서, 그 위에 구현돼 있던
PR #1(`feature/coverage-gaps`, 2026-07-26 드래프트)의 커버리지 확대 5건이 기반을 잃었다.
PR은 닫았지만 **브랜치 `feature/coverage-gaps`는 원격에 보존**되어 있어 구현 참조가 가능하다.

기능 자체는 대부분 실메일 모드에서도 유효하며, 오히려 발신 IP·HELO·MAIL FROM이 확정되어
더 정확한 판정이 가능하다. 아래 판정에 따라 M8에서 재구현한다.

## 이관 항목

| # | 항목 | 원본 커밋 | 판정 | 재구현 메모 |
|---|------|----------|------|------------|
| 1 | DMARC 외부 리포트 수신 승인 (RFC 7489 §7.1) | `cc19ad5` | **그대로 이식** | 도메인만 필요 — `DmarcCheck` 확장 또는 별도 `Check`. rua/ruf가 타 조직이면 `<정책도메인>._report._dmarc.<수신도메인>` TXT 확인, 없으면 WARN |
| 2 | PTR/RBL 대상 IP IPv6(AAAA) 지원 | `b6067db` | **범위 축소 후 재작성** | MX 도출부(`TargetIpResolver`)는 M7에서 삭제 — 폐기. 실메일은 `client_ip`가 IPv6일 수 있으므로 **RBL nibble 역순 조회(RFC 3596)와 미지원 존 제외 표시 로직만** 살린다 |
| 3 | PTR 제네릭/동적 호스트명 경고 | `dc5010b` | **그대로 이식** | 실메일에서 더 정확(대상 IP가 세션 접속 IP로 확정). FCrDNS 성립해도 IP 옥텟 포함·dynamic/pool/dsl 패턴이면 WARN |
| 4 | 사설/예약 IP 검증 | `040eda1` | **대부분 사장** | 입력 400 거부는 진입점 삭제로 무의미. 사설 IP 차단은 M7 `IpClassifier` + `REJECTED_PRIVATE_IP`가 이미 담당. `IpRanges` 유틸의 대역 판정 로직만 필요 시 참조 |
| 5 | MTA-STS(RFC 8461) / TLS-RPT(RFC 8460) 검사 카드 | `d34ef1c` | **그대로 이식** | 도메인만 필요. TXT + HTTPS 정책 파일 fetch·파싱, 정책 mx와 실제 MX 대조(enforce 불일치 FAIL). `PolicyFetcher` 추상화로 단위 테스트 네트워크 금지 원칙 유지 |

## M8 본 범위 (PRD v1.4 기준, 참고)

실메일 세션과 `message.eml`이 있어야 가능한 검사 — 위 이관 항목과 함께 구현한다.

- DKIM 서명 검증 (`message.eml` 원문 사용 — 수집 디렉터리 보존은 `MailResult.incomingDir`)
- HELO/PTR 일치 검사 (현재 PTR 카드에 "2단계에서 검사" 안내만 있음)
- DMARC alignment (SPF/DKIM 결과와 From 도메인 정렬 — adkim/aspf 반영)
- 헤더 품질 (Message-ID, Date, Received 체인 등)

## 참고

- 이관 항목 1·3·5는 `Check` 구현체 추가만으로 끝나는 작업 (설계 규칙: "검사 추가 = `Check` 구현체 추가만으로")
- 원본 브랜치 조회: `git log origin/feature/coverage-gaps`, 특정 커밋 참조: `git show <해시>`
