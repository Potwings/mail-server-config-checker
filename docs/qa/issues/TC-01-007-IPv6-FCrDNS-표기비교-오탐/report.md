# 이슈 리포트 — IPv6 FCrDNS 비교가 주소 표기 차이로 오탐 FAIL

- **발견 테스트**: TC-01-007 (픽스처 B, IPv6 client_ip) 수행 중 PTR 카드에서 발견
- **발견일**: 2026-07-28
- **심각도**: Medium (IPv6 발신 서버는 FCrDNS가 정상이어도 항상 FAIL 판정)

## 증상

client_ip `2001:4860:4860::8888`(압축 표기)의 PTR `dns.google`을 정방향 조회하면
dnsjava가 AAAA를 완전 표기 `2001:4860:4860:0:0:0:0:8888`로 돌려주는데,
`PtrCheck`가 **문자열 비교**(`forward.values().contains(ip)`)로 왕복을 확인해
같은 주소인데도 "정방향 확인 실패 … ≠ …"로 FAIL 처리됨.

- 증적: `screenshot-001.jpg` — 동일 주소 두 표기가 ≠로 표시됨

## 원인

IPv6는 동일 주소의 문자열 표기가 여러 개(압축/완전/대소문자) — 비교 전 정규화 필요.
IPv4-only 시절에는 dotted-quad 표기가 유일해 문제가 없었고, M8에서 IPv6 대상이
실제로 유입 가능해지며 드러남.

## 조치

`PtrCheck`에서 비교 전 양쪽을 Guava `InetAddresses.forString` → `toAddrString`
(RFC 5952 정규형)으로 정규화해 비교. 단위 테스트
`IPv6_FCrDNS는_표기가_달라도_왕복_확인된다` 추가.

## 재검증

수정 후 픽스처 C(동일 IPv6) 재적재 → PTR 카드에서 `FCrDNS 확인: … → dns.google → …`
evidence 확인 (결과는 QA 시트 TC-01-010 참조).
