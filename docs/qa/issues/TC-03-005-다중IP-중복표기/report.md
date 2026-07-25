# Issue Report: TC-03-005

## Overview

| Field | Value |
|-------|-------|
| **Test Case ID** | TC-03-005 |
| **Test Name** | 다중 IP worst-of 집계 및 [ip] 태그 |
| **Severity** | Minor |
| **Date** | 2026-07-26 |
| **URL** | http://localhost:8080 |

## Description

발신 IP를 2개 이상 입력했을 때 SPF 카드의 evidence 한 줄에 IP가 두 번 표기된다.
다중 IP 구분용 `[ip]` 태그와 메시지 본문의 IP가 겹치기 때문으로, 같은 규칙을 쓰는
PTR/RBL 카드는 태그만 붙이고 본문에서는 IP를 반복하지 않아 표기 규칙도 어긋난다.

기능 판정(worst-of 집계, pass/softfail 구분)은 정상이므로 표시 문제에 해당한다.

## Steps to Reproduce

1. http://localhost:8080 접속
2. 도메인에 `gmail.com` 입력
3. 발신 IP에 `209.85.128.1, 1.2.3.4` 입력
4. 진단 실행 후 SPF 카드의 evidence 확인

## Expected Result

```
[209.85.128.1] 발신 IP 평가: pass (매칭: ip4:209.85.128.0/17)
[1.2.3.4] 발신 IP 평가: softfail — 이 IP는 SPF 허용 목록에 포함되지 않음 (매칭: ~all)
```

## Actual Result

```
[209.85.128.1] 발신 IP 209.85.128.1 평가: pass (매칭: ip4:209.85.128.0/17)
[1.2.3.4] 발신 IP 1.2.3.4 평가: softfail — 이 IP는 SPF 허용 목록에 포함되지 않음 (매칭: ~all)
```

## Evidence

read_page 접근성 트리로 확인 (스크린샷 대체 — 텍스트 표기 문제라 트리 출력이 더 명확).

## Console Errors (if any)

```
None
```

## Additional Notes

`SpfCheck.evaluateSenderIps()`에서 태그가 붙는 다중 IP인 경우 라벨에서 IP를 빼도록 수정.
단일 IP일 때는 태그가 없으므로 기존처럼 `발신 IP <ip> 평가:` 형태를 유지한다.
`SpfCheckTest.다중_IP는_worst_of_집계와_IP_태그` 단언을 수정 후 문자열로 갱신했고,
빌드·재검증(다중/단일 IP 모두) 통과 확인.
