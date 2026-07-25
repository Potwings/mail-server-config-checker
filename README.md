# mail-server-config-checker

Check your mail server's SPF, DMARC, PTR, RBL, and MX configuration in one shot.

도메인 하나만 입력하면 메일 서버 설정을 RFC 기준으로 한 번에 진단합니다.

## 검사 항목 (1단계 — DNS 정적 검사)

| 항목 | 내용 |
|---|---|
| **SPF** | RFC 7208 구문 검증, include/redirect 재귀 10-lookup 카운팅, 중복 레코드 permerror, `+all` 과허용 경고 |
| **DMARC** | RFC 7489 정책 검증, 조직 도메인 폴백(서브도메인 대응), rua/pct/alignment 점검 |
| **MX / DNS** | MX 존재·우선순위·해석, MX→CNAME 위반(RFC 5321/2181), Null MX(RFC 7505) 감지 |
| **PTR / FCrDNS** | 역방향 DNS 존재 + 정방향 왕복 확인 (IP는 MX에서 도출하거나 직접 입력) |
| **RBL** | Spamhaus ZEN(DQS), Barracuda, SpamCop 등재 조회 — 오류 코드를 "미등재"로 오판하지 않음 |
| **DNS 전파** | 권한 NS 기준값 vs 글로벌·국내 통신사(KT/SKB/LG U+) 리졸버 7종 비교, 잔여 TTL 표시 |

DKIM 검증은 2단계(실메일 검사 모드)에서 지원 예정입니다 — 셀렉터는 DNS로 열거할 수 없기 때문입니다.

## 실행

```bash
./gradlew :checker-web:bootRun
```

브라우저에서 `http://localhost:8080` 접속, 또는:

```bash
curl "http://localhost:8080/api/v1/diagnose?domain=example.com"
curl "http://localhost:8080/api/v1/diagnose?domain=example.com&ip=203.0.113.5"
```

### Spamhaus DQS 키 (권장)

Spamhaus는 공용 리졸버 경유 조회를 차단하므로 [무료 DQS 키](https://www.spamhaus.com/free-trial/)를 발급받아 설정해야 ZEN 조회가 동작합니다. 키가 없으면 Spamhaus 항목은 SKIP + 발급 안내로 표시됩니다(미등재로 오판하지 않음).

**로컬 개발 — `application-local.yml` (권장)**

```bash
cp checker-web/src/main/resources/application-local.yml.example \
   checker-web/src/main/resources/application-local.yml
# 파일을 열어 spamhaus-dqs-key 에 발급받은 키를 입력
./gradlew :checker-web:bootRun    # bootRun 은 기본으로 local 프로필 활성화
```

`application-local.yml` 은 `.gitignore` 대상이라 키가 커밋되지 않습니다.

**배포 환경 — 환경변수**

```bash
SPAMHAUS_DQS_KEY=your-key java -jar checker-web.jar
```

Barracuda는 조회에 사용하는 DNS 서버 IP의 [무료 등록](https://barracudacentral.org/account/register)이 필요합니다.

## 빌드 / 테스트

```bash
./gradlew build
```

- JDK 17, Spring Boot 3.5, dnsjava
- `checker-core`: 웹과 분리된 검사 엔진 모듈 (재사용 가능)
- `checker-web`: REST API + UI

## License

Apache License 2.0
