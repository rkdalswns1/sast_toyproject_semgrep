# Phase 11 KISA Diagnostic Rule Candidate Research

조사일: 2026-09-01

이 문서는 조사 당시 KISA 2021 카탈로그에서 `NOT_IMPLEMENTED`였던 41개 항목 중 Semgrep Community Edition과 현재 지원 언어(Java, JavaScript, Python)로 범위를 제한해 시험 가능한 후보를 선별한 결과다.

## Approved First Scope

사용자 승인에 따라 Phase 11에서는 아래 범위만 구현한다.

| KISA ID | 항목명 | 승인 언어 | 구현 상태 |
|---|---|---|---|
| 제2절-11 | 부적절한 인증서 유효성 검증 | Java, JavaScript, Python | `PARTIAL` |
| 제5절-5 | 신뢰할 수 없는 데이터의 역직렬화 | Java, Python | `PARTIAL` |

코드삽입, 적절하지 않은 난수 값 사용 및 조건부 후보는 이번 Phase에서 구현하지 않는다. JavaScript 역직렬화도 라이브러리별 동작 차이가 커 승인 범위에서 제외한다.

## Decision Criteria

후보는 다음 조건을 모두 만족하거나, 제한 조건을 명확히 적을 수 있을 때만 선정한다.

1. 위험 API 호출, 명시적인 보안 해제 설정 또는 단일 함수 안의 입력 흐름처럼 정적 패턴이 분명하다.
2. 현재 로컬 Semgrep Community Edition으로 실행할 수 있다. Pro 전용 cross-file 분석을 전제로 하지 않는다.
3. 지원 언어별 취약 샘플과 대응되는 정상 샘플을 짧고 결정적으로 작성할 수 있다.
4. 탐지하지 못하는 프레임워크·API와 예상 오탐 원인을 설명할 수 있다.
5. 한 KISA 항목당 독립 YAML 하나라는 현재 품질 계약을 유지한다.

공개 규칙 “활용 가능”은 공개 규칙을 그대로 원격 실행한다는 뜻이 아니다. 이 프로젝트는 네트워크 없이 로컬 YAML만 실행하므로, 채택 시 KISA `kisa_standard_id`, 언어별 고유 Rule ID, 메시지와 테스트를 포함한 로컬 규칙으로 검토·적응해야 한다. 규칙 원문을 복사하거나 실질적으로 변형할 때는 Semgrep Rules License와 원본 출처를 기록한다.

## Recommended First Batch

| 우선순위 | KISA ID | 항목명 | 제안 지원 언어 | 공개 Semgrep 규칙 활용 여부 | 자체 규칙 필요 여부 | 예상 오탐 위험 | 구현 난이도 | 선정 근거와 제한 |
|---:|---|---|---|---|---|---|---|---|
| 1 | 제2절-11 | 부적절한 인증서 유효성 검증 | Java, JavaScript, Python | 부분 활용 가능. Python의 `unverified-ssl-context`, Node TLS 검증 우회 규칙 등을 참고할 수 있음 | 필요. Java trust-all `TrustManager`와 KISA metadata를 로컬 규칙으로 정리 | 낮음 | 중간 | `verify=False`, `rejectUnauthorized=false`, 비어 있는 `checkServerTrusted`처럼 보안 검증을 명시적으로 끄는 패턴은 취약·정상 구분이 명확함 |
| 2 | 제5절-5 | 신뢰할 수 없는 데이터의 역직렬화 | Java, Python | 활용 가능. 공식 Community 저장소에 Java JMS/Jackson/SnakeYAML 및 Python deserialization 규칙이 존재함 | 필요. 현재 프로젝트가 검증할 API 범위와 KISA metadata를 고정 | 중간 | 중간 | 위험 역직렬화 API는 분명하지만 입력이 실제로 신뢰되는 경우도 있으므로 우선 대표 API와 요청 입력의 단일 함수 흐름으로 제한. JavaScript는 라이브러리 편차가 커서 1차 제외 |
| 3 | 제1절-2 | 코드삽입 | JavaScript, Python | 활용 가능. JavaScript `detect-eval-with-expression`, Python `dangerous-code-run` 등 공식 Community 규칙이 존재함 | 필요. 비상수 입력이 `eval`·`exec` 계열로 흐르는 범위와 KISA metadata를 고정 | 중간 | 중간 | 위험 sink는 명확하지만 상수식·제한된 내부 표현식 사용을 모두 취약점으로 볼 수 있으므로 비상수 또는 요청 입력 흐름으로 제한. Java는 ScriptEngine·표현식 엔진별 차이로 1차 제외 |
| 4 | 제2절-8 | 적절하지 않은 난수 값 사용 | Java, JavaScript, Python | 부분 활용 가능. JavaScript `detect-pseudoRandomBytes` 등은 참고 가능 | 필요. Java `Random`, JavaScript `Math.random`, Python `random`이 보안 토큰·키 생성 문맥에서 사용되는 경우를 언어별로 정의 | 중간 | 낮음~중간 | API 패턴은 쉽지만 게임·샘플링 등 비보안 난수 사용은 취약점이 아니므로 변수명, 토큰 생성 함수 또는 보안 API 인접 문맥으로 범위를 제한해야 함 |

조사 단계에서는 위 네 항목을 권고했으나 실제 1차 구현은 앞의 `Approved First Scope`에 명시한 두 항목과 승인 언어로 제한한다.

## Conditional Candidates

| 우선순위 | KISA ID | 항목명 | 제안 지원 언어 | 공개 Semgrep 규칙 활용 여부 | 자체 규칙 필요 여부 | 예상 오탐 위험 | 구현 난이도 | 조건부인 이유 |
|---:|---|---|---|---|---|---|---|---|
| 5 | 제2절-7 | 충분하지 않은 키 길이 사용 | Java, JavaScript, Python | 일부 암호화 API 규칙을 참고할 수 있으나 KISA 기준과 정확히 일치하는 공통 규칙은 확인이 필요함 | 필요 | 낮음 | 중간 | 리터럴 키 길이가 기준 미만인 호출은 명확하다. 구현 전에 공식 가이드의 알고리즘별 최소 길이를 그대로 시험 기준으로 확정해야 함 |
| 6 | 제6절-2 | 제거되지 않고 남은 디버그 코드 | JavaScript, Python | 프레임워크별 공개 규칙을 부분 참고할 수 있음 | 필요 | 중간 | 낮음 | `debug=True`, `debugger` 등은 검출이 쉽지만 개발·테스트 파일에서는 정상일 수 있다. 운영 소스에서 명시적으로 활성화된 디버그 설정만 대상으로 제한해야 함. Java의 일반 출력문은 오탐이 커서 제외 |
| 7 | 제1절-12 | 서버사이드 요청 위조 | Java, JavaScript, Python | Registry에 관련 규칙이 있으나 고정밀도 coverage 상당 부분은 Pro 규칙에 의존함 | 필요 | 중간 | 높음 | 요청 입력에서 HTTP client까지의 taint 흐름과 URL 허용목록을 함께 모델링해야 한다. Community Edition의 단일 함수·대표 프레임워크 범위로 성공적인 정상/취약 시험이 가능할 때만 채택 |

조건부 후보는 1차 네 항목을 구현하고 실제 오탐과 실행 시간을 검토한 뒤 별도 승인을 받아야 한다.

## Excluded from Phase 11 First Scope

다음 34개 항목은 카탈로그에서 삭제하지 않고 `NOT_IMPLEMENTED`를 유지한다.

| 제외 그룹 | KISA ID | 제외 근거 |
|---|---|---|
| 프레임워크·데이터 흐름 의존 입력 검증 | 제1절-7, 제1절-9, 제1절-10, 제1절-13, 제1절-15 | URL 허용목록, XML/LDAP 구성, HTTP header 생성 및 보안 결정 문맥을 알아야 하므로 짧은 범용 규칙으로는 누락·오탐 위험이 큼 |
| 현재 언어에서 부적합하거나 정밀 분석 필요 | 제1절-14, 제1절-16, 제1절-17 | 정수·메모리·포맷 스트링 문제는 현재의 관리형 언어 3종에서 의미가 다르거나 정교한 타입·데이터 흐름 분석이 필요함 |
| 인증·인가·업무 정책의 부재 판단 | 제1절-11, 제2절-1, 제2절-2, 제2절-3, 제2절-9, 제2절-10, 제2절-12, 제2절-16 | 보호 로직이 다른 파일·미들웨어·배포 구성에 있을 수 있어 특정 코드가 “없다”는 사실을 로컬 패턴만으로 확정하기 어려움 |
| 중요정보 의미와 운영 절차 필요 | 제2절-5, 제2절-13, 제2절-14, 제2절-15 | 데이터가 실제 중요정보인지, 주석이 유효한 비밀인지, 해시 대상이 비밀번호인지, 다운로드 무결성이 다른 계층에서 검증되는지 판단해야 함 |
| 시간·상태 및 제어 흐름 | 제3절-1, 제3절-2 | TOCTOU와 무한 반복은 경로·동시성·종료 조건 분석이 필요하고 의도적인 반복문을 오탐하기 쉬움 |
| 오류 처리 문맥 | 제4절-1, 제4절-2, 제4절-3 | 사용자 응답, 중앙 예외 처리기와 로깅 정책을 함께 봐야 하며 단순 `catch`·`except` 패턴은 오탐이 큼 |
| 객체·자원 생명주기 | 제5절-1, 제5절-2, 제5절-3, 제5절-4 | null 가능성, 자원 소유권, 해제 이후 경로와 초기화 여부는 언어별 흐름 분석이나 컴파일러 판단이 필요함 |
| 세션·캡슐화·포괄 API | 제6절-1, 제6절-3, 제6절-4, 제7절-1, 제7절-2 | 세션 소유 관계나 private 배열의 의도, DNS 기반 보안 결정, “취약한 API” 범주는 프로젝트 문맥 없이 일반화하기 어려움 |

## Public Evidence

- [Semgrep Community rules repository](https://github.com/semgrep/semgrep-rules) — Community Edition 규칙의 공식 저장소이며 공개 규칙과 Pro 규칙의 범위를 구분한다.
- [Semgrep code injection guidance](https://semgrep.dev/docs/category/code-injection) — Java, JavaScript, Python 코드삽입 위험과 규칙 작성 근거를 제공한다.
- [Python insecure deserialization guidance](https://semgrep.dev/docs/learn/vulnerabilities/insecure-deserialization/python-deserialization) — 위험 역직렬화 API와 taint 기반 탐지 범위를 설명한다.
- [Java Community security rules](https://github.com/semgrep/semgrep-rules/tree/develop/java/lang/security) — JMS/Jackson/SnakeYAML 역직렬화 규칙을 확인할 수 있다.
- [JavaScript Community security rules](https://github.com/semgrep/semgrep-rules/tree/develop/javascript/lang/security) — eval과 의사난수 관련 공개 규칙을 확인할 수 있다.
- [Python Community security rules](https://github.com/semgrep/semgrep-rules/tree/develop/python/lang/security) — 위험 코드 실행, 역직렬화, 인증서 검증 우회 규칙을 확인할 수 있다.
- [Semgrep Pro rules](https://semgrep.dev/products/semgrep-code/pro-rules/) — cross-file·cross-function dataflow에 의존하는 고정밀 규칙은 현재 로컬 Community Edition 범위와 구분해야 한다.

## Approval Boundary

승인되지 않은 나머지 후보에는 아래 작업을 하지 않는다.

- `app/rules/catalog.py` 구현 상태 또는 지원 언어 변경
- `app/rules/semgrep/kisa-2021/` YAML 추가
- DB seed 또는 migration 변경
- `tests/samples/` 및 기대 Finding 변경

1차 네 후보 전체를 자동 승인된 것으로 간주하지 않는다. 이번 구현은 `Approved First Scope`의 항목과 언어만 대상으로 한다.

## Phase 23 Follow-up Decision

2026-09-02 재조사와 사용자 승인에 따라 Phase 11 당시 보류·제외했던 항목 중 아래 다섯 항목을 두 번째 확대 범위로 확정했다. 범위는 단일 함수 또는 직접 참조 패턴으로 제한하고 모두 `PARTIAL`로 관리한다.

| KISA ID | 항목명 | 승인 언어 | 제한된 탐지 범위 |
|---|---|---|---|
| 제1절-2 | 코드삽입 | Java, JavaScript, Python | 요청 입력에서 `eval` 계열 실행까지의 taint |
| 제2절-7 | 충분하지 않은 키 길이 사용 | Java, JavaScript, Python | 리터럴 RSA 키 길이 2,048비트 미만 |
| 제6절-3 | Public 메소드부터 반환된 Private 배열 | Java | private 배열 원본 직접 반환 |
| 제6절-4 | Private 배열에 Public 데이터 할당 | Java | 외부 배열 참조의 private 필드 직접 대입 |
| 제7절-2 | 취약한 API 사용 | Java | Servlet 내부 `System.exit` 호출 |
