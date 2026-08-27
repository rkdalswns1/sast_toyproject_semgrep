# Requirements

## Purpose

Java, JavaScript, Python 소스 코드를 대상으로 정적 애플리케이션 보안 테스트를 수행하고, 진단 결과를 저장·조회·관리한다.

## Functional Requirements

- 사용자 로그인·로그아웃
- ADMIN / USER 역할 구분
- ADMIN 사용자 계정 생성·수정
- ADMIN 사용자 역할 변경
- ADMIN 사용자 활성화·비활성화
- ADMIN 사용자 비밀번호 초기화
- 사용자 계정은 물리 삭제하지 않는다.
- 프로젝트 생성·수정·조회
- 프로젝트별 사용자 권한 관리
- ZIP 소스 업로드
- Java, JavaScript, Python 언어 구분
- Semgrep 기반 분석 실행
- 분석 상태 관리: PENDING, RUNNING, COMPLETED, FAILED
- 분석 결과 정규화 및 저장
- 파일 경로와 코드 위치를 포함한 Finding 조회
- severity, confidence, rule 정보 제공
- Finding 상세 조회 및 severity 필터
- KISA 소프트웨어 개발보안 49개 항목 카탈로그 관리
- 항목별 구현 상태와 지원 언어 관리

## Security Requirements

- 비밀번호는 해시로 저장한다.
- 권한이 없는 사용자는 프로젝트와 분석 결과를 조회할 수 없다.
- ZIP Slip과 절대 경로를 차단한다.
- 심볼릭 링크를 허용하지 않는다.
- 업로드 크기와 분석 실행 시간을 제한한다.
- 분석별 작업 디렉터리를 분리한다.
- 최초 관리자 계정은 `admin`이다.
- 최초 관리자 비밀번호는 `admin`이며 평문이 아닌 bcrypt 해시로 저장한다.
- 관리자는 자기 자신을 비활성화할 수 없다.
- 마지막 활성 ADMIN 계정은 비활성화하거나 USER로 변경할 수 없다.
- 로그인·로그아웃을 포함한 상태 변경 요청은 CSRF 토큰으로 보호한다.
- 구체적인 Enum, 환경변수 및 업로드 제한은 `configuration.md`를 따른다.

## Dependency Versioning

이 문서는 제품의 기능 요구사항을 정의한다.

설치할 Python 패키지와 정확한 버전은 Phase 1에서 생성하는 프로젝트 루트의 `requirements.txt`에 고정한다.

Python 실행 버전은 3.12를 기준으로 한다. Semgrep 버전도 `requirements.txt`에서 고정한다.

## Completion Criteria

각 요구사항에 대해 구현 위치와 검증 방법이 존재해야 한다. 핵심 사용자 흐름은 자동 테스트로 검증한다.
