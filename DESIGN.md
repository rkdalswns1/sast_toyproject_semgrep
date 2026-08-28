# Design

## Source of truth
- Status: Active
- Last refreshed: 2026-08-28
- Primary product surfaces: 로그인, 사용자 관리, 프로젝트, ZIP 업로드, 분석 이력, Finding, KISA 규칙
- Evidence reviewed: `docs/ui-design.md`, `docs/routes.md`, `design/pencil-new.pen`, `design/export.pdf`, `design/pen-dev-sfr-012-013-prompt.md`, Jinja2 templates, `app/static/css/app.css`

## Brand
- Personality: 신뢰할 수 있고 절제된 사내 보안 도구
- Trust signals: 명확한 역할 표시, 분석 상태, 보안 제한, 추적 가능한 식별자
- Avoid: 과도한 장식, 소비자용 마케팅 문구, 보안 상태를 모호하게 만드는 색상

## Product goals
- Goals: ADMIN이 안전하게 소스를 분석하고 USER가 할당된 결과를 빠르게 읽는다.
- Non-goals: SPA, 실시간 진행률, 다중 SAST 엔진, 이메일 발송
- Success signals: 권한별 작업이 명확하고 Finding에서 원인과 조치 정보를 추적할 수 있다.

## Personas and jobs
- Primary personas: 시스템 관리자, 프로젝트 일반 사용자
- User jobs: 계정·프로젝트·규칙 관리, 분석 실행, 결과 조회
- Key contexts of use: 데스크톱 사내망 브라우저

## Information architecture
- Primary navigation: 프로젝트, 사용자 관리(ADMIN), KISA 규칙
- Core routes/screens: `docs/routes.md`를 따른다.
- Content hierarchy: 목록 → 프로젝트/분석 상세 → Finding 상세

## Design principles
- 권한에 없는 작업은 비활성 버튼이 아니라 화면에서 제거한다.
- 상태와 오류를 구분하되 내부 오류 원문은 ADMIN에게만 제공한다.
- 테이블에서 식별자, 상태, 지원 언어를 한눈에 비교할 수 있게 한다.

## Visual language
- Color: 기존 `app/static/css/app.css` 팔레트 유지
- Typography: 기존 시스템 글꼴 유지
- Spacing/layout rhythm: 기존 page-shell, card, metadata-grid 패턴 유지
- Shape/radius/elevation: 기존 card와 button 스타일 유지
- Motion: 필수 동작 없음
- Imagery/iconography: 장식용 이미지 없이 상태 중심

## Components
- Existing components to reuse: page header, card, table, badge, form stack, alert, empty state
- New/changed components: 언어 지원 배지 그룹, 구현 상태 배지, 규칙 필터, 규칙 등록 폼
- Variants and states: IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED, 활성/비활성
- Token/component ownership: `app/static/css/app.css`

## Accessibility
- Target standard: WCAG 2.1 AA 수준의 대비와 키보드 접근
- Keyboard/focus behavior: 모든 입력·필터·버튼에 가시적 포커스
- Contrast/readability: 상태를 색상만으로 전달하지 않고 텍스트 병기
- Screen-reader semantics: 표 머리글, label, fieldset/legend 사용
- Reduced motion and sensory considerations: 핵심 정보에 애니메이션을 요구하지 않음

## Responsive behavior
- Supported breakpoints/devices: 데스크톱 우선, 좁은 화면에서 표 가로 스크롤 허용
- Layout adaptations: 필터와 폼은 좁은 화면에서 한 열로 배치
- Touch/hover differences: hover 없이도 모든 기능과 상태를 식별 가능

## Interaction states
- Loading: 분석 요청 중 단순 대기
- Empty: 등록 규칙 없음, 필터 결과 없음 상태 분리
- Error: 입력 오류와 서버 오류 분리
- Success: 저장 후 목록 또는 상세로 이동
- Disabled: 비활성 규칙은 상태를 표시하되 실행 규칙 세트에서 제외
- Offline/slow network: 별도 오프라인 모드 없음

## Content voice
- Tone: 짧고 직접적인 한국어 관리 도구 문체
- Terminology: 진단 항목, KISA ID, 구현 상태, 지원 언어, Semgrep Rule ID
- Microcopy rules: 동작 버튼은 `규칙 등록`, `변경 저장`, `비활성화`처럼 결과가 드러나게 작성

## Implementation constraints
- Framework/styling system: FastAPI, Jinja2, 기존 공통 CSS
- Design-token constraints: 기존 색상·간격·버튼 패턴 재사용
- Performance constraints: 서버 렌더링과 단순 GET/POST 유지
- Compatibility constraints: React, Next.js, SPA, WebSocket 추가 금지
- Test/screenshot expectations: ADMIN/USER 상태와 empty/error 상태를 각각 검증

## Open questions
- [x] SFR-012 진단 항목 등록·수정 화면, ADMIN 권한 및 경로 확정
- [x] SFR-013 KISA 카탈로그 목록·상세 화면, ADMIN/USER 조회 정책 및 경로 확정
