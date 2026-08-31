import fs from "node:fs/promises";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const W = 1280;
const H = 720;
const FONT = "Noto Sans CJK KR";
const C = {
  navy: "#0B2236",
  navy2: "#12344F",
  blue: "#1F6EA5",
  blue2: "#3D8FC4",
  pale: "#EAF3F9",
  pale2: "#F4F8FB",
  ink: "#152536",
  muted: "#60758A",
  line: "#D7E2EA",
  white: "#FFFFFF",
  green: "#23855B",
  greenPale: "#E5F5ED",
  amber: "#C87912",
  amberPale: "#FFF3DD",
  red: "#C53A45",
  redPale: "#FCE8EA",
};

const OUT = "/home/kmj/sast-project-clean/presentation/SecureScan_RFP_중간발표_수정본.pptx";
const BUILD = "/home/kmj/sast-project-clean/.tmp/presentation-build";
const ASSET = `${BUILD}/assets`;

async function readBytes(path) {
  const b = await fs.readFile(path);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function rect(slide, x, y, w, h, fill, radius = 0, line = "none", lineWidth = 0) {
  return slide.shapes.add({
    geometry: radius ? "roundRect" : "rect",
    position: { left: x, top: y, width: w, height: h },
    fill,
    line: { style: "solid", fill: line, width: lineWidth },
    ...(radius ? { borderRadius: "rounded-xl" } : {}),
  });
}

function textBox(slide, text, x, y, w, h, size = 20, color = C.ink, bold = false, align = "left") {
  const s = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  s.text = text;
  s.text.style = { fontFamily: FONT, fontSize: size, color, bold, alignment: align };
  return s;
}

function line(slide, x, y, w, h = 0, color = C.line, width = 1) {
  return slide.shapes.add({
    geometry: "line",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: color, width },
  });
}

function imageBox(slide, bytes, x, y, w, h, name) {
  rect(slide, x - 4, y - 4, w + 8, h + 8, C.white, 12, C.line, 1);
  return slide.images.add({
    blob: bytes,
    contentType: "image/png",
    alt: name,
    name,
    fit: "contain",
    position: { left: x, top: y, width: w, height: h },
    geometry: "roundRect",
    borderRadius: "rounded-xl",
  });
}

function badge(slide, label, x, y, w, fill = C.pale, color = C.blue) {
  rect(slide, x, y, w, 28, fill, 14, "none", 0);
  textBox(slide, label, x, y + 4, w, 20, 13, color, true, "center");
}

function header(slide, title, section, reqs, page) {
  textBox(slide, section.toUpperCase(), 64, 38, 270, 22, 13, C.blue, true);
  textBox(slide, title, 64, 68, 1030, 58, 34, C.ink, true);
  if (reqs) {
    rect(slide, 896, 38, 320, 28, C.pale2, 14, "none", 0);
    textBox(slide, reqs, 896, 42, 320, 18, 11, C.muted, true, "center");
  }
  line(slide, 64, 130, 1152, 0, C.line, 1);
  textBox(slide, `SecureScan · 중간발표`, 64, 688, 260, 18, 11, C.muted, false);
  textBox(slide, String(page).padStart(2, "0"), 1178, 688, 38, 18, 11, C.muted, true, "right");
}

function addNotes(slide, body, sources) {
  const sourceLines = sources.map((s) => `- ${s}`).join("\n");
  slide.speakerNotes.textFrame.setText(`${body}\n\n[Sources]\n${sourceLines}`);
  slide.speakerNotes.setVisible(true);
}

function bullet(slide, title, body, x, y, w, accent = C.blue) {
  rect(slide, x, y + 3, 7, 54, accent, 4, "none", 0);
  textBox(slide, title, x + 20, y, w - 20, 26, 19, C.ink, true);
  textBox(slide, body, x + 20, y + 30, w - 20, 48, 15, C.muted, false);
}

function stat(slide, value, label, x, y, color, sub = "") {
  textBox(slide, value, x, y, 150, 64, 48, color, true);
  textBox(slide, label, x, y + 63, 170, 28, 17, C.white, true);
  if (sub) textBox(slide, sub, x, y + 91, 180, 38, 13, "#9CC5DF", false);
}

const presentation = Presentation.create({ slideSize: { width: W, height: H } });

// Slide 1
{
  const s = presentation.slides.add();
  s.background.fill = C.white;
  rect(s, 0, 0, 322, H, C.navy);
  rect(s, 80, 104, 62, 62, C.blue, 14, "none", 0);
  textBox(s, "✓", 80, 112, 62, 44, 30, C.white, true, "center");
  textBox(s, "SecureScan", 80, 186, 180, 34, 24, C.white, true);
  textBox(s, "KISA 기준 기반 SAST MVP", 80, 228, 190, 52, 14, "#A9BDD0", false);
  textBox(s, "정적 애플리케이션 보안 진단\n프로그램 MVP 개발 중간발표", 386, 164, 812, 172, 50, C.ink, true);
  line(s, 386, 368, 154, 0, C.blue, 6);
  textBox(s, "Java · JavaScript · Python  |  FastAPI · Semgrep · SQLAlchemy", 386, 404, 790, 38, 20, C.muted, false);
  textBox(s, "중간점검  |  2026.08.30", 386, 580, 400, 28, 16, C.blue, true);
  textBox(s, "요구사항을 기능별로 묶어 설계·구현·검증했습니다", 386, 616, 700, 30, 17, C.muted, false);
  addNotes(s,
    "안녕하세요. 이번 발표에서는 RFP 번호를 순서대로 읽기보다, 실제 구현한 기능을 중심으로 관련 요구사항을 묶어서 설명드리겠습니다. 핵심은 ZIP 소스를 안전하게 받아 Semgrep으로 분석하고, 결과를 KISA 기준의 공통 Finding으로 저장·조회하는 흐름입니다.",
    ["/home/kmj/sast-project-clean/docs/requirements.md", "/home/kmj/sast-project-clean/docs/architecture.md"]);
}

// Slide 2
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "업로드부터 결과까지 하나의 흐름으로 연결했습니다", "MVP 사용자 흐름", "SFR-008~013 · DAR-003~009", 2);
  const xs = [76, 274, 472, 670, 868, 1066];
  for (let i = 0; i < 5; i++) {
    s.shapes.add({ geometry: "rightArrow", position: { left: xs[i] + 142, top: 274, width: 42, height: 34 }, fill: C.pale, line: { style: "solid", fill: "none", width: 0 } });
  }
  const steps = [
    ["01", "로그인", "사내 계정·역할 확인"],
    ["02", "프로젝트", "언어·사용자 경계"],
    ["03", "ZIP 업로드", "검증 후 안전 추출"],
    ["04", "Semgrep", "격리 공간에서 실행"],
    ["05", "정규화", "공통 Finding 변환"],
    ["06", "결과 조회", "이력·필터·상세"],
  ];
  steps.forEach((d, i) => {
    rect(s, xs[i], 220, 146, 144, i === 3 ? C.navy : C.pale2, 14, i === 3 ? C.navy : C.line, 1);
    textBox(s, d[0], xs[i] + 18, 238, 42, 25, 14, i === 3 ? "#9CC5DF" : C.blue, true);
    textBox(s, d[1], xs[i] + 18, 276, 112, 30, 20, i === 3 ? C.white : C.ink, true);
    textBox(s, d[2], xs[i] + 18, 314, 112, 40, 13, i === 3 ? "#B7CCDB" : C.muted, false);
  });
  rect(s, 76, 422, 1134, 140, C.pale, 14, "none", 0);
  textBox(s, "설계 원칙", 104, 446, 130, 28, 18, C.blue, true);
  textBox(s, "분석 엔진은 Semgrep 하나로 고정하고, 엔진 결과와 화면 사이에 정규화 계층을 두었습니다.", 254, 442, 900, 34, 20, C.ink, true);
  textBox(s, "따라서 언어나 규칙이 늘어나더라도 프로젝트·분석 이력·Finding 조회 흐름은 그대로 재사용합니다.", 254, 490, 900, 38, 17, C.muted, false);
  addNotes(s,
    "전체 흐름은 로그인, 프로젝트, ZIP 업로드, Semgrep 실행, 정규화, 결과 조회의 여섯 단계입니다. 중요한 설계 판단은 Semgrep JSON을 화면에 바로 보여주지 않고 공통 Finding 형식으로 바꿔 저장한 것입니다. 이 때문에 Java, JavaScript, Python이 같은 이력과 결과 화면을 공유합니다.",
    ["/home/kmj/sast-project-clean/docs/architecture.md", "/home/kmj/sast-project-clean/docs/quality.md", "/home/kmj/sast-project-clean/docs/traceability.md"]);
}

// Slide 3
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "로그인 한 번에 계정 보호와 역할 통제를 함께 적용했습니다", "인증·권한", "SFR-001·003 · SEC-001~006 · TST-001~003", 3);
  rect(s, 66, 164, 520, 438, C.pale2, 16, C.line, 1);
  textBox(s, "인증 요청이 처리되는 순서", 96, 190, 360, 30, 22, C.ink, true);
  const authSteps = [
    ["01", "회사 이메일 검증", "@company.com 형식만 허용"],
    ["02", "bcrypt 해시 비교", "평문 비밀번호는 저장하지 않음"],
    ["03", "서명 쿠키 발급", "user_id·CSRF·만료 정보만 포함"],
    ["04", "DB 권한 재확인", "역할·활성 상태를 요청마다 조회"],
  ];
  authSteps.forEach((d, i) => {
    const y = 242 + i * 78;
    rect(s, 96, y, 58, 50, i === 3 ? C.navy : C.pale, 12, "none", 0);
    textBox(s, d[0], 96, y + 12, 58, 22, 14, i === 3 ? C.white : C.blue, true, "center");
    textBox(s, d[1], 176, y - 1, 230, 26, 18, C.ink, true);
    textBox(s, d[2], 176, y + 29, 334, 30, 14, C.muted, false);
    if (i < 3) line(s, 124, y + 52, 0, 25, C.line, 2);
  });
  bullet(s, "사내 계정 정책", "@company.com 형식만 허용하고 최초 관리자는 admin@company.com으로 생성합니다.", 640, 176, 536, C.blue);
  bullet(s, "평문을 남기지 않는 비밀번호", "bcrypt 단방향 해시만 DB에 저장하고 로그인 시 해시를 비교합니다.", 640, 286, 536, C.green);
  bullet(s, "쿠키보다 DB 권한을 신뢰", "서명 쿠키에는 user_id·CSRF·만료만 두고 역할과 활성 상태는 요청마다 DB에서 확인합니다.", 640, 396, 536, C.amber);
  rect(s, 640, 518, 536, 84, C.navy, 12, "none", 0);
  textBox(s, "선택 근거", 664, 538, 110, 24, 16, "#9CC5DF", true);
  textBox(s, "서버 세션 저장소 없이 단순성을 유지하면서도\n권한 변경은 다음 요청부터 즉시 반영됩니다.", 790, 530, 358, 54, 17, C.white, true);
  addNotes(s,
    "계정은 사내 프로그램이라는 전제로 company.com 이메일만 받습니다. 비밀번호는 복호화가 필요한 암호화가 아니라, 원문을 되돌릴 수 없는 bcrypt 해시로 저장합니다. 세션은 서명 쿠키를 사용하지만 권한을 쿠키에 고정하지 않고 매 요청마다 DB에서 역할과 활성 상태를 확인했습니다. 그래서 관리자가 역할을 바꾸면 다음 요청부터 바로 반영됩니다.",
    ["/home/kmj/sast-project-clean/docs/requirements.md", "/home/kmj/sast-project-clean/docs/security.md", "/home/kmj/sast-project-clean/app/auth/", "/home/kmj/sast-project-clean/tests/test_authentication.py"]);
}

// Slide 4
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "프로젝트 단위로 소스와 사용자를 묶어 접근 경계를 만들었습니다", "프로젝트·접근 경계", "SFR-003·008 · DAR-003~005·010 · SEC-003~006", 4);
  rect(s, 64, 164, 430, 438, C.pale2, 16, C.line, 1);
  textBox(s, "권한 판단 순서", 92, 190, 260, 30, 22, C.ink, true);
  const ys = [252, 346, 440];
  [
    ["1", "ADMIN인가?", "생성·수정·할당·업로드·분석 실행 허용"],
    ["2", "할당된 USER인가?", "프로젝트·분석 이력·Finding 읽기 허용"],
    ["3", "그 외 요청인가?", "자원 존재를 숨기기 위해 404 반환"],
  ].forEach((d, i) => {
    rect(s, 92, ys[i], 46, 46, i === 2 ? C.redPale : C.pale, 12, "none", 0);
    textBox(s, d[0], 92, ys[i] + 8, 46, 24, 18, i === 2 ? C.red : C.blue, true, "center");
    textBox(s, d[1], 158, ys[i] - 1, 280, 26, 18, C.ink, true);
    textBox(s, d[2], 158, ys[i] + 29, 282, 42, 14, C.muted, false);
  });
  rect(s, 534, 164, 682, 438, C.pale2, 16, C.line, 1);
  textBox(s, "DB 관계로 접근을 판단", 566, 190, 360, 30, 22, C.ink, true);
  line(s, 771, 306, 0, 48, C.line, 3);
  line(s, 770, 306, 193, 48, C.line, 3);
  line(s, 771, 306, 271, 48, C.line, 3);
  line(s, 963, 306, 79, 48, C.line, 3);
  line(s, 770, 434, 0, 58, C.line, 3);
  line(s, 1042, 434, 0, 58, C.line, 3);
  rect(s, 686, 238, 170, 68, C.navy, 14, "none", 0);
  textBox(s, "PROJECT", 686, 257, 170, 28, 20, C.white, true, "center");
  rect(s, 878, 238, 170, 68, C.pale, 14, C.line, 1);
  textBox(s, "USER", 878, 257, 170, 28, 20, C.blue, true, "center");
  rect(s, 650, 354, 240, 80, C.white, 14, C.line, 1);
  textBox(s, "PROJECT_USER", 650, 371, 240, 24, 18, C.ink, true, "center");
  textBox(s, "할당 관계", 650, 401, 240, 20, 14, C.muted, false, "center");
  rect(s, 922, 354, 240, 80, C.white, 14, C.line, 1);
  textBox(s, "ANALYSIS_RUN", 922, 371, 240, 24, 18, C.ink, true, "center");
  textBox(s, "프로젝트별 실행 이력", 922, 401, 240, 20, 14, C.muted, false, "center");
  rect(s, 650, 492, 240, 80, C.pale, 14, C.line, 1);
  textBox(s, "READ ACCESS", 650, 509, 240, 24, 18, C.blue, true, "center");
  textBox(s, "ADMIN 또는 할당 USER", 650, 539, 240, 20, 14, C.muted, false, "center");
  rect(s, 922, 492, 240, 80, C.pale, 14, C.line, 1);
  textBox(s, "FINDING", 922, 509, 240, 24, 18, C.blue, true, "center");
  textBox(s, "분석 실행에 종속", 922, 539, 240, 20, 14, C.muted, false, "center");
  addNotes(s,
    "프로젝트는 단순한 목록이 아니라 접근 경계입니다. ADMIN은 프로젝트를 만들고 사용자를 할당하며 소스를 업로드하고 분석할 수 있습니다. 일반 USER는 project_users 관계에 할당된 프로젝트만 읽을 수 있습니다. URL의 프로젝트 ID를 그대로 믿지 않고 DB 관계를 확인하며, 권한이 없으면 403 대신 404를 반환해 프로젝트 존재 여부도 숨깁니다.",
    ["/home/kmj/sast-project-clean/docs/database.md", "/home/kmj/sast-project-clean/docs/security.md", "/home/kmj/sast-project-clean/app/projects/access.py", "/home/kmj/sast-project-clean/tests/test_projects.py"]);
}

// Slide 5
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "업로드 파일을 신뢰하지 않고 분석마다 복사본을 격리합니다", "업로드·작업공간", "SFR-008 · SEC-007~009 · TST-004", 5);
  const nodeY = 230;
  [250, 484, 718, 952].forEach((x) => s.shapes.add({ geometry: "rightArrow", position: { left: x, top: nodeY + 43, width: 62, height: 34 }, fill: C.pale, line: { style: "solid", fill: "none", width: 0 } }));
  const nodes = [
    [72, "ZIP 검증", "서명·경로·링크·암호화"],
    [306, "프로젝트 소스", "검증된 원본을 지속 보관"],
    [540, "분석별 작업공간", "정규 파일만 고유 공간에 복사"],
    [774, "Semgrep 실행", "60초·2 jobs·메모리·출력 제한"],
    [1008, "임시 공간 삭제", "성공·실패와 무관하게 정리"],
  ];
  nodes.forEach((d, i) => {
    rect(s, d[0], nodeY, 178, 120, i === 2 ? C.navy : C.pale2, 14, i === 2 ? C.navy : C.line, 1);
    textBox(s, String(i + 1).padStart(2, "0"), d[0] + 16, nodeY + 14, 36, 22, 13, i === 2 ? "#9CC5DF" : C.blue, true);
    textBox(s, d[1], d[0] + 16, nodeY + 45, 150, 26, 17, i === 2 ? C.white : C.ink, true);
    textBox(s, d[2], d[0] + 16, nodeY + 77, 150, 34, 12, i === 2 ? "#B7CCDB" : C.muted, false);
  });
  rect(s, 72, 402, 1114, 170, C.pale, 14, "none", 0);
  textBox(s, "원본과 복사본의 차이", 98, 428, 250, 30, 20, C.blue, true);
  textBox(s, "프로젝트 소스", 98, 476, 160, 24, 17, C.ink, true);
  textBox(s, "다음 분석에서도 사용할 검증된 소스이므로 보관", 270, 476, 390, 26, 16, C.muted, false);
  textBox(s, "분석 작업공간", 98, 520, 160, 24, 17, C.ink, true);
  textBox(s, "한 번의 분석을 위한 임시 복사본이며 실행 직후 삭제", 270, 520, 430, 26, 16, C.muted, false);
  textBox(s, "DB 경로도 다시 검증", 740, 476, 180, 24, 17, C.ink, true);
  textBox(s, "저장된 값이 프로젝트 경계를 벗어나면 실행하지 않음", 740, 512, 390, 48, 16, C.muted, false);
  addNotes(s,
    "업로드 보안에서 중요한 점은 확장자만 보지 않는 것입니다. 실제 ZIP 구조를 검사해 경로 탈출, 심볼릭 링크, 특수 파일, 암호화 ZIP과 크기 초과를 차단합니다. 검증된 프로젝트 소스는 보관하지만, Semgrep은 매 실행마다 만든 별도 임시 복사본에서 동작합니다. 이 복사본은 성공이나 실패와 관계없이 삭제합니다. 또한 DB에 저장된 경로도 분석 직전에 프로젝트 경계 안인지 다시 확인합니다.",
    ["/home/kmj/sast-project-clean/docs/security.md", "/home/kmj/sast-project-clean/docs/configuration.md", "/home/kmj/sast-project-clean/app/projects/upload.py", "/home/kmj/sast-project-clean/app/analysis/service.py", "/home/kmj/sast-project-clean/tests/test_source_upload.py"]);
}

// Slide 6
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "Semgrep 결과를 분석별 이력과 공통 Finding으로 남깁니다", "분석·결과 정규화", "SFR-009·010 · DAR-005·006·008·009 · QLT-003~005", 6);
  rect(s, 64, 164, 632, 438, C.pale2, 16, C.line, 1);
  textBox(s, "분석 실행은 상태와 근거를 함께 남깁니다", 94, 192, 520, 30, 22, C.ink, true);
  const stateXs = [94, 244, 394, 544];
  ["PENDING", "RUNNING", "COMPLETED", "FAILED"].forEach((d, i) => {
    rect(s, stateXs[i], 250, 126, 50, i === 1 ? C.navy : (i === 2 ? C.greenPale : (i === 3 ? C.redPale : C.pale)), 12, "none", 0);
    textBox(s, d, stateXs[i], 264, 126, 22, 14, i === 1 ? C.white : (i === 2 ? C.green : (i === 3 ? C.red : C.blue)), true, "center");
  });
  textBox(s, "분석별 저장 정보", 94, 342, 220, 28, 19, C.blue, true);
  [
    ["실행 이력", "프로젝트·실행자·시작/종료 시각·오류"],
    ["재현 정보", "소스/규칙 SHA-256·Semgrep 버전·활성 Rule"],
    ["결과 연결", "AnalysisRun 1:N Finding·Rule FK"],
  ].forEach((d, i) => {
    const y = 390 + i * 62;
    textBox(s, d[0], 94, y, 130, 24, 16, C.ink, true);
    textBox(s, d[1], 234, y, 402, 36, 14, C.muted, false);
    if (i < 2) line(s, 94, y + 43, 542, 0, C.line, 1);
  });
  rect(s, 740, 164, 476, 438, C.pale2, 16, C.line, 1);
  textBox(s, "Semgrep JSON", 772, 196, 180, 26, 18, C.blue, true);
  textBox(s, "↓  normalizer", 772, 234, 180, 25, 15, C.muted, true);
  textBox(s, "공통 Finding", 772, 274, 200, 30, 24, C.ink, true);
  ["상대 파일 경로와 줄·열", "심각도·신뢰도·메시지", "근거 코드·권고·원본 결과", "분석 시점 Rule 메타데이터"].forEach((v, i) => {
    rect(s, 772, 324 + i * 48, 14, 14, i === 3 ? C.green : C.blue, 7, "none", 0);
    textBox(s, v, 800, 316 + i * 48, 366, 30, 16, C.ink, i === 3);
  });
  line(s, 772, 526, 386, 0, C.line, 1);
  textBox(s, "분석별 재현 정보", 772, 544, 170, 22, 15, C.blue, true);
  textBox(s, "소스·규칙 SHA-256 / Semgrep 버전 / 활성 Rule 목록", 940, 541, 224, 42, 13, C.muted, false);
  addNotes(s,
    "Semgrep 결과는 분석 실행별로 저장합니다. 상태는 PENDING, RUNNING, COMPLETED 또는 FAILED로 남고, 성공한 결과는 파일 위치, 심각도, 신뢰도, 근거 코드와 원본 JSON을 공통 Finding으로 정규화합니다. 또한 소스와 규칙 세트의 해시, Semgrep 버전, 활성 규칙 목록을 함께 저장해 나중에 어떤 조건으로 분석했는지 확인할 수 있습니다.",
    ["/home/kmj/sast-project-clean/docs/architecture.md", "/home/kmj/sast-project-clean/docs/database.md", "/home/kmj/sast-project-clean/app/findings/services.py", "/home/kmj/sast-project-clean/tests/test_findings.py"]);
}

// Slide 7
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "49개 카탈로그와 자동 탐지 범위를 분리해 과장 없이 관리합니다", "KISA 규칙", "SFR-011~013 · DAR-007 · QLT-002 · TST-005·006", 7);
  rect(s, 64, 164, 404, 438, C.navy, 16, "none", 0);
  stat(s, "49", "KISA 카탈로그", 96, 194, C.white, "공식 항목 전체 등록");
  stat(s, "8", "PARTIAL 자동 탐지", 266, 194, "#77C5A2", "3개 언어별 규칙 검증");
  stat(s, "41", "NOT_IMPLEMENTED", 96, 352, "#F4BC65", "자동 탐지를 주장하지 않음");
  textBox(s, "지원 언어", 266, 360, 120, 24, 15, "#9CC5DF", true);
  textBox(s, "Java\nJavaScript\nPython", 266, 394, 120, 92, 19, C.white, true);
  line(s, 96, 516, 300, 0, "#31516A", 1);
  textBox(s, "YAML은 개발자가 작성하고,\n관리자는 KISA 항목·언어·Rule ID 연결만 DB에 등록합니다.", 96, 536, 310, 56, 14, "#C7D8E5", false);
  rect(s, 510, 164, 706, 438, C.pale2, 16, C.line, 1);
  textBox(s, "카탈로그와 탐지 규칙의 역할 분리", 542, 192, 520, 30, 22, C.ink, true);
  s.shapes.add({ geometry: "rightArrow", position: { left: 746, top: 330, width: 54, height: 32 }, fill: C.pale, line: { style: "solid", fill: "none", width: 0 } });
  s.shapes.add({ geometry: "rightArrow", position: { left: 980, top: 330, width: 54, height: 32 }, fill: C.pale, line: { style: "solid", fill: "none", width: 0 } });
  const ruleNodes = [
    [542, "KISA CATALOG", "공식 49개 항목", "ID·명칭·분류·설명"],
    [776, "DIAGNOSTIC_RULE", "관리자 DB 매핑", "언어·Semgrep Rule ID"],
    [1010, "YAML", "개발자 관리", "Semgrep이 실행"],
  ];
  ruleNodes.forEach((d, i) => {
    rect(s, d[0], 264, 190, 174, i === 1 ? C.navy : C.white, 14, i === 1 ? C.navy : C.line, 1);
    textBox(s, d[1], d[0] + 16, 286, 158, 26, 15, i === 1 ? "#9CC5DF" : C.blue, true, "center");
    textBox(s, d[2], d[0] + 16, 332, 158, 28, 18, i === 1 ? C.white : C.ink, true, "center");
    textBox(s, d[3], d[0] + 16, 378, 158, 40, 14, i === 1 ? "#C7D8E5" : C.muted, false, "center");
  });
  rect(s, 542, 474, 642, 92, C.pale, 12, "none", 0);
  textBox(s, "웹 애플리케이션은 YAML을 해석하거나 수정하지 않습니다.", 570, 494, 584, 28, 18, C.ink, true, "center");
  textBox(s, "공식 카탈로그 조회와 언어별 Rule ID 연결만 담당합니다.", 570, 532, 584, 24, 15, C.muted, false, "center");
  addNotes(s,
    "여기서는 카탈로그 등록과 자동 탐지를 구분해야 합니다. 공식 49개 항목은 모두 조회할 수 있지만, 현재 실제 Semgrep 규칙과 고정 샘플로 검증한 항목은 8개이며 상태는 PARTIAL입니다. 나머지 41개는 NOT_IMPLEMENTED로 표시해 자동 탐지한다고 과장하지 않습니다. YAML은 개발자가 작성하고, 관리 화면은 KISA 항목과 언어별 Semgrep Rule ID 연결만 담당합니다.",
    ["/home/kmj/sast-project-clean/docs/kisa-catalog.md", "/home/kmj/sast-project-clean/docs/traceability.md", "/home/kmj/sast-project-clean/app/rules/catalog.py", "/home/kmj/sast-project-clean/tests/test_diagnostic_examples.py"]);
}

// Slide 8
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "중간점검을 통과했고, 남은 구현은 진단 항목 확장입니다", "검증·남은 구현", "48 tests passed · 2026.08.30", 8);
  rect(s, 64, 162, 338, 248, C.navy, 16, "none", 0);
  textBox(s, "48", 94, 188, 160, 74, 56, C.white, true);
  textBox(s, "자동 테스트 통과", 94, 262, 210, 30, 20, "#9CC5DF", true);
  textBox(s, "인증·권한·ZIP 방어·실제 Semgrep·\nFinding·규칙·DB 무결성·품질 구조", 94, 316, 264, 68, 15, "#C7D8E5", false);
  rect(s, 442, 162, 766, 248, C.pale2, 16, C.line, 1);
  badge(s, "남은 구현 1건", 474, 190, 142, C.amberPale, C.amber);
  textBox(s, "NOT_IMPLEMENTED 진단 항목 구현", 474, 246, 646, 40, 28, C.ink, true);
  textBox(s, "현재 자동 탐지하지 않는 41개 KISA 항목을 대상으로\nSemgrep 규칙과 검증 데이터를 추가합니다.", 474, 302, 580, 64, 18, C.muted, false);
  textBox(s, "YAML 규칙  +  취약·정상 샘플  +  KISA Rule ID 매핑", 474, 374, 620, 28, 16, C.blue, true);
  textBox(s, "시연 순서", 64, 458, 160, 28, 21, C.ink, true);
  const demo = ["로그인", "프로젝트·사용자", "ZIP 업로드·분석", "Finding 필터·상세", "KISA 규칙 조회"];
  demo.forEach((d, i) => {
    const x = 64 + i * 230;
    if (i < 4) s.shapes.add({ geometry: "rightArrow", position: { left: x + 190, top: 538, width: 30, height: 24 }, fill: C.pale, line: { style: "solid", fill: "none", width: 0 } });
    rect(s, x, 512, 192, 92, i === 2 ? C.blue : C.pale2, 14, i === 2 ? C.blue : C.line, 1);
    textBox(s, String(i + 1), x + 14, 526, 28, 22, 13, i === 2 ? C.white : C.blue, true);
    textBox(s, d, x + 14, 558, 164, 28, 15, i === 2 ? C.white : C.ink, true);
  });
  addNotes(s,
    "중간점검으로 최신 작업 트리에서 전체 48개 테스트가 통과했습니다. 최종발표 전 남은 구현은 현재 NOT_IMPLEMENTED 상태인 진단 항목을 자동 탐지할 수 있도록 확장하는 것입니다. 항목별로 Semgrep YAML, 취약·정상 샘플, KISA Rule ID 매핑을 함께 추가해야 탐지 구현으로 인정하겠습니다. 이어서 로그인, 프로젝트, ZIP 분석, Finding 상세, KISA 규칙 순서로 시연하겠습니다.",
    ["/home/kmj/sast-project-clean/docs/testing.md", "/home/kmj/sast-project-clean/docs/security.md", "/home/kmj/sast-project-clean/docs/traceability.md", "Local verification: .venv/bin/pytest -q — 48 passed in 57.58s (2026-08-30)"]);
}

// Slide 9
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "요구사항은 기능 단위로 묶어 추적할 수 있습니다", "부록 A · 요구사항 추적", "SFR · DAR · SEC · TST · QLT", 9);
  const rows = [
    ["로그인·계정 보호", "SFR-001·003 / DAR-002 / SEC-001·002", "bcrypt·signed cookie·CSRF·DB 역할 재검증", "TST-001"],
    ["프로젝트·권한", "SFR-003·008 / DAR-003~005·010 / SEC-003~006", "ProjectUser 관계·ADMIN 쓰기·USER 읽기·404", "TST-002·003"],
    ["ZIP·분석 격리", "SFR-008 / SEC-007~009", "안전 추출·경계 재검증·분석별 작업공간·제한", "TST-004·008"],
    ["분석 이력·Finding", "SFR-009·010 / DAR-005·006·008·009", "상태·provenance·공통 결과·상대경로", "TST-004·007 / QLT-003~005"],
    ["KISA 규칙", "SFR-011~013 / DAR-007", "49개 카탈로그·8개 PARTIAL·언어별 Rule ID 매핑", "TST-005·006 / QLT-002"],
  ];
  const cols = [64, 288, 658, 1048];
  ["기능 묶음", "관련 요구사항", "구현 근거", "검증"].forEach((v, i) => textBox(s, v, cols[i] + 12, 166, [210, 350, 370, 168][i], 28, 15, i === 0 ? C.blue : C.muted, true));
  line(s, 64, 204, 1152, 0, C.navy, 2);
  rows.forEach((r, ri) => {
    const y = 216 + ri * 82;
    if (ri % 2 === 0) rect(s, 64, y, 1152, 72, C.pale2, 8, "none", 0);
    textBox(s, r[0], cols[0] + 12, y + 12, 202, 44, 16, C.ink, true);
    textBox(s, r[1], cols[1] + 12, y + 10, 346, 48, 14, C.ink, false);
    textBox(s, r[2], cols[2] + 12, y + 10, 366, 48, 14, C.muted, false);
    textBox(s, r[3], cols[3] + 12, y + 10, 156, 48, 14, C.blue, true);
  });
  addNotes(s,
    "이 표는 질의응답에서 요구사항 번호를 물어볼 때 사용합니다. 발표 본문에서는 기능을 먼저 설명하고, 이 부록에서 관련 요구사항과 시험 근거를 한 번에 확인할 수 있습니다.",
    ["/home/kmj/sast-project-clean/docs/requirements.md", "/home/kmj/sast-project-clean/docs/traceability.md"]);
}

// Slide 10
{
  const s = presentation.slides.add(); s.background.fill = C.white;
  header(s, "자동 테스트는 보안 경계와 분석 흐름을 확인했습니다", "부록 B · 자동 테스트 범위", "TST-001~008 · QLT-001~005", 10);
  const tests = [
    ["01", "인증·계정", "ADMIN/USER 로그인, bcrypt 해시, 쿠키 위변조·만료, CSRF, 사내 이메일 정책"],
    ["02", "접근 권한", "ADMIN 쓰기 허용, USER 쓰기 차단, 할당 프로젝트 조회, 미할당 자원 404"],
    ["03", "ZIP 업로드", "정상 ZIP 저장, ZIP Slip·심볼릭 링크·암호화 ZIP·파일 수와 크기 제한"],
    ["04", "Semgrep 실행", "성공·실패·timeout·출력 제한·프로세스 종료·작업공간 정리·환경변수 격리"],
    ["05", "Finding·규칙", "정규화 필드·필터·상세·원본 결과, 49개 카탈로그, 3개 언어 실제 샘플"],
    ["06", "DB·품질 구조", "FK·삭제 정책·마이그레이션·상대경로·모듈 책임·항목별 YAML 독립성"],
  ];
  tests.forEach((d, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 64 + col * 584;
    const y = 170 + row * 136;
    rect(s, x, y, 552, 112, i === 3 ? C.navy : C.pale2, 14, i === 3 ? C.navy : C.line, 1);
    textBox(s, d[0], x + 22, y + 20, 40, 22, 14, i === 3 ? "#9CC5DF" : C.blue, true);
    textBox(s, d[1], x + 76, y + 17, 170, 28, 19, i === 3 ? C.white : C.ink, true);
    textBox(s, d[2], x + 76, y + 54, 442, 46, 14, i === 3 ? "#C7D8E5" : C.muted, false);
  });
  rect(s, 64, 584, 1136, 48, C.pale, 12, "none", 0);
  textBox(s, "최신 작업 트리 기준 48개 자동 테스트 통과 · 실제 Semgrep 취약/정상 샘플 포함", 64, 598, 1136, 24, 16, C.blue, true, "center");
  addNotes(s,
    "48개라는 숫자만 말하기보다 무엇을 검증했는지 설명하기 위한 장입니다. 인증과 권한, 악성 ZIP 방어, Semgrep 실행 실패와 제한, Finding 정규화, KISA 카탈로그와 세 언어 실제 샘플, DB 관계와 모듈 구조를 자동으로 확인했습니다. 모든 테스트는 임시 DB와 임시 업로드 디렉터리를 사용해 개발 데이터를 변경하지 않습니다.",
    ["/home/kmj/sast-project-clean/docs/testing.md", "/home/kmj/sast-project-clean/docs/quality.md", "/home/kmj/sast-project-clean/docs/security.md", "/home/kmj/sast-project-clean/docs/architecture.md"]);
}

await fs.mkdir(`${BUILD}/renders`, { recursive: true });
for (const [i, slide] of presentation.slides.items.entries()) {
  const png = await presentation.export({ slide, format: "png", scale: 1 });
  await fs.writeFile(`${BUILD}/renders/slide-${String(i + 1).padStart(2, "0")}.png`, new Uint8Array(await png.arrayBuffer()));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(`${BUILD}/renders/slide-${String(i + 1).padStart(2, "0")}.layout.json`, await layout.text());
}
const montage = await presentation.export({ format: "webp", montage: true, scale: 1 });
await fs.writeFile(`${BUILD}/renders/deck-montage.webp`, new Uint8Array(await montage.arrayBuffer()));
const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save(OUT);
console.log(OUT);
