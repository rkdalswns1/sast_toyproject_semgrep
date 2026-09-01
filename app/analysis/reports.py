"""Read-only CSV and PDF exports for one normalized analysis run."""

from __future__ import annotations

import csv
import html
import io
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus, FindingStatus, Severity
from app.db.models.finding import Finding
from app.db.models.project import Project


SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
ANALYSIS_STATUS_LABELS = {
    AnalysisStatus.PENDING: "대기",
    AnalysisStatus.RUNNING: "진행 중",
    AnalysisStatus.COMPLETED: "완료",
    AnalysisStatus.FAILED: "실패",
}
FINDING_STATUS_LABELS = {
    FindingStatus.OPEN: "미조치",
    FindingStatus.IN_PROGRESS: "조치 중",
    FindingStatus.RESOLVED: "조치 완료",
    FindingStatus.FALSE_POSITIVE: "오탐",
    FindingStatus.ACCEPTED_RISK: "위험 수용",
}
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class ReportFinding:
    finding_id: int
    kisa_id: str
    rule_name: str
    severity: str
    confidence: str
    location: str
    message: str
    workflow_status: str
    workflow_note: str


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    analysis_id: int
    project_name: str
    source_version: str
    deployment_version: str
    source_description: str
    analysis_at: str
    executor: str
    analysis_status: str
    severity_counts: dict[str, int]
    findings: tuple[ReportFinding, ...]


def _clean_text(value: object | None) -> str:
    if value is None:
        return ""
    text = str(value)
    return "".join(
        character
        for character in text
        if character in "\n\t" or ord(character) >= 32
    )


def _safe_relative_path(value: str) -> str:
    cleaned = _clean_text(value)
    path = PurePosixPath(cleaned)
    if (
        not cleaned
        or path.is_absolute()
        or ".." in path.parts
        or _WINDOWS_ABSOLUTE_PATH.match(cleaned)
    ):
        return "경로 비공개"
    return cleaned


def _finding_location(finding: Finding) -> str:
    location = f"{_safe_relative_path(finding.file_path)}:{finding.start_line}"
    if finding.start_column is not None:
        location += f":{finding.start_column}"
    if finding.end_line is not None and finding.end_line != finding.start_line:
        location += f"-{finding.end_line}"
    return location


def _analysis_source_metadata(analysis_run: AnalysisRun) -> dict[str, object]:
    summary = analysis_run.summary if isinstance(analysis_run.summary, dict) else {}
    provenance = summary.get("provenance")
    if not isinstance(provenance, dict):
        return {}
    source_metadata = provenance.get("source_metadata")
    return source_metadata if isinstance(source_metadata, dict) else {}


def build_analysis_report(
    *, analysis_run: AnalysisRun, project: Project, findings: list[Finding]
) -> AnalysisReport:
    """Copy ORM data into a format-neutral, immutable report snapshot."""
    source_metadata = _analysis_source_metadata(analysis_run)
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    report_findings: list[ReportFinding] = []
    for finding in findings:
        counts[finding.severity.value] += 1
        workflow = finding.workflow
        workflow_status = workflow.status if workflow else FindingStatus.OPEN
        report_findings.append(
            ReportFinding(
                finding_id=finding.id,
                kisa_id=_clean_text(finding.kisa_id),
                rule_name=_clean_text(finding.rule_name),
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                location=_finding_location(finding),
                message=_clean_text(finding.message),
                workflow_status=FINDING_STATUS_LABELS[workflow_status],
                workflow_note=_clean_text(workflow.note if workflow else None),
            )
        )

    analysis_datetime: datetime | None = analysis_run.started_at
    analysis_at = (
        analysis_datetime.strftime("%Y-%m-%d %H:%M:%S")
        if analysis_datetime is not None
        else "-"
    )
    return AnalysisReport(
        analysis_id=analysis_run.id,
        project_name=_clean_text(project.name),
        source_version=_clean_text(source_metadata.get("source_version")),
        deployment_version=_clean_text(source_metadata.get("deployment_version")),
        source_description=_clean_text(source_metadata.get("description")),
        analysis_at=analysis_at,
        executor=_clean_text(analysis_run.executor.username),
        analysis_status=ANALYSIS_STATUS_LABELS[analysis_run.status],
        severity_counts=counts,
        findings=tuple(report_findings),
    )


def _csv_safe_cell(value: object) -> object:
    """Prevent spreadsheet applications from evaluating external text."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def render_csv_report(report: AnalysisReport) -> bytes:
    """Render a UTF-8 BOM CSV with one Finding per row."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    headers = [
        "프로젝트명",
        "소스 버전",
        "배포 버전",
        "분석 일시",
        "실행 계정",
        "분석 상태",
        "CRITICAL 건수",
        "HIGH 건수",
        "MEDIUM 건수",
        "LOW 건수",
        "INFO 건수",
        "KISA ID",
        "규칙명",
        "심각도",
        "신뢰도",
        "파일 위치",
        "메시지",
        "조치 상태",
        "검토 의견",
    ]
    writer.writerow(headers)
    base_row: list[object] = [
        report.project_name,
        report.source_version,
        report.deployment_version,
        report.analysis_at,
        report.executor,
        report.analysis_status,
        *(report.severity_counts[severity.value] for severity in SEVERITY_ORDER),
    ]
    findings: tuple[ReportFinding | None, ...] = report.findings or (None,)
    for finding in findings:
        detail_row: list[object] = (
            ["", "", "", "", "", "", "", ""]
            if finding is None
            else [
                finding.kisa_id,
                finding.rule_name,
                finding.severity,
                finding.confidence,
                finding.location,
                finding.message,
                finding.workflow_status,
                finding.workflow_note,
            ]
        )
        writer.writerow([_csv_safe_cell(value) for value in [*base_row, *detail_row]])
    return output.getvalue().encode("utf-8-sig")


def _register_korean_fonts() -> tuple[str, str]:
    regular_name = "SastReportRegular"
    bold_name = "SastReportBold"
    registered_fonts = set(pdfmetrics.getRegisteredFontNames())
    if regular_name in registered_fonts and bold_name in registered_fonts:
        return regular_name, bold_name

    candidates = (
        (
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
        ),
        (
            Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
            Path("/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"),
        ),
        (
            Path("C:/Windows/Fonts/malgun.ttf"),
            Path("C:/Windows/Fonts/malgunbd.ttf"),
        ),
    )
    for regular_path, bold_path in candidates:
        if not regular_path.is_file() or not bold_path.is_file():
            continue
        try:
            pdfmetrics.registerFont(TTFont(regular_name, str(regular_path)))
            pdfmetrics.registerFont(TTFont(bold_name, str(bold_path)))
            pdfmetrics.registerFontFamily(
                "SastReport",
                normal=regular_name,
                bold=bold_name,
                italic=regular_name,
                boldItalic=bold_name,
            )
            return regular_name, bold_name
        except Exception:
            continue

    fallback_name = "HYSMyeongJo-Medium"
    if fallback_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(fallback_name))
    return fallback_name, fallback_name


def _paragraph_text(value: str, *, empty: str = "-") -> str:
    cleaned = value or empty
    return html.escape(cleaned).replace("\n", "<br/>")


def _report_styles(regular_font: str, bold_font: str) -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=sample["Title"],
            fontName=bold_font,
            fontSize=20,
            leading=27,
            textColor=colors.HexColor("#172033"),
            alignment=TA_CENTER,
            spaceAfter=8 * mm,
        ),
        "heading": ParagraphStyle(
            "ReportHeading",
            parent=sample["Heading2"],
            fontName=bold_font,
            fontSize=12,
            leading=17,
            textColor=colors.HexColor("#1F4D78"),
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=sample["BodyText"],
            fontName=regular_font,
            fontSize=9,
            leading=14,
            textColor=colors.HexColor("#263238"),
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=sample["BodyText"],
            fontName=regular_font,
            fontSize=8,
            leading=12,
            textColor=colors.HexColor("#52616B"),
            wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=sample["BodyText"],
            fontName=bold_font,
            fontSize=8,
            leading=12,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
    }


def render_pdf_report(report: AnalysisReport) -> bytes:
    """Render an A4 customer-facing report without raw engine output."""
    regular_font, bold_font = _register_korean_fonts()
    styles = _report_styles(regular_font, bold_font)
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="정적 애플리케이션 보안 진단 결과 보고서",
        author="SecureScan",
    )
    story: list[object] = [
        Paragraph("정적 애플리케이션 보안 진단 결과 보고서", styles["title"]),
    ]

    metadata_rows = [
        ("프로젝트", report.project_name, "분석 실행", f"#{report.analysis_id}"),
        ("소스 버전", report.source_version, "배포 버전", report.deployment_version),
        ("분석 일시", report.analysis_at, "실행 계정", report.executor),
        ("분석 상태", report.analysis_status, "Finding", f"{len(report.findings)}건"),
    ]
    metadata_table = Table(
        [
            [
                Paragraph(_paragraph_text(label_a), styles["small"]),
                Paragraph(_paragraph_text(value_a), styles["body"]),
                Paragraph(_paragraph_text(label_b), styles["small"]),
                Paragraph(_paragraph_text(value_b), styles["body"]),
            ]
            for label_a, value_a, label_b, value_b in metadata_rows
        ],
        colWidths=[25 * mm, 57 * mm, 25 * mm, 57 * mm],
    )
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1F7")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EAF1F7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7C5D3")),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D2DCE5")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([metadata_table, Spacer(1, 3 * mm)])
    if report.source_description:
        story.extend(
            [
                Paragraph("분석 대상 설명", styles["heading"]),
                Paragraph(_paragraph_text(report.source_description), styles["body"]),
            ]
        )

    story.append(Paragraph("심각도별 요약", styles["heading"]))
    severity_table = Table(
        [
            [
                Paragraph(severity.value, styles["table_header"])
                for severity in SEVERITY_ORDER
            ],
            [report.severity_counts[severity.value] for severity in SEVERITY_ORDER],
        ],
        colWidths=[32.8 * mm] * len(SEVERITY_ORDER),
    )
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4D78")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), bold_font),
                ("FONTNAME", (0, 1), (-1, 1), regular_font),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7C5D3")),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D2DCE5")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([severity_table, Paragraph("Finding 목록", styles["heading"])])

    if not report.findings:
        story.append(Paragraph("탐지된 Finding이 없습니다.", styles["body"]))
    for index, finding in enumerate(report.findings, start=1):
        if index > 1 and (index - 1) % 5 == 0:
            story.append(PageBreak())
        story.append(
            Paragraph(
                _paragraph_text(
                    f"{index}. [{finding.kisa_id}] {finding.rule_name}"
                ),
                styles["heading"],
            )
        )
        detail_table = Table(
            [
                [
                    Paragraph("심각도", styles["small"]),
                    Paragraph(_paragraph_text(finding.severity), styles["body"]),
                    Paragraph("신뢰도", styles["small"]),
                    Paragraph(_paragraph_text(finding.confidence), styles["body"]),
                    Paragraph("조치 상태", styles["small"]),
                    Paragraph(_paragraph_text(finding.workflow_status), styles["body"]),
                ],
                [
                    Paragraph("파일 위치", styles["small"]),
                    Paragraph(_paragraph_text(finding.location), styles["body"]),
                    "",
                    "",
                    "",
                    "",
                ],
            ],
            colWidths=[19 * mm, 35 * mm, 19 * mm, 25 * mm, 22 * mm, 44 * mm],
        )
        detail_table.setStyle(
            TableStyle(
                [
                    ("SPAN", (1, 1), (5, 1)),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F5F8")),
                    ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F2F5F8")),
                    ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#F2F5F8")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5DF")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DCE3E9")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.extend(
            [
                detail_table,
                Spacer(1, 1.5 * mm),
                Paragraph("메시지", styles["small"]),
                Paragraph(_paragraph_text(finding.message), styles["body"]),
                Spacer(1, 1.5 * mm),
                Paragraph("검토 의견", styles["small"]),
                Paragraph(_paragraph_text(finding.workflow_note), styles["body"]),
                Spacer(1, 2 * mm),
            ]
        )

    def add_page_number(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont(regular_font, 8)
        canvas.setFillColor(colors.HexColor("#6B7785"))
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"{doc.page} 페이지")
        canvas.restoreState()

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return output.getvalue()
